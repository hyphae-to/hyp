/**
 * Zero-dependency POSIX PTY helper built on standard `python3` (`pty.fork()`).
 *
 * Used for:
 *  1. Live interactive `codex` PTY sessions (`codex queue --thread <uuid>` wakeups).
 *  2. Interactive TTY confirmation of human-CLI-only `hyp inbox approve <receipt>`.
 *
 * All spawned processes are tracked by `Sandbox.reaper` (`detached: true`, `-pgid` kill)
 * so zero orphaned PTY children can ever leak after tests exit.
 */

import type { Sandbox, TrackedProcess } from "./sandbox.ts";

const PTY_BRIDGE_PY = `
import fcntl, os, pty, select, signal, struct, sys, termios

rows = int(os.environ.pop("HYP_PTY_ROWS", "40"))
cols = int(os.environ.pop("HYP_PTY_COLS", "140"))
argv = sys.argv[1:]

pid, fd = pty.fork()
if pid == 0:
    os.execvpe(argv[0], argv, os.environ)

try:
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
except OSError:
    pass

def _forward_sig(signum, _frame):
    try:
        os.kill(pid, signum)
    except OSError:
        pass

signal.signal(signal.SIGTERM, _forward_sig)
signal.signal(signal.SIGINT, _forward_sig)

stdin_open = True
while True:
    watch = [fd] + ([0] if stdin_open else [])
    try:
        r, _, _ = select.select(watch, [], [], 0.1)
    except InterruptedError:
        continue
    if fd in r:
        try:
            data = os.read(fd, 4096)
            if not data:
                break
            os.write(1, data)
        except OSError:
            break
    if stdin_open and 0 in r:
        try:
            data = os.read(0, 4096)
            if not data:
                stdin_open = False
            else:
                os.write(fd, data)
        except OSError:
            stdin_open = False
    wpid, status = os.waitpid(pid, os.WNOHANG)
    if wpid == pid:
        # Drain any trailing PTY bytes before exiting.
        while True:
            try:
                r2, _, _ = select.select([fd], [], [], 0.05)
                if fd not in r2:
                    break
                tail = os.read(fd, 4096)
                if not tail:
                    break
                os.write(1, tail)
            except OSError:
                break
        if os.WIFEXITED(status):
            sys.exit(os.WEXITSTATUS(status))
        if os.WIFSIGNALED(status):
            sys.exit(128 + os.WTERMSIG(status))
        sys.exit(0)

try:
    _, status = os.waitpid(pid, 0)
    if os.WIFEXITED(status):
        sys.exit(os.WEXITSTATUS(status))
    if os.WIFSIGNALED(status):
        sys.exit(128 + os.WTERMSIG(status))
except ChildProcessError:
    pass
sys.exit(0)
`.trim();

export interface PtyProcess {
  tracked: TrackedProcess;
  write(text: string): void;
  closeStdin(): void;
  kill(graceMs?: number): Promise<void>;
}

/** Spawns `command` inside a real POSIX PTY owned by `sandbox.reaper`. */
export function spawnInPty(
  sandbox: Sandbox,
  label: string,
  command: string,
  args: string[],
  options: {
    env?: Record<string, string>;
    cwd?: string;
    rows?: number;
    cols?: number;
  } = {},
): PtyProcess {
  const env = {
    ...(options.env ?? sandbox.env),
    TERM: options.env?.TERM ?? "xterm-256color",
    HYP_PTY_ROWS: String(options.rows ?? 40),
    HYP_PTY_COLS: String(options.cols ?? 140),
  };

  const tracked = sandbox.reaper.spawn(
    label,
    "python3",
    ["-u", "-c", PTY_BRIDGE_PY, command, ...args],
    {
      env,
      cwd: options.cwd ?? sandbox.paths.workspaceDir,
      stdio: ["pipe", "pipe", "pipe"],
    },
  );

  return {
    tracked,
    write(text: string): void {
      if (!tracked.exited && tracked.child.stdin && !tracked.child.stdin.destroyed) {
        tracked.child.stdin.write(text);
      }
    },
    closeStdin(): void {
      try {
        tracked.child.stdin?.end();
      } catch {
        // ignore
      }
    },
    kill(graceMs = 2_000): Promise<void> {
      return sandbox.reaper.kill(tracked, graceMs);
    },
  };
}

/**
 * Runs a CLI command inside a real PTY, feeding `inputOnMatch` once `promptPattern` appears
 * (e.g., `"y\n"` for `hyp inbox approve <receipt>`), and returns exit code + captured output.
 */
export async function runInteractivePtyCommand(
  sandbox: Sandbox,
  label: string,
  command: string,
  args: string[],
  options: {
    env?: Record<string, string>;
    cwd?: string;
    promptPattern?: RegExp;
    inputOnMatch?: string;
    timeoutMs?: number;
  } = {},
): Promise<{ exitCode: number | null; output: string }> {
  const ptyProc = spawnInPty(sandbox, label, command, args, {
    env: options.env,
    cwd: options.cwd,
  });

  let sent = false;
  const checkAndSend = () => {
    if (sent || !options.inputOnMatch) return;
    if (!options.promptPattern || options.promptPattern.test(ptyProc.tracked.stdout)) {
      sent = true;
      ptyProc.write(options.inputOnMatch);
    }
  };
  ptyProc.tracked.child.stdout?.on("data", checkAndSend);
  if (!options.promptPattern && options.inputOnMatch) {
    setTimeout(checkAndSend, 150);
  }

  const timeoutMs = options.timeoutMs ?? 15_000;
  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    void ptyProc.kill(1_000);
  }, timeoutMs);

  try {
    await ptyProc.tracked.exitPromise;
  } finally {
    clearTimeout(timer);
  }

  if (timedOut) {
    throw new Error(
      `Interactive PTY command '${label}' timed out after ${timeoutMs}ms\nOUTPUT:\n${ptyProc.tracked.stdout.slice(-2000)}`,
    );
  }

  return {
    exitCode: ptyProc.tracked.exitCode,
    output: ptyProc.tracked.stdout,
  };
}
