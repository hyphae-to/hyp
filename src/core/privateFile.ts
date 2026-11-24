// Secret files (tokens, webhook secrets): only the owner may read them.
import { readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative } from "node:path";

/**
 * Whether `path` is a systemd credential: inside `$CREDENTIALS_DIRECTORY` (after resolving
 * symlinks), a directory systemd makes private to the unit (no access for others).
 */
function isSystemdCredential(path: string, credentialsDirectory: string | undefined): boolean {
  if (credentialsDirectory === undefined || credentialsDirectory === "") return false;
  const directory = realpathSync(credentialsDirectory);
  if ((statSync(directory).mode & 0o007) !== 0) return false;
  const inside = relative(directory, realpathSync(path));
  return inside !== "" && !inside.startsWith("..") && !isAbsolute(inside);
}

/**
 * Reads a secret file, refusing it unless only the owner can read it. systemd credentials
 * (`LoadCredential=`) are always created 0440 in a directory private to the unit, so there the
 * group may read too; any other permission is still refused.
 */
export function readPrivateFile(path: string, env: NodeJS.ProcessEnv = process.env): string {
  const mode = statSync(path).mode & 0o777;
  const forbidden = isSystemdCredential(path, env["CREDENTIALS_DIRECTORY"]) ? 0o037 : 0o077;
  if ((mode & forbidden) !== 0) {
    throw new Error(`${path} is mode ${mode.toString(8)}; it must not be readable by group or others (chmod 600)`);
  }
  return readFileSync(path, "utf8").trim();
}
