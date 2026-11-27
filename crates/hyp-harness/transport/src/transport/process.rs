//! Bounded, draining subprocess IO shared by native transports.

use std::io;
use std::process::ExitStatus;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

pub(super) async fn spawn_with_retry(command: &mut Command, retries: u32) -> io::Result<Child> {
    let mut attempts = 0u32;
    loop {
        match command.spawn() {
            Ok(child) => return Ok(child),
            Err(error)
                if error.kind() == io::ErrorKind::ExecutableFileBusy && attempts < retries =>
            {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(10 * u64::from(attempts))).await;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(super) struct ProcessOutput {
    pub status: io::Result<ExitStatus>,
    pub stdout: io::Result<(Vec<u8>, bool)>,
    pub stderr: io::Result<(Vec<u8>, bool)>,
}

/// Drains both pipes while waiting, preserving separate errors for caller policy.
/// On timeout kills the child; kill-on-drop stays configured by the caller.
pub(super) async fn wait_bounded(
    child: &mut Child,
    timeout: Duration,
    limit: usize,
) -> Result<ProcessOutput, tokio::time::error::Elapsed> {
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let wait = async {
        let stdout = async {
            match stdout {
                Some(reader) => read_bounded(reader, limit).await,
                None => Ok((Vec::new(), false)),
            }
        };
        let stderr = async {
            match stderr {
                Some(reader) => read_bounded(reader, limit).await,
                None => Ok((Vec::new(), false)),
            }
        };
        let (stdout, stderr, status) = tokio::join!(stdout, stderr, child.wait());
        ProcessOutput {
            status,
            stdout,
            stderr,
        }
    };
    let result = tokio::time::timeout(timeout, wait).await;
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

async fn read_bounded<R: AsyncRead + Unpin>(
    mut reader: R,
    limit: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if buf.len() < limit {
            let take = (limit - buf.len()).min(n);
            buf.extend_from_slice(&chunk[..take]);
            if take < n {
                truncated = true;
            }
        } else {
            truncated = true;
        }
    }
    Ok((buf, truncated))
}
