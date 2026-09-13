//! One strict worker's process lifetime, independent of the task daemon.
//!
//! This hidden binary mode has no store, queue, provider parsing or mutable
//! control channel. Its immutable command and deadline come from the runner.

use std::path::Path;
use std::time::Duration;

pub(crate) const MODE: &str = "--__hangar-support-supervisor-v1";
pub(crate) const SETUP_FAILURE: i32 = 125;
/// Fixed allowance for the surviving supervisor after the active runner deadline.
pub const DEADLINE_GRACE: Duration = Duration::from_secs(2);

/// Handle the hidden mode before starting a runtime, logging or database boot.
/// Returns `None` for ordinary daemon invocation; otherwise the process exit code.
#[must_use]
pub fn dispatch_if_requested() -> Option<i32> {
    let mut args = std::env::args_os();
    let _ = args.next();
    if args.next().as_deref() != Some(std::ffi::OsStr::new(MODE)) {
        return None;
    }
    Some(match supervise(args.collect()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("strict support supervisor setup failed: {error}");
            SETUP_FAILURE
        }
    })
}

/// Build the trusted helper command. The supplied binary is a reviewed daemon,
/// not a provider-selected executable; qualification pins its actual digest.
pub(crate) fn command(
    binary: &Path,
    root: &Path,
    program: &Path,
    runtime: Duration,
) -> std::io::Result<std::process::Command> {
    let binary = binary.canonicalize()?;
    if binary.file_stem().and_then(|name| name.to_str()) != Some("ainb-hangar-daemon")
        || !binary.is_file()
    {
        return Err(std::io::Error::other(
            "strict support requires the reviewed daemon supervisor binary",
        ));
    }
    let milliseconds = u64::try_from(runtime.as_millis())
        .map_err(|_| std::io::Error::other("strict runtime exceeds supported deadline"))?;
    if milliseconds == 0 {
        return Err(std::io::Error::other("strict runtime must be positive"));
    }
    let mut command = std::process::Command::new(binary);
    command
        .arg(MODE)
        .arg(root.canonicalize()?)
        .arg(milliseconds.to_string())
        .arg(program.canonicalize()?)
        .arg("--");
    Ok(command)
}

#[cfg(target_os = "linux")]
fn supervise(args: Vec<std::ffi::OsString>) -> std::io::Result<i32> {
    use nix::errno::Errno;
    use nix::sys::signal::{Signal, killpg};
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    use nix::unistd::{Pid, getpgrp, getpid};
    use std::process::Stdio;
    use std::time::Instant;

    if args.len() < 4 || args[3] != "--" {
        return Err(std::io::Error::other(
            "invalid immutable supervisor command",
        ));
    }
    let root = Path::new(&args[0]).canonicalize()?;
    let milliseconds = args[1]
        .to_str()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| std::io::Error::other("invalid supervisor deadline"))?;
    let duration = Duration::from_millis(milliseconds)
        .checked_add(DEADLINE_GRACE)
        .ok_or_else(|| std::io::Error::other("supervisor deadline overflow"))?;
    let deadline = Instant::now()
        .checked_add(duration)
        .ok_or_else(|| std::io::Error::other("supervisor deadline overflow"))?;
    if getpgrp() != getpid() || !std::env::current_dir()?.canonicalize()?.starts_with(&root) {
        return Err(std::io::Error::other(
            "supervisor must own its process group and execution cwd",
        ));
    }
    nix::sys::prctl::set_child_subreaper(true).map_err(std::io::Error::from)?;
    if !nix::sys::prctl::get_child_subreaper().map_err(std::io::Error::from)? {
        return Err(std::io::Error::other(
            "supervisor subreaper was not installed",
        ));
    }
    // Reject a wholly unavailable signal primitive before a worker can run.
    // Signal zero is only a preflight; real group-stop probes remain mandatory.
    killpg(getpid(), None).map_err(std::io::Error::from)?;
    let mut command = ainb_hangar_sandbox::strict_support_command(Path::new(&args[2]), &root)
        .map_err(|error| std::io::Error::other(format!("strict support sandbox: {error}")))?;
    // Inherit this supervisor's process group; no child process_group(0).
    // The strict filter prevents the worker and descendants leaving it.
    let child = command
        .command()
        .args(&args[4..])
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    let child_pid = Pid::from_raw(
        i32::try_from(child.id()).map_err(|_| std::io::Error::other("worker pid out of range"))?,
    );
    // waitpid below owns all reaping, including adopted descendants. std Child
    // has no kill-on-drop, so dropping the handle does not alter that ownership.
    drop(child);
    let group = getpid();
    let mut direct_status = None;
    loop {
        if Instant::now() >= deadline {
            // Includes this supervisor. The kernel/init reaps after this kill;
            // do not claim that an already-killed supervisor performed cleanup.
            let _ = killpg(group, Signal::SIGKILL);
            std::process::abort();
        }
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child_pid => direct_status = Some(code),
            Ok(WaitStatus::Signaled(pid, signal, _)) if pid == child_pid => {
                // Preserve the conventional numeric signal outcome, not the
                // original Unix wait-status representation.
                direct_status = Some(128 + signal as i32);
            }
            Ok(WaitStatus::StillAlive) => std::thread::sleep(Duration::from_millis(10)),
            Ok(_) | Err(Errno::EINTR) => {}
            Err(Errno::ECHILD) => return Ok(direct_status.unwrap_or(SETUP_FAILURE)),
            Err(_) => {
                let _ = killpg(group, Signal::SIGKILL);
                std::process::abort();
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn supervise(_: Vec<std::ffi::OsString>) -> std::io::Result<i32> {
    Err(std::io::Error::other(
        "strict support supervisor requires Linux",
    ))
}
