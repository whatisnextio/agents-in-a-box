//! Executed offline-support boundary probes. Required enforcement never skips.

use ainb_hangar_sandbox::strict_support_command;
use std::path::Path;

#[test]
fn strict_support_rejects_missing_execution_root() {
    let root = tempfile::tempdir().unwrap();
    assert!(strict_support_command(Path::new("/bin/sh"), &root.path().join("missing")).is_err());
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn strict_support_rejects_unsupported_host() {
    let root = tempfile::tempdir().unwrap();
    assert!(strict_support_command(Path::new("/bin/sh"), root.path()).is_err());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use super::*;
    use std::fs;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::{Command, Stdio};

    fn execute(script: &str, root: &Path, args: &[&Path]) -> std::process::Output {
        let mut command = strict_support_command(Path::new("/usr/bin/python3"), root)
            .expect("strict confinement construction must work on the qualification host");
        command
            .command()
            .env_clear()
            .arg("-c")
            .arg(script)
            .args(args)
            .current_dir(root)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
            .command()
            .output()
            .expect("strict enforcement must succeed before child exec")
    }

    #[test]
    fn strict_support_denies_controller_and_successor_files() {
        let home = tempfile::tempdir().unwrap();
        let epoch = home.path().join("epoch-1");
        let successor = home.path().join("epoch-2");
        fs::create_dir(&epoch).unwrap();
        fs::create_dir(&successor).unwrap();
        let database = home.path().join("controller.db");
        let artifact = successor.join("artifact");
        fs::write(&database, "controller sentinel").unwrap();
        fs::write(&artifact, "successor sentinel").unwrap();
        assert!(
            fs::read("/etc/passwd").is_ok(),
            "host config positive control"
        );
        // Same-UID positive controls precede confinement.
        assert_eq!(
            fs::read_to_string(&database).unwrap(),
            "controller sentinel"
        );
        fs::write(&artifact, "successor sentinel").unwrap();
        std::os::unix::fs::symlink(&database, epoch.join("db-link")).unwrap();
        let output = execute(
            r#"
import os, sys
def denied(action):
    try:
        action()
    except PermissionError:
        return
    raise AssertionError('forbidden filesystem operation succeeded')
with open('report', 'w') as f: f.write('accepted local output')
assert open('report').read() == 'accepted local output'
for path in [sys.argv[1], sys.argv[2], 'db-link']:
    denied(lambda: open(path).read())
    denied(lambda: open(path, 'w').write('corrupt'))
    denied(lambda: os.truncate(path, 0))
    denied(lambda: os.chmod(path, 0o777))
    denied(lambda: os.utime(path, (1, 1)))
denied(lambda: open('/etc/passwd').read())
denied(lambda: open('/proc/self/status').read())
denied(lambda: open(sys.argv[3], 'w').write('forbidden create'))
print('strict-files-verified')
"#,
            &epoch,
            &[&database, &artifact, &successor.join("new-file")],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "strict-files-verified"
        );
        assert_eq!(
            fs::read_to_string(&database).unwrap(),
            "controller sentinel"
        );
        assert_eq!(fs::read_to_string(&artifact).unwrap(), "successor sentinel");
        assert!(!successor.join("new-file").exists());
        assert_eq!(
            fs::read_to_string(epoch.join("report")).unwrap(),
            "accepted local output"
        );
    }

    #[test]
    fn strict_support_denies_network_and_descendant_bypass() {
        let epoch = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let positive = TcpStream::connect(address).expect("same-UID network positive control");
        let (accepted, _) = listener.accept().unwrap();
        drop((positive, accepted));
        let output = execute(
            r#"
import socket, subprocess, sys
for family, kind in [(socket.AF_INET, socket.SOCK_STREAM),
                     (socket.AF_INET6, socket.SOCK_DGRAM),
                     (socket.AF_UNIX, socket.SOCK_STREAM)]:
    try: socket.socket(family, kind)
    except PermissionError: pass
    else: raise AssertionError('socket creation escaped seccomp')
child = subprocess.run([sys.executable, '-c',
    'import socket\ntry: socket.socket()\nexcept PermissionError: print("child-denied")\nelse: raise AssertionError("child escaped")'],
    capture_output=True, text=True)
assert child.returncode == 0, child.stderr
assert child.stdout.strip() == 'child-denied'
print('strict-network-verified')
"#,
            epoch.path(),
            &[],
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "strict-network-verified"
        );
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn strict_support_lost_root_fails_before_program_runs() {
        let home = tempfile::tempdir().unwrap();
        let epoch = home.path().join("epoch");
        fs::create_dir(&epoch).unwrap();
        let mut command = strict_support_command(Path::new("/bin/sh"), &epoch).unwrap();
        command.command().arg("-c").arg("printf worker-executed").stdout(Stdio::piped());
        fs::remove_dir(&epoch).unwrap();
        assert!(
            command.command().output().is_err(),
            "missing required root must prevent exec"
        );
        // A bare program is viable on this host; the preceding failure is setup.
        assert!(Command::new("/bin/sh").args(["-c", "exit 0"]).status().unwrap().success());
    }

    #[test]
    fn strict_support_closes_inherited_fds_and_denies_alternate_syscalls() {
        let home = tempfile::tempdir().unwrap();
        let epoch = home.path().join("epoch");
        fs::create_dir(&epoch).unwrap();
        let outside = fs::File::create(home.path().join("controller-state")).unwrap();
        // Deliberately inherit a high descriptor without CLOEXEC. Keeping it
        // above normal interpreter descriptors makes reuse unambiguous.
        // SAFETY: fcntl duplicates a live descriptor; OwnedFd closes only that
        // returned duplicate, and the original file remains owned by `outside`.
        let raw = unsafe { libc::fcntl(outside.as_raw_fd(), libc::F_DUPFD, 1000) };
        assert!(raw >= 1000, "positive inherited descriptor control");
        let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
        let syscalls = [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
            libc::SYS_pidfd_getfd,
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_move_mount,
            libc::SYS_open_tree,
            libc::SYS_fsopen,
            libc::SYS_fsconfig,
            libc::SYS_fsmount,
            libc::SYS_mount_setattr,
            libc::SYS_setsid,
            libc::SYS_setpgid,
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_tgkill,
            libc::SYS_pidfd_send_signal,
            libc::SYS_rt_sigqueueinfo,
            libc::SYS_rt_tgsigqueueinfo,
        ];
        let script = format!(
            r#"
import os, errno, ctypes, subprocess, sys
try: os.fstat({raw})
except OSError as error: assert error.errno == errno.EBADF
else: raise AssertionError('inherited controller descriptor survived exec')
libc = ctypes.CDLL(None, use_errno=True)
class Header(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
class Caps(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
header = Header(0x20080522, 0)
caps = (Caps * 2)()
assert libc.capget(ctypes.byref(header), caps) == 0
assert all(c.effective == c.permitted == c.inheritable == 0 for c in caps)
assert libc.prctl(39, 0, 0, 0, 0) == 1, 'no_new_privs absent'
for capability in range(64):
    state = libc.prctl(47, 1, capability, 0, 0)
    assert state == 0 or (state == -1 and ctypes.get_errno() == errno.EINVAL), ('ambient capability present', capability)
ctypes.set_errno(0)
assert libc.syscall({clone3}, 0, 0) == -1 and ctypes.get_errno() == errno.ENOSYS
for flag in [0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x00020000]:
    ctypes.set_errno(0)
    assert libc.syscall({clone}, flag, 0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM
for number in {syscalls:?}:
    ctypes.set_errno(0)
    result = libc.syscall(number, 0, 0, 0, 0, 0, 0)
    assert result == -1 and ctypes.get_errno() == errno.EPERM, (number, result, ctypes.get_errno())
descendant = subprocess.run([sys.executable, '-c', '''
import os, errno
for operation in [os.setsid, lambda: os.setpgid(0, 0), lambda: os.kill(os.getppid(), 0)]:
    try: operation()
    except PermissionError as error: assert error.errno == errno.EPERM
    else: raise AssertionError('descendant escaped process/signal boundary')
print('descendant-stays-confined')
'''], capture_output=True, text=True)
assert descendant.returncode == 0, descendant.stderr
assert descendant.stdout.strip() == 'descendant-stays-confined'
print('strict-alternate-paths-verified')
"#,
            clone3 = libc::SYS_clone3,
            clone = libc::SYS_clone,
        );
        let output = execute(&script, &epoch, &[]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "strict-alternate-paths-verified"
        );
        drop(inherited);
    }
}
