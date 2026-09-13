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
    use std::os::unix::fs::MetadataExt;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    // Hold the actual owned child through every observation and reap on all
    // paths. No test operation accepts a caller-supplied target PID.
    struct SignalTarget(std::process::Child);

    impl Drop for SignalTarget {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn signal_target(directory: &Path) -> SignalTarget {
        fs::create_dir(directory).unwrap();
        let ready = directory.join("ready");
        let marker = directory.join("notification");
        let mut target = SignalTarget(
            Command::new("/usr/bin/python3")
                .env_clear()
                .args([
                    "-c",
                    "import signal, sys\ndef notified(*_):\n    with open(sys.argv[2], 'w') as f: f.write('kernel-notification')\nsignal.signal(signal.SIGUSR1, notified)\nwith open(sys.argv[1], 'w') as f: f.write('ready')\nwhile True: signal.pause()",
                ])
                .arg(&ready)
                .arg(&marker)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("fresh namespace-owned signal target must start"),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !ready.exists() {
            assert!(
                target.0.try_wait().unwrap().is_none(),
                "target exited before readiness"
            );
            assert!(
                Instant::now() < deadline,
                "signal handler readiness timed out"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        target
    }

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
        // Reusing the name must not silently authorise a replacement inode.
        // The command retains the original inode, preventing identity reuse.
        fs::create_dir(&epoch).unwrap();
        assert!(
            command.command().output().is_err(),
            "a replacement directory must prevent exec"
        );
        fs::remove_dir(&epoch).unwrap();
        let successor = home.path().join("successor");
        fs::create_dir(&successor).unwrap();
        fs::write(successor.join("sentinel"), "owned successor").unwrap();
        std::os::unix::fs::symlink(&successor, &epoch).unwrap();
        assert!(
            command.command().output().is_err(),
            "a replacement symlink must prevent exec"
        );
        assert_eq!(
            fs::read_to_string(successor.join("sentinel")).unwrap(),
            "owned successor"
        );
        // A newly bound, unchanged root must still start the same program with
        // full strict enforcement; failures above cannot pass vacuously.
        let mut positive = strict_support_command(Path::new("/bin/sh"), &successor).unwrap();
        let output = positive
            .command()
            .args(["-c", "printf worker-executed"])
            .stdout(Stdio::piped())
            .output()
            .expect("unchanged required root must allow exec");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"worker-executed");
        // A bare program is viable on this host; the preceding failure is setup.
        assert!(Command::new("/bin/sh").args(["-c", "exit 0"]).status().unwrap().success());
        println!(
            "\nstrict-required-root-verified missing=spawn-denied replacement-directory=spawn-denied replacement-symlink=spawn-denied unchanged-root=executed"
        );
    }

    #[test]
    fn strict_support_closes_inherited_fds_and_denies_alternate_syscalls() {
        const PARENT_NAMESPACE: &str = "HANGAR_STRICT_FCNTL_PARENT_NS";
        const INNER_PROOF: &str = "owned-namespace-async-controls-verified";
        let namespace = fs::read_link("/proc/self/ns/pid").unwrap();
        match std::env::var_os(PARENT_NAMESPACE) {
            None => {
                // This one case contains a real, benign kernel notification.
                // Isolate its fresh owned targets from all host processes.
                // Missing namespace tooling is a failure, never a skip.
                let output = Command::new("sudo")
                    .args([
                        "-n",
                        "timeout",
                        "--signal=KILL",
                        "30s",
                        "unshare",
                        "--pid",
                        "--fork",
                        "--mount-proc",
                        "--kill-child",
                        "env",
                        "-i",
                        "PATH=/usr/bin:/bin",
                    ])
                    .arg(format!("{PARENT_NAMESPACE}={}", namespace.display()))
                    .arg(std::env::current_exe().unwrap().canonicalize().unwrap())
                    .args([
                        "--exact",
                        "linux::strict_support_closes_inherited_fds_and_denies_alternate_syscalls",
                        "--test-threads=1",
                        "--nocapture",
                    ])
                    .output()
                    .expect("sudo and a disposable PID namespace are mandatory for this probe");
                assert!(
                    output.status.success(),
                    "nested probe failed: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                let proof: Vec<_> =
                    stdout.lines().filter(|line| line.starts_with(INNER_PROOF)).collect();
                assert_eq!(
                    proof.len(),
                    1,
                    "nested test must emit exactly one namespace proof"
                );
                // Do not replay nested libtest result lines: the outer named
                // test remains one mandatory case in the frozen runset.
                println!("\n{}", proof[0]);
                return;
            }
            Some(parent) => assert_ne!(
                namespace,
                std::path::PathBuf::from(parent),
                "notification probe must run in a new PID namespace"
            ),
        }
        assert_eq!(
            std::process::id(),
            1,
            "nested test must own its PID namespace"
        );
        let home = tempfile::tempdir().unwrap();
        let epoch = home.path().join("epoch");
        fs::create_dir(&epoch).unwrap();
        let positive_directory = home.path().join("positive-target");
        let mut positive = signal_target(&positive_directory);
        let observer_uid = unsafe { libc::geteuid() };
        let positive_pid = positive.0.id();
        assert_eq!(
            fs::metadata(format!("/proc/{positive_pid}")).unwrap().uid(),
            observer_uid,
            "positive target must have the observer's UID"
        );
        let mut pipe = [-1; 2];
        // SAFETY: pipe2 returns fresh owned descriptors. The signal target is
        // our live Child in this private namespace and only handles SIGUSR1.
        assert_eq!(
            unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let read_pipe = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
        let write_pipe = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
        let flags = unsafe { libc::fcntl(read_pipe.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    read_pipe.as_raw_fd(),
                    libc::F_SETOWN,
                    positive.0.id() as libc::pid_t,
                )
            },
            0
        );
        // F_SETSIG is Linux UAPI command 10 on both supported native ABIs.
        assert_eq!(
            unsafe { libc::fcntl(read_pipe.as_raw_fd(), 10, libc::SIGUSR1) },
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(read_pipe.as_raw_fd(), libc::F_SETFL, flags | libc::O_ASYNC) },
            0
        );
        assert_eq!(
            unsafe { libc::write(write_pipe.as_raw_fd(), b"x".as_ptr().cast(), 1) },
            1
        );
        let notification = positive_directory.join("notification");
        let deadline = Instant::now() + Duration::from_secs(3);
        while fs::read_to_string(&notification).ok().as_deref() != Some("kernel-notification") {
            assert!(
                positive.0.try_wait().unwrap().is_none(),
                "positive target unexpectedly exited"
            );
            assert!(
                Instant::now() < deadline,
                "unconfined kernel notification did not arrive"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            fs::read_to_string(&notification).unwrap(),
            "kernel-notification"
        );
        assert!(positive.0.try_wait().unwrap().is_none());
        assert_eq!(
            unsafe { libc::fcntl(read_pipe.as_raw_fd(), libc::F_SETFL, flags) },
            0
        );
        drop((read_pipe, write_pipe));
        drop(positive);
        let negative_directory = home.path().join("confined-target");
        let mut negative = signal_target(&negative_directory);
        let target_pid = negative.0.id();
        assert_eq!(
            fs::metadata(format!("/proc/{target_pid}")).unwrap().uid(),
            observer_uid,
            "confined target must have the observer's UID"
        );
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
import os, errno, ctypes, subprocess, sys, fcntl, signal, struct
try: os.fstat({raw})
except OSError as error: assert error.errno == errno.EBADF
else: raise AssertionError('inherited controller descriptor survived exec')
libc = ctypes.CDLL(None, use_errno=True)
def denied(operation):
    try: operation()
    except OSError as error: assert error.errno == errno.EPERM, error
    else: raise AssertionError('async signal authority escaped confinement')
r, w = os.pipe()
# Ordinary fcntl remains useful: descriptor flags, nonblocking status, and dup.
fd_flags = fcntl.fcntl(r, fcntl.F_GETFD)
fcntl.fcntl(r, fcntl.F_SETFD, fd_flags | fcntl.FD_CLOEXEC)
assert fcntl.fcntl(r, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
flags = fcntl.fcntl(r, fcntl.F_GETFL)
fcntl.fcntl(r, fcntl.F_SETFL, flags | os.O_NONBLOCK)
assert fcntl.fcntl(r, fcntl.F_GETFL) & os.O_NONBLOCK
duplicate = fcntl.fcntl(r, fcntl.F_DUPFD, 10)
os.close(duplicate)
denied(lambda: fcntl.fcntl(r, fcntl.F_SETOWN, {target_pid}))
denied(lambda: fcntl.fcntl(r, 15, struct.pack('ii', 1, {target_pid}))) # F_SETOWN_EX / F_OWNER_PID
denied(lambda: fcntl.fcntl(r, 10, signal.SIGUSR1)) # F_SETSIG
denied(lambda: fcntl.fcntl(r, fcntl.F_SETFL, flags | os.O_ASYNC))
directory = os.open('.', os.O_RDONLY | os.O_DIRECTORY)
denied(lambda: fcntl.fcntl(directory, 1026, 2)) # F_NOTIFY / DN_MODIFY
lease = os.open('lease-control', os.O_CREAT | os.O_RDWR, 0o600)
denied(lambda: fcntl.fcntl(lease, 1024, fcntl.F_WRLCK)) # F_SETLEASE
for command, value in [(0x8901, {target_pid}), (0x8902, {target_pid}), (0x5452, 1)]:
    denied(lambda: fcntl.ioctl(r, command, struct.pack('i', value)))
assert os.write(w, b'x') == 1
assert os.read(r, 1) == b'x'
for fd in [r, w, directory, lease]: os.close(fd)
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
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !negative_directory.join("notification").exists(),
            "confined notification unexpectedly reached owned target"
        );
        assert!(
            negative.0.try_wait().unwrap().is_none(),
            "confined target must remain alive"
        );
        drop(inherited);
        println!(
            "\n{INNER_PROOF} namespace={} observer_uid={observer_uid} positive_pid={positive_pid} positive_uid={observer_uid} positive_notification=received positive_target=alive confined_target_pid={target_pid} confined_target_uid={observer_uid} confined_commands=EPERM confined_notification=absent confined_target=alive ordinary_fcntl=usable",
            namespace.display()
        );
    }

    #[test]
    fn strict_support_denies_peer_resource_limits() {
        const PARENT_NAMESPACE: &str = "HANGAR_STRICT_RESOURCE_PARENT_NS";
        const PROOF: &str = "owned-namespace-peer-resource-controls-verified";
        let namespace = fs::read_link("/proc/self/ns/pid").unwrap();
        match std::env::var_os(PARENT_NAMESPACE) {
            None => {
                let output = Command::new("sudo")
                    .args([
                        "-n",
                        "timeout",
                        "--signal=KILL",
                        "30s",
                        "unshare",
                        "--pid",
                        "--fork",
                        "--mount-proc",
                        "--kill-child",
                        "env",
                        "-i",
                        "PATH=/usr/bin:/bin",
                    ])
                    .arg(format!("{PARENT_NAMESPACE}={}", namespace.display()))
                    .arg(std::env::current_exe().unwrap().canonicalize().unwrap())
                    .args([
                        "--exact",
                        "linux::strict_support_denies_peer_resource_limits",
                        "--test-threads=1",
                        "--nocapture",
                    ])
                    .output()
                    .expect("owned PID namespace tooling is mandatory for peer-resource probe");
                assert!(
                    output.status.success(),
                    "nested peer-resource probe failed: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert_eq!(
                    stdout
                        .lines()
                        .filter(|line| line.starts_with(PROOF))
                        .count(),
                    1
                );
                // Retain actual native/parent observations, without duplicating
                // the nested libtest names or result count in the outer suite.
                for line in stdout.lines().filter(|line| {
                    line.starts_with(PROOF)
                        || line.starts_with("RESOURCE_NATIVE ")
                        || line.starts_with("RESOURCE_OBSERVER ")
                }) {
                    println!("\n{line}");
                }
                return;
            }
            Some(parent) => assert_ne!(
                namespace,
                std::path::PathBuf::from(parent),
                "peer-resource probe requires a fresh PID namespace"
            ),
        }
        assert_eq!(std::process::id(), 1, "test must own its PID namespace");

        struct ResourceTarget(std::process::Child);
        impl Drop for ResourceTarget {
            fn drop(&mut self) {
                // Ordinary owned-child teardown only, after observations or on
                // assertion failure. No signal operation forms part of the probe.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        fn observed_limits(target: &ResourceTarget) -> (u64, u64) {
            let mut limits = libc::rlimit64 {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: PID comes only from our held live Child. This call queries
            // its limit and never supplies a replacement limit.
            assert_eq!(
                unsafe {
                    libc::prlimit64(
                        libc::pid_t::try_from(target.0.id()).unwrap(),
                        libc::RLIMIT_NOFILE,
                        std::ptr::null(),
                        &raw mut limits,
                    )
                },
                0,
                "parent must query its owned target"
            );
            (limits.rlim_cur, limits.rlim_max)
        }
        let home = tempfile::tempdir().unwrap();
        let epoch = home.path().join("epoch");
        fs::create_dir(&epoch).unwrap();
        let mut uids = [0; 3];
        let mut gids = [0; 3];
        // SAFETY: writable arrays contain exactly the three output identities.
        assert_eq!(
            unsafe { libc::getresuid(&raw mut uids[0], &raw mut uids[1], &raw mut uids[2]) },
            0
        );
        assert_eq!(
            unsafe { libc::getresgid(&raw mut gids[0], &raw mut gids[1], &raw mut gids[2]) },
            0
        );
        assert!(uids.iter().all(|value| *value == uids[0]));
        assert!(gids.iter().all(|value| *value == gids[0]));
        let mut targets = Vec::new();
        for name in ["positive", "confined"] {
            let ready = home.path().join(format!("{name}-ready"));
            let mut target = ResourceTarget(
                Command::new("/usr/bin/python3")
                    .env_clear()
                    .args([
                        "-c",
                        r#"
import os, resource, sys, time
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
values = [os.getpid(), *os.getresuid(), *os.getresgid(), soft, hard]
with open(sys.argv[1] + '.pending', 'x') as f:
    f.write(' '.join(str((1 << 64) - 1 if value == -1 else value) for value in values))
os.rename(sys.argv[1] + '.pending', sys.argv[1])
while True: time.sleep(1)
"#,
                    ])
                    .arg(&ready)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .expect("fresh owned resource target must start"),
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            while !ready.exists() {
                assert!(
                    target.0.try_wait().unwrap().is_none(),
                    "target exited before readiness"
                );
                assert!(
                    Instant::now() < deadline,
                    "owned target readiness timed out"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            let values: Vec<u64> = fs::read_to_string(&ready)
                .unwrap()
                .split_whitespace()
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(values.len(), 9);
            assert_eq!(values[0], u64::from(target.0.id()));
            assert_eq!(values[1..4], uids.map(u64::from));
            assert_eq!(values[4..7], gids.map(u64::from));
            assert_eq!(
                fs::read_link(format!("/proc/{}/ns/pid", target.0.id())).unwrap(),
                namespace
            );
            assert_eq!(observed_limits(&target), (values[7], values[8]));
            assert!(values[7] >= 64, "minimum safe initial soft NOFILE is 64");
            assert!(target.0.try_wait().unwrap().is_none());
            targets.push(target);
        }
        assert_ne!(targets[0].0.id(), targets[1].0.id());
        // The same script executes in both modes. It records the actual syscall
        // result even when confinement fails, so the parent can retain and
        // independently compare the target's limits before its denial assertion.
        const NATIVE: &str = r#"
import ctypes, errno, os, resource, sys
libc = ctypes.CDLL(None, use_errno=True)
class Header(ctypes.Structure):
    _fields_ = [('version', ctypes.c_uint32), ('pid', ctypes.c_int)]
class Caps(ctypes.Structure):
    _fields_ = [('effective', ctypes.c_uint32), ('permitted', ctypes.c_uint32), ('inheritable', ctypes.c_uint32)]
class Limit(ctypes.Structure):
    _fields_ = [('soft', ctypes.c_uint64), ('hard', ctypes.c_uint64)]
assert libc.prctl(47, 4, 0, 0, 0) == 0, 'ambient clear failed'
header = Header(0x20080522, 0)
caps = (Caps * 2)()
assert libc.capset(ctypes.byref(header), caps) == 0, 'capability clear failed'
assert libc.capget(ctypes.byref(header), caps) == 0
assert all(c.effective == c.permitted == c.inheritable == 0 for c in caps)
for capability in range(64):
    ctypes.set_errno(0)
    state = libc.prctl(47, 1, capability, 0, 0)
    assert state == 0 or (state == -1 and ctypes.get_errno() == errno.EINVAL), 'ambient capability remains'
libc.prlimit64.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(Limit), ctypes.POINTER(Limit)]
libc.prlimit64.restype = ctypes.c_int
self_limit = Limit()
assert libc.prlimit64(0, resource.RLIMIT_NOFILE, None, ctypes.byref(self_limit)) == 0, 'self query failed'
pid, soft, hard = map(int, sys.argv[1:])
assert pid > 1 and pid != os.getpid() and soft >= 64
replacement = Limit(soft - 1, hard)
old = Limit()
ctypes.set_errno(0)
result = libc.prlimit64(pid, resource.RLIMIT_NOFILE, ctypes.byref(replacement), ctypes.byref(old))
error = ctypes.get_errno()
print('RESOURCE_NATIVE', os.getpid(), *os.getresuid(), *os.getresgid(), self_limit.soft, self_limit.hard,
      result, error, old.soft, old.hard, 'caps=zero', 'ambient=zero', 'self=usable', flush=True)
"#;
        for (index, target) in targets.iter_mut().enumerate() {
            let before = observed_limits(target);
            let arguments = [
                target.0.id().to_string(),
                before.0.to_string(),
                before.1.to_string(),
            ];
            let output = if index == 0 {
                Command::new("/usr/bin/python3")
                    .env_clear()
                    .arg("-c")
                    .arg(NATIVE)
                    .args(&arguments)
                    .current_dir(&epoch)
                    .stdin(Stdio::null())
                    .output()
                    .expect("unconfined native positive probe must execute")
            } else {
                let paths: Vec<_> = arguments.iter().map(Path::new).collect();
                execute(NATIVE, &epoch, &paths)
            };
            println!("\n{}", String::from_utf8_lossy(&output.stdout).trim_end());
            assert!(
                output.status.success(),
                "native probe failed before observation: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            let fields: Vec<_> = stdout.split_whitespace().collect();
            assert_eq!(fields.len(), 17, "native probe observation shape");
            assert_eq!(fields[0], "RESOURCE_NATIVE");
            assert_eq!(&fields[14..], &["caps=zero", "ambient=zero", "self=usable"]);
            let values: Vec<i128> = fields[1..14]
                .iter()
                .map(|value| value.parse().unwrap())
                .collect();
            assert_eq!(values[1..4], uids.map(i128::from));
            assert_eq!(values[4..7], gids.map(i128::from));
            let after = observed_limits(target);
            let alive = target.0.try_wait().unwrap().is_none();
            println!(
                "\nRESOURCE_OBSERVER mode={} target={} before_soft={} before_hard={} after_soft={} after_hard={} target_alive={alive}",
                if index == 0 { "unconfined" } else { "strict" },
                target.0.id(),
                before.0,
                before.1,
                after.0,
                after.1
            );
            assert!(alive, "owned target must remain alive");
            if index == 0 {
                assert_eq!(
                    (values[9], values[10]),
                    (0, 0),
                    "same-identity capability-free positive must succeed"
                );
                assert_eq!(
                    (values[11], values[12]),
                    (i128::from(before.0), i128::from(before.1))
                );
                assert_eq!(after, (before.0 - 1, before.1));
            } else {
                assert_eq!(
                    (values[9], values[10]),
                    (-1, i128::from(libc::EPERM)),
                    "strict worker must deny peer RLIMIT_NOFILE mutation"
                );
                assert_eq!(after, before, "strict peer limit must remain unchanged");
            }
        }
        println!(
            "\n{PROOF} namespace={} uid={} gid={} positive=soft-lowered-one hard=unchanged strict=EPERM targets=alive self=usable",
            namespace.display(),
            uids[0],
            gids[0]
        );
    }
}
