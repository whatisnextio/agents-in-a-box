//! Opt-in offline worker confinement. The filter is built in the parent and
//! installed before exec; neither Landlock nor seccomp can be removed by the
//! worker or its descendants. This is a scoped boundary, not a syscall allowlist.

use std::os::unix::process::CommandExt;
use std::path::Path;

use crate::{Enforcement, SandboxError, SandboxPolicy, SandboxedCommand};

pub(crate) fn build(
    program: &Path,
    execution_root: &Path,
) -> Result<SandboxedCommand, SandboxError> {
    let root = execution_root.canonicalize()?;
    if !root.is_dir() {
        return Err(SandboxError::Unavailable(
            "execution root is not a directory".into(),
        ));
    }
    let program = program.canonicalize()?;
    let mut policy = SandboxPolicy::strict_support(&root);
    // Grant the executable, never its parent (which can contain controller DBs
    // or another execution). Scripts must place their interpreter in system roots.
    policy.read_roots.push(program.clone());
    let filter = network_filter();
    let filter_len = u16::try_from(filter.len())
        .map_err(|_| SandboxError::Unavailable("seccomp filter is too large".into()))?;
    let mut command = std::process::Command::new(program);
    // SAFETY: runs only in the forked child. The BPF storage is preallocated in
    // the parent and retained through installation. Syscalls report errors to
    // std's spawn handshake, so no worker program runs after failed enforcement.
    unsafe {
        command.pre_exec(move || {
            // CLOEXEC preserves std's error-reporting pipe until exec while
            // preventing inherited sockets/files from bypassing the policy.
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            crate::imp_linux::apply_strict_landlock(&policy.read_roots, &policy.write_roots)?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            drop_capabilities()?;
            let program = libc::sock_fprog {
                len: filter_len,
                filter: filter.as_ptr().cast_mut(),
            };
            if libc::prctl(libc::PR_SET_SECCOMP, 2, &raw const program) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(SandboxedCommand {
        inner: command,
        enforcement: Enforcement::Enforced,
    })
}

// Linux capability ABI v3 has two 32-bit words. Clear ambient capabilities as
// well as all three task sets: no_new_privs alone does not drop privileges a
// root-owned daemon already holds. NNP prevents regaining them across exec.
unsafe fn drop_capabilities() -> std::io::Result<()> {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let header = Header {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [Data {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: local structures match the kernel's fixed capability v3 ABI;
    // only the calling, pre-exec child is affected.
    unsafe {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL,
            0,
            0,
            0,
        ) != 0
            || libc::syscall(libc::SYS_capset, &raw const header, data.as_ptr()) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

fn statement(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn network_filter() -> Vec<libc::sock_filter> {
    const LOAD_WORD_ABS: u16 = 0x20;
    const EQUAL: u16 = 0x15;
    const JUMP_BITS_SET: u16 = 0x45;
    const RETURN: u16 = 0x06;
    const KILL_PROCESS: u32 = 0x8000_0000;
    const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
    const ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;

    // seccomp_data.arch is at byte 4; nr at byte 0. Reject alternate syscall
    // ABIs before looking at their numbers, including x32 on x86-64.
    let mut filter = vec![
        statement(LOAD_WORD_ABS, 4),
        jump(EQUAL, AUDIT_ARCH, 1, 0),
        statement(RETURN, KILL_PROCESS),
        statement(LOAD_WORD_ABS, 0),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        filter.push(jump(JUMP_BITS_SET, 0x4000_0000, 0, 1));
        filter.push(statement(RETURN, KILL_PROCESS));
    }
    // clone3 hides flags behind a pointer, so report unsupported and let libc
    // fall back to clone. Ordinary fork/threads remain available, but a worker
    // cannot acquire new user-namespace capabilities or escape its namespaces.
    filter.push(jump(EQUAL, libc::SYS_clone3 as u32, 0, 1));
    filter.push(statement(RETURN, 0x0005_0000 | libc::ENOSYS as u32));
    const NEW_NAMESPACES: u32 = 0x0200_0000
        | 0x0400_0000
        | 0x0800_0000
        | 0x1000_0000
        | 0x2000_0000
        | 0x4000_0000
        | 0x0002_0000;
    filter.push(jump(EQUAL, libc::SYS_clone as u32, 0, 4));
    filter.push(statement(LOAD_WORD_ABS, 16)); // clone flags, argument zero
    filter.push(jump(JUMP_BITS_SET, NEW_NAMESPACES, 0, 1));
    filter.push(statement(RETURN, DENY));
    filter.push(statement(LOAD_WORD_ABS, 0));
    // Async descriptor owners/signals are kernel signal-routing authority:
    // blocking kill(2) alone does not prevent fasync from signalling another
    // same-UID process. Compare the command's low word, as the kernel does.
    // Values are Linux UAPI asm-generic/fcntl.h on both supported ABIs.
    for (syscall, commands) in [
        (libc::SYS_fcntl, &[8_u32, 15, 10, 1026, 1024][..]),
        // FIOSETOWN, SIOCSPGRP, FIOASYNC; owner getters remain available.
        (libc::SYS_ioctl, &[0x8901_u32, 0x8902, 0x5452][..]),
    ] {
        filter.push(jump(
            EQUAL,
            syscall as u32,
            0,
            (commands.len() * 2 + 2) as u8,
        ));
        filter.push(statement(LOAD_WORD_ABS, 24)); // argument one: command
        for command in commands {
            filter.push(jump(EQUAL, *command, 0, 1));
            filter.push(statement(RETURN, DENY));
        }
        filter.push(statement(LOAD_WORD_ABS, 0));
    }
    // Keep ordinary status flag changes (e.g. O_NONBLOCK), but never enable
    // O_ASYNC, including on a pre-existing stdio open-file description.
    filter.push(jump(EQUAL, libc::SYS_fcntl as u32, 0, 6));
    filter.push(statement(LOAD_WORD_ABS, 24));
    filter.push(jump(EQUAL, libc::F_SETFL as u32, 0, 3));
    filter.push(statement(LOAD_WORD_ABS, 32)); // argument two: flags
    filter.push(jump(JUMP_BITS_SET, libc::O_ASYNC as u32, 0, 1));
    filter.push(statement(RETURN, DENY));
    filter.push(statement(LOAD_WORD_ABS, 0));
    for syscall in [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        // io_uring can submit socket and file operations outside the ordinary
        // syscall path. There are no inherited ring descriptors after exec.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Do not import a controller descriptor or modify another process to
        // make it perform the denied operation on the worker's behalf.
        libc::SYS_pidfd_getfd,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_open_by_handle_at,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        // Confinement must survive a privileged controller launching the
        // worker: no mount/namespace remap and no signals to other processes.
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
        // Landlock V3 does not mediate these metadata mutations. Deny them
        // even inside the execution root so known outside paths cannot be used
        // to alter controller/successor modes, ownership, timestamps or xattrs.
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        // UAPI asm-generic/unistd.h: __NR_fchmodat2 = 452 on both supported
        // architectures; libc 0.2.189 omits the aarch64 named constant.
        452,
        libc::SYS_fchown,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
    ] {
        filter.push(jump(EQUAL, syscall as u32, 0, 1));
        filter.push(statement(RETURN, DENY));
    }
    #[cfg(target_arch = "x86_64")]
    for syscall in [
        libc::SYS_chmod,
        libc::SYS_chown,
        libc::SYS_lchown,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
    ] {
        filter.push(jump(EQUAL, syscall as u32, 0, 1));
        filter.push(statement(RETURN, DENY));
    }
    filter.push(statement(RETURN, ALLOW));
    filter
}
