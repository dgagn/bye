use std::{
    env::VarError,
    ffi::{CString, OsStr},
    fmt::Display,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::PathBuf,
    sync::{LazyLock, atomic::AtomicU32},
    time::Duration,
};

use bye::Error;
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    sys::{socket::getsockname, wait::waitpid},
    unistd::{ForkResult, execve, fork, pipe2, read},
};
use tokio::{io::unix::AsyncFd, net::TcpListener};

pub use bye::Bye;

#[cfg(feature = "tracing")]
use tracing::{error, info, warn};

mod bye;

const READY_ENV: &str = "UPGRADE_FD";
static READY_LAST_PID: AtomicU32 = AtomicU32::new(0);

#[derive(Debug)]
struct UpgradeUsr1 {
    exe_path: CString,
    args: Vec<CString>,
    env: Vec<CString>,
}

impl UpgradeUsr1 {
    pub fn new(exe_path: PathBuf) -> bye::Result<Self> {
        let exe_path = CString::new(exe_path.as_os_str().as_bytes())?;
        let args = std::env::args_os()
            .map(|arg| CString::new(arg.as_bytes()))
            .collect::<Result<Vec<_>, _>>()?;

        let env = std::env::vars_os()
            .map(|(key, value)| {
                let mut kv = Vec::new();
                kv.extend(key.as_bytes());
                kv.push(b'=');
                kv.extend(value.as_bytes());
                CString::new(kv)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            exe_path,
            args,
            env,
        })
    }

    pub async fn upgrade(&self, timeout: Option<Duration>) -> bye::Result<bool> {
        fork_and_exec(&self.exe_path, &self.args, &self.env, timeout).await
    }
}

fn cstr_kv_eq_ignore_ascii(e: &CString, key: &[u8]) -> bool {
    let bytes = e.as_bytes();
    if let Some(eq) = memchr::memchr(b'=', bytes) {
        bytes[..eq].eq_ignore_ascii_case(key)
    } else {
        false
    }
}

fn replace_or_push_env<D: Display>(env: &mut Vec<CString>, key: &str, val: D) -> bye::Result<()> {
    let kbytes = key.as_bytes();
    if let Some(idx) = env.iter().position(|e| cstr_kv_eq_ignore_ascii(e, kbytes)) {
        env[idx] = CString::new(format!("{key}={val}"))?;
    } else {
        env.push(CString::new(format!("{key}={val}"))?);
    }
    Ok(())
}

fn get_env_u32(env: &[CString], key: &str) -> Option<u32> {
    let kbytes = key.as_bytes();
    for e in env {
        let bytes = e.as_bytes();
        if let Some(eq) = memchr::memchr(b'=', bytes) {
            if bytes[..eq].eq_ignore_ascii_case(kbytes) {
                if let Ok(s) = std::str::from_utf8(&bytes[eq + 1..]) {
                    if let Ok(n) = s.parse::<u32>() {
                        return Some(n);
                    }
                }
            }
        }
    }
    None
}

async fn fork_and_exec(
    path: &CString,
    args: &[CString],
    env: &[CString],
    timeout: Option<Duration>,
) -> bye::Result<bool> {
    let (read_fd, write_fd) = pipe2(OFlag::O_CLOEXEC).map_err(Error::Pipe2)?;

    clear_cloexec(&write_fd)?;
    set_nonblocking(&read_fd)?;

    let mut env_with_fd = Vec::with_capacity(env.len() + 1);
    env_with_fd.extend(
        env.iter()
            .filter(|e| !cstr_kv_eq_ignore_ascii(e, READY_ENV.as_bytes()))
            .cloned(),
    );
    env_with_fd.push(CString::new(format!(
        "{}={}",
        READY_ENV,
        write_fd.as_raw_fd()
    ))?);

    // cstr for execve with old argv
    let argv: Vec<&_> = args.iter().map(|s| s.as_c_str()).collect();

    match unsafe { fork().map_err(Error::Fork)? } {
        ForkResult::Parent { child } => {
            drop(env_with_fd);

            // make sure the write fd is closed in the parent
            drop(write_fd);

            let af = AsyncFd::new(read_fd)?;
            // could have a timeout here if desired

            let fut = async move {
                let mut buf = [0; 1];
                loop {
                    let mut guard = af.readable().await?;
                    match read(&af, &mut buf) {
                        Ok(0) => return Ok(false),
                        Ok(_) => return Ok(true),
                        Err(Errno::EAGAIN) => {
                            // continue waiting
                            guard.clear_ready();
                            continue;
                        }
                        Err(Errno::EINTR) => {
                            // interrupted, continue waiting
                            guard.clear_ready();
                            continue;
                        }
                        Err(e) => {
                            return Err(Error::Nix(e));
                        }
                    }
                }
            };

            let result = if let Some(dur) = timeout {
                tokio::time::timeout(dur, fut).await
            } else {
                Ok(fut.await)
            };

            match result {
                Ok(Ok(true)) => Ok(true),
                Ok(Ok(false)) => Ok(false),
                Ok(Err(e)) => Err(e),
                Err(_) => {
                    use nix::sys::signal::{Signal, kill};
                    kill(child, Signal::SIGKILL).map_err(|e| Error::KillChild {
                        pid: child.into(),
                        source: e,
                    })?;
                    waitpid(child, None).map_err(Error::WaitPid)?;
                    Err(Error::ChildTimeout)
                }
            }
        }
        ForkResult::Child => {
            drop(read_fd);

            if let Some(nfds) = get_env_u32(&env_with_fd, "LISTEN_FDS") {
                if nfds > 0 {
                    let child_pid = std::process::id();
                    replace_or_push_env(&mut env_with_fd, "LISTEN_PID", child_pid).ok();

                    for i in 0..nfds {
                        let fd = (3 + i) as i32;
                        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
                        if let Err(e) = clear_cloexec(&borrowed) {
                            #[cfg(feature = "tracing")]
                            error!("failed to clear cloexec on fd {}: {}", fd, e);
                            std::process::exit(127);
                        }
                    }
                }
            }

            let envp: Vec<&_> = env_with_fd.iter().map(|s| s.as_c_str()).collect();

            execve(path, &argv, &envp).map_err(Error::Execve)?;
            std::process::exit(127);
        }
    }
}

fn parse_fd_from_env(v: &OsStr) -> bye::Result<i32> {
    let s = std::str::from_utf8(v.as_bytes()).map_err(|e| Error::EnvUtf8 {
        key: "UPGRADE_FD",
        source: e,
    })?;
    let fd = s.parse::<i32>().map_err(|e| Error::EnvParse {
        key: "UPGRADE_FD",
        source: e,
    })?;
    if fd < 0 {
        return Err(Error::InvalidUpgradeFd);
    }
    Ok(fd)
}

pub fn try_pid_file() -> Result<PathBuf, VarError> {
    Ok(std::env::var("PIDFILE")?.into())
}

static SYSTEMD_PORTS: LazyLock<Vec<u16>> = std::sync::LazyLock::new(|| {
    compute_systemd_ports().unwrap_or_else(|e| {
        #[cfg(feature = "tracing")]
        error!("Failed to compute systemd ports: {}", e);
        vec![]
    })
});

pub fn systemd_ports() -> &'static [u16] {
    &SYSTEMD_PORTS
}

fn compute_systemd_ports() -> bye::Result<Vec<u16>> {
    let listen_fds = std::env::var("LISTEN_FDS")
        .unwrap_or("0".to_string())
        .parse::<u32>()
        .map_err(|e| Error::EnvParse {
            key: "LISTEN_FDS",
            source: e,
        })?;

    let listen_pid = std::env::var("LISTEN_PID")
        .unwrap_or("0".to_string())
        .parse::<u32>()
        .map_err(|e| Error::EnvParse {
            key: "LISTEN_PID",
            source: e,
        })?;

    if listen_fds == 0 || listen_pid != std::process::id() {
        return Err(Error::SystemdActivation);
    }

    let mut ports = Vec::with_capacity(listen_fds as usize);
    for i in 0..listen_fds {
        let fd = (3 + i) as i32;

        let port = match getsockname::<nix::sys::socket::SockaddrStorage>(fd) {
            Ok(v) => v
                .as_sockaddr_in()
                .map(|sockaddr| sockaddr.port())
                .or_else(|| v.as_sockaddr_in6().map(|sockaddr| sockaddr.port()))
                .unwrap_or(0),
            Err(e) => {
                return Err(Error::Sockname(e));
            }
        };
        if port != 0 {
            ports.push(port);
        }
    }

    Ok(ports)
}

/// Creates a TCP listener that uses systemd socket activation if available.
pub async fn systemd_tcp_listener(port: u16) -> bye::Result<TcpListener> {
    let systemd_ports = SYSTEMD_PORTS.iter().position(|&p| p == port);
    let listener = if let Some(systemd_port) = systemd_ports {
        let fd = (3 + systemd_port) as i32;
        #[cfg(feature = "tracing")]
        info!("using systemd socket fd: {}", fd);
        let raw_listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
        raw_listener.set_nonblocking(true)?;
        TcpListener::from_std(raw_listener)?
    } else {
        #[cfg(feature = "tracing")]
        warn!("no systemd socket found for port {}", port);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
        TcpListener::bind(addr).await?
    };

    Ok(listener)
}

/// Notifies the system that the service is ready.
pub fn ready() -> bye::Result<()> {
    let pid = std::process::id();
    let prev = READY_LAST_PID.swap(pid, std::sync::atomic::Ordering::AcqRel);

    if prev == pid {
        return Ok(());
    }

    if let Some(val) = std::env::var_os(READY_ENV) {
        let fd = parse_fd_from_env(&val)?;
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        fcntl(&fd, FcntlArg::F_GETFD).map_err(|e| Error::Fcntl {
            op: "F_GETFD",
            source: e,
        })?;

        loop {
            let n = nix::unistd::write(&fd, &[1u8]);
            match n {
                Ok(_) => break,
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => continue,
                Err(Errno::EPIPE) => {
                    #[cfg(feature = "tracing")]
                    warn!("UPGRADE_FD is closed, ignoring write");
                    break;
                }
                Err(e) => {
                    return Err(Error::NotifyWrite(e));
                }
            }
        }
    }

    if let Ok(pid_file) = try_pid_file() {
        let pid = std::process::id();
        std::fs::write(pid_file, pid.to_string())?;
    }

    Ok(())
}

fn clear_cloexec<F: AsFd>(fd: &F) -> bye::Result<()> {
    let getfd = fcntl(fd, FcntlArg::F_GETFD).map_err(|e| Error::Fcntl {
        op: "F_GETFD",
        source: e,
    })?;
    let flags = FdFlag::from_bits_truncate(getfd);
    let new_flags = flags.difference(FdFlag::FD_CLOEXEC);
    fcntl(fd, FcntlArg::F_SETFD(new_flags)).map_err(|e| Error::Fcntl {
        op: "F_SETFD",
        source: e,
    })?;
    Ok(())
}

fn set_nonblocking(fd: &OwnedFd) -> bye::Result<()> {
    let getfl = fcntl(fd, FcntlArg::F_GETFL).map_err(|e| Error::Fcntl {
        op: "F_GETFL",
        source: e,
    })?;
    let flags = OFlag::from_bits_truncate(getfl);
    let new_flags = flags | OFlag::O_NONBLOCK;
    fcntl(fd, FcntlArg::F_SETFL(new_flags)).map_err(|e| Error::Fcntl {
        op: "F_SETFL",
        source: e,
    })?;
    Ok(())
}
