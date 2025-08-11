use nix::{
    errno::Errno,
    sys::wait::{WaitPidFlag, WaitStatus, waitpid},
};
use std::{
    num::ParseIntError,
    str::Utf8Error,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use thiserror::Error;
use tokio::signal::unix::SignalKind;
use tokio_util::{
    sync::{CancellationToken, WaitForCancellationFuture},
    task::{TaskTracker, task_tracker::TaskTrackerWaitFuture},
};

#[cfg(feature = "tracing")]
use tracing::{error, info};

use crate::UpgradeUsr1;

#[derive(Debug, Clone)]
pub struct Bye {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    /// Task tracker to manage spawned tasks
    tracker: TaskTracker,
    /// Broadcast token to signal shutdown
    shutdown_started: CancellationToken,
    /// Indicates if the bye instance is currently running
    running: AtomicBool,
}

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid UTF-8 in env var {key}")]
    EnvUtf8 {
        key: &'static str,
        #[source]
        source: Utf8Error,
    },
    #[error("invalid value for env var {key}")]
    EnvParse {
        key: &'static str,
        #[source]
        source: ParseIntError,
    },

    #[error("UPGRADE_FD is not a valid file descriptor")]
    InvalidUpgradeFd,

    #[error("UPGRADE_FD is not open")]
    UpgradeFdNotOpen(#[source] nix::errno::Errno),

    #[error("notify write error")]
    NotifyWrite(#[source] nix::errno::Errno),

    #[error("fork failed")]
    Fork(#[source] nix::errno::Errno),
    #[error("execve failed")]
    Execve(#[source] nix::errno::Errno),
    #[error("timed out waiting for child to signal ready")]
    ChildTimeout,
    #[error("sending SIGKILL to child {pid} failed")]
    KillChild {
        pid: i32,
        #[source]
        source: nix::errno::Errno,
    },
    #[error("waitpid failed")]
    WaitPid(#[source] nix::errno::Errno),

    #[error("getsockname failed")]
    Sockname(#[source] nix::errno::Errno),
    #[error("no systemd socket activation, or wrong LISTEN_PID")]
    SystemdActivation,

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Nul(#[from] std::ffi::NulError),

    #[error(transparent)]
    Nix(#[from] nix::errno::Errno),

    #[error("pipe2 failed")]
    Pipe2(#[source] nix::errno::Errno),

    #[error("fcntl failed {op}")]
    Fcntl {
        op: &'static str,
        #[source]
        source: nix::errno::Errno,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Bye {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                tracker: TaskTracker::new(),
                running: AtomicBool::new(true),
                shutdown_started: CancellationToken::new(),
            }),
        }
    }

    pub fn new_with_signals() -> Result<Self> {
        let grace = Self::new();
        grace.spawn_signals()?;
        Ok(grace)
    }

    /// Check if it's currently running (i.e., not shut down)
    pub fn is_running(&self) -> bool {
        self.inner.running.load(Ordering::Acquire)
    }

    /// Future that resolves when shutdown is initiated (soft)
    pub fn on_shutdown(&self) -> WaitForCancellationFuture<'_> {
        self.inner.shutdown_started.cancelled()
    }

    /// Clonable token that is cancelled when shutdown is initiated (soft)
    pub fn shutdown_token(&self) -> CancellationToken {
        self.inner.shutdown_started.clone()
    }

    /// Begin the graceful shutdown process (idempotent)
    pub fn shutdown(&self) {
        if self.inner.running.swap(false, Ordering::AcqRel) {
            self.inner.shutdown_started.cancel();
            self.inner.tracker.close();
        }
    }

    /// Wait for all tracked tasks to complete
    pub fn wait(&self) -> TaskTrackerWaitFuture<'_> {
        self.inner.tracker.wait()
    }

    /// Initiate shutdown and wait for all tasks to complete
    pub fn drain(&self) -> TaskTrackerWaitFuture<'_> {
        self.shutdown();
        self.wait()
    }

    /// Spawn a new tracked task with a cancellation token
    #[must_use]
    pub fn spawn<F, Fut, T>(&self, make: F) -> tokio::task::JoinHandle<T>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        assert!(self.is_running(), "cannot spawn on shut down");
        let tok = self.inner.shutdown_started.child_token();
        self.inner.tracker.spawn(async move { make(tok).await })
    }

    #[must_use]
    pub fn try_spawn<F, Fut, T>(&self, make: F) -> Option<tokio::task::JoinHandle<T>>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if self.is_running() {
            Some(self.spawn(make))
        } else {
            None
        }
    }

    #[must_use]
    pub fn spawn_detached<F, T>(&self, f: F) -> tokio::task::JoinHandle<T>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.spawn(|_| f)
    }

    #[must_use]
    pub fn try_spawn_detached<F, T>(&self, f: F) -> Option<tokio::task::JoinHandle<T>>
    where
        F: std::future::Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        self.try_spawn(|_| f)
    }

    pub fn spawn_signals(&self) -> Result<()> {
        let mut sigchld = tokio::signal::unix::signal(SignalKind::child())?;
        let mut sigusr1 = tokio::signal::unix::signal(SignalKind::user_defined1())?;
        let mut sigterm = tokio::signal::unix::signal(SignalKind::terminate())?;
        let mut sigint = tokio::signal::unix::signal(SignalKind::interrupt())?;
        let mut sigquit = tokio::signal::unix::signal(SignalKind::quit())?;

        let upgrade = UpgradeUsr1::new(std::env::current_exe()?)?;
        let me = self.clone();
        tokio::spawn(async move {
            let res: Result<()> = async {
                loop {
                    tokio::select! {
                        _ = sigterm.recv() => {
                            #[cfg(feature = "tracing")]
                            info!("received term, shutting down gracefully.");
                            me.drain().await;
                            return Ok::<(), Error>(());
                        }
                        _ = sigint.recv() => {
                            #[cfg(feature = "tracing")]
                            info!("received int, shutting down gracefully.");
                            me.drain().await;
                            return Ok(());
                        }
                        _ = sigquit.recv() => {
                            #[cfg(feature = "tracing")]
                            info!("received quit, shutting down gracefully.");
                            me.drain().await;
                            return Ok(());
                        }
                        _ = sigusr1.recv() => {
                            #[cfg(feature = "tracing")]
                            info!("received usr1, shutting down gracefully.");
                            // could take a timeout as param for timeout
                            let upgrade = upgrade.upgrade(None).await?;
                            if upgrade {
                                #[cfg(feature = "tracing")]
                                info!("upgrade successful, shutting down gracefully.");
                                me.drain().await;
                                return Ok(());
                            } else {
                                #[cfg(feature = "tracing")]
                                info!("upgrade failed, continuing without upgrade.");
                            }
                        }
                        _ = sigchld.recv() => {
                            loop {
                                match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
                                    Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                                    Ok(_) => continue,
                                    Err(e) => {
                                        #[cfg(feature = "tracing")]
                                        error!("Error reaping child process: {}", e);
                                        break;
                                    }
                                }
                            }
                            continue;
                        }
                    }
                }
            }
            .await;

            if let Err(e) = res {
                #[cfg(feature = "tracing")]
                error!(error = ?e, "error in signal handler");
                me.shutdown();
            }
        });
        Ok(())
    }
}

impl Default for Bye {
    fn default() -> Self {
        Self::new()
    }
}
