# bye

Graceful shutdown and zero‑downtime **USR1** upgrade helpers for tokio apps,
with **systemd socket activation** support.

* **Signals handled**: `SIGTERM`, `SIGINT`, `SIGQUIT`, start graceful shutdown;
`SIGUSR1` fork+exec self and switch over once the child reports **ready**;
`SIGCHLD` reap.
* **Graceful model**: broadcast a `CancellationToken`, stop accepting new work,
and **drain** tracked tasks via `TaskTracker`.
* **Upgrade flow**: parent forks/execs current binary; child boots and calls
`bye::ready()` to signal readiness; parent drains and exits.
* **systemd**: adopt pre‑opened sockets (socket activation) with
`systemd_tcp_listener(port)`.

> Platform: **Unix** (Linux/BSD).

---

## Installation

```toml
[dependencies]
bye = { version = "0.1", default-features = false }
# Optional logging
tracing = "0.1"            # if you want logs
bye = { version = "0.1", features = ["tracing"] }
```

Minimum Supported Rust Version (MSRV): **1.74**.

---

## Quick start

```rust
use bye::{Bye};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Listen for TERM/INT/QUIT/USR1 and start reaping children
    let bye = Bye::new_with_signals()?;

    // Do your initialization…
    // Only after you're ready to serve, tell the world:
    bye::ready()?;

    // Main loop
    loop {
        tokio::select! {
            _ = bye.on_shutdown() => break, // soft shutdown started
            // ... your app work here (accept connections, handle jobs, etc.)
        }
    }

    // Wait for all spawned tasks to finish
    bye.drain().await;
    Ok(())
}
```

### Spawning cancellable tasks

```rust
let handle = bye.spawn(|tok| async move {
    // Do work until cancelled
    tok.cancelled().await;
    // Cleanup
});

// If you're not sure the app is still running, use try_spawn
let maybe = bye.try_spawn(|tok| async move { /* ... */ });
```

### Using systemd socket activation

```rust
use bye::{Bye, systemd_tcp_listener};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpListener};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bye = Bye::new_with_signals()?;
    // Will adopt a socket passed by systemd for :8080 if available,
    // otherwise binds 0.0.0.0:8080 normally.
    let listener: TcpListener = systemd_tcp_listener(8080).await?;

    bye::ready()?; // tell the parent/system you're ready

    loop {
        tokio::select! {
            _ = bye.on_shutdown() => break,
            Ok((mut sock, _)) = listener.accept() => {
                bye.spawn(|tok| async move {
                    let mut buf = [0u8; 1024];
                    let _ = tokio::select! {
                        _ = tok.cancelled() => Ok::<(), std::io::Error>(()),
                        r = sock.read(&mut buf) => r.map(|_| ())
                    };
                    let _ = sock.write_all(b"bye\n").await;
                });
            }
        }
    }

    bye.wait().await;
    Ok(())
}
```

---

### Upgrade (USR1) flow

1. Send `SIGUSR1` to the running process.
2. Parent **forks** and `execve`s the current binary, passing an internal pipe
   via the `UPGRADE_FD` env var.
3. Child performs initialization. When ready to take traffic, it calls
   `bye::ready()` once.
4. Parent sees a byte written on the pipe, calls `drain()` and exits. If the
   child exits prematurely without signaling ready, the parent continues
running.

#### `bye::ready()`

* Writes one byte to the `UPGRADE_FD` pipe **once per PID** (idempotent).
* If environment variable `PIDFILE` is set, writes the numeric PID to that file.

> Call `ready()` **only after** listeners, background tasks, and any caches are fully initialized.

### systemd socket activation

* `systemd_tcp_listener(port: u16) -> TcpListener` will:
  * If `LISTEN_FDS` contains a socket for this process, adopt it (the first one if multiple).
  * Otherwise, bind to `0.0.0.0:port`.

* `systemd_ports() -> &'static [u16]` returns all discovered ports from `LISTEN_FDS` for this process (computed once).

### Signals & logging

* The signal loop is runtime‑friendly (async) and uses `tokio::signal::unix`.
* Logging is behind the `tracing` feature. When disabled, logs are elided.

## Environment variables

* `UPGRADE_FD` – *internal*, set by the parent when forking; the child writes a single byte to signal readiness. You don't set this manually.
* `PIDFILE` – if set, `ready()` writes the current PID to this path.
* `LISTEN_FDS`, `LISTEN_PID` – standard systemd socket activation variables. The crate inspects these to adopt sockets.

---

## Safety and caveats

* The crate uses `nix` to perform `fork`, `execve`, `fcntl`, and other low‑level operations. Unsafe code is limited and contained; functions that manipulate fds take/return `OwnedFd`/`BorrowedFd` where possible.
* When adopting a systemd socket with `from_raw_fd`, ownership is transferred to the child process after `execve`; do not also use those fds elsewhere.
* If an upgrade fails to signal readiness (child exits without calling `ready()`), the parent continues to serve. This is by design to avoid downtime. You can monitor the parent process and restart it if needed. Unexpected errors during upgrade will start shutdown.

---

## Feature flags

* `tracing` – enable internal logs (`info!`, `warn!`, `error!`). Off by default.

---

## Contributing

Issues and PRs welcome!

---

## License

Dual‑licensed under **MIT** or **Apache‑2.0**.
