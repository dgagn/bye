# bye

Graceful shutdown & zero-downtime USR1 upgrade helpers for Tokio apps (systemd-friendly).

- TERM / INT / QUIT - cancel tasks, stop accepting new work, wait for them to finish
- USR1 - fork+exec self, wait for the child to call `bye::ready()`, then gracefully exit the parent
- Optional systemd socket activation helpers

> Platform: Unix (Linux/BSD).
