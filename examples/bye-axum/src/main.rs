use std::error::Error;

use axum::Router;
use bye::Bye;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let grace = Bye::new_with_signals()?;

    let listener = bye::systemd_tcp_listener(8080).await?;

    println!("Listening on {}", listener.local_addr()?);

    let router = Router::new().route("/", axum::routing::get(|| async { "Ok" }));

    let token = grace.shutdown_token();
    let shutdown = async move { token.cancelled().await };

    bye::ready()?;

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .unwrap();

    Ok(())
}
