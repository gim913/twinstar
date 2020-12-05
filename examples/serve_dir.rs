use anyhow::*;
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use log::LevelFilter;
use northstar::{Server, Request, Response, GEMINI_PORT};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_module("northstar", LevelFilter::Debug)
        .init();

    Server::bind(("localhost", GEMINI_PORT))
        .add_route("/", handle_request)
        .serve()
        .await
}

fn handle_request(request: Request) -> BoxFuture<'static, Result<Response>> {
    async move {
        let path = request.path_segments();
        let response = northstar::util::serve_dir("public", &path).await?;

        Ok(response)
    }
    .boxed()
}
