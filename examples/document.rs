use anyhow::*;
use futures_core::future::BoxFuture;
use futures_util::FutureExt;
use log::LevelFilter;
use twinstar::document::HeadingLevel::*;
use twinstar::{Document, Request, Response, Server, GEMINI_PORT};

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::builder()
        .filter_module("twinstar", LevelFilter::Debug)
        .init();

    Server::bind(("localhost", GEMINI_PORT))
        .add_route("/", handle_request)
        .serve()
        .await
}

fn handle_request(_request: Request) -> BoxFuture<'static, Result<Response>> {
    async move {
        let response = Document::new()
            .add_preformatted(include_str!("twinstar_logo.txt"))
            .add_blank_line()
            .add_link("https://docs.rs/twinstar", "Documentation")
            .add_link("https://github.com/panicbit/twinstar", "GitHub")
            .add_blank_line()
            .add_heading(H1, "Usage")
            .add_blank_line()
            .add_text("Add the latest version of twinstar to your `Cargo.toml`.")
            .add_blank_line()
            .add_heading(H2, "Manually")
            .add_blank_line()
            .add_preformatted_with_alt(
                "toml",
                r#"twinstar = "0.3.0" # check crates.io for the latest version"#,
            )
            .add_blank_line()
            .add_heading(H2, "Automatically")
            .add_blank_line()
            .add_preformatted_with_alt("sh", "cargo add twinstar")
            .add_blank_line()
            .add_heading(H1, "Generating a key & certificate")
            .add_blank_line()
            .add_preformatted_with_alt(
                "sh",
                concat!(
                "mkdir cert && cd cert\n",
                "openssl req -x509 -nodes -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365",
            ),
            )
            .into();
        Ok(response)
    }
    .boxed()
}
