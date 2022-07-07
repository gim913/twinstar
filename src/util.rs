#[cfg(feature="serve_dir")]
use std::path::{Path, PathBuf};
#[cfg(feature="serve_dir")]
use mime::Mime;
use anyhow::{Result, Context};
#[cfg(feature="serve_dir")]
use tokio::{
    fs::{self, File},
    io,
};
#[cfg(feature="serve_dir")]
use crate::types::{Document, document::HeadingLevel::*};
use crate::types::Response;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::task::Poll;
use futures_core::future::Future;
use tokio::time;

#[cfg(feature="serve_dir")]
pub async fn serve_file<P: AsRef<Path>>(path: P, mime: &Mime) -> Result<Response> {
    let path = path.as_ref();

    let file = match File::open(path).await {
        Ok(file) => file,
        Err(err) => match err.kind() {
            std::io::ErrorKind::PermissionDenied => {
                warn!("Asked to serve {}, but permission denied by OS", path.display());
                return Ok(Response::not_found());
            },
            _ => return warn_unexpected(err, path, line!()),
        }
    };

    Ok(Response::success(mime, file))
}

#[cfg(feature="serve_dir")]
pub async fn serve_dir<D: AsRef<Path>, P: AsRef<Path>>(dir: D, virtual_path: &[P]) -> Result<Response> {
    debug!("Dir: {}", dir.as_ref().display());
    let dir = dir.as_ref();
    let dir = match dir.canonicalize() {
        Ok(dir) => dir,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => {
                    warn!("Path {} not found.  Check your configuration.", dir.display());
                    return Response::server_error("Server incorrectly configured")
                },
                std::io::ErrorKind::PermissionDenied => {
                    warn!("Permission denied for {}.  Check that the server has access.", dir.display());
                    return Response::server_error("Server incorrectly configured")
                },
                _ => return warn_unexpected(e, dir, line!()),
            }
        },
    };
    let mut path = dir.to_path_buf();

    for segment in virtual_path {
        path.push(segment);
    }

    let path = match path.canonicalize() {
        Ok(dir) => dir,
        Err(e) => {
            match e.kind() {
                std::io::ErrorKind::NotFound => return Ok(Response::not_found()),
                std::io::ErrorKind::PermissionDenied => {
                    // Runs when asked to serve a file in a restricted dir
                    // i.e. not /noaccess, but /noaccess/file
                    warn!("Asked to serve {}, but permission denied by OS", path.display());
                    return Ok(Response::not_found());
                },
                _ => return warn_unexpected(e, path.as_ref(), line!()),
            }
        },
    };

    if !path.starts_with(&dir) {
        return Ok(Response::not_found());
    }

    if !path.is_dir() {
        let mime = guess_mime_from_path(&path);
        return serve_file(path, &mime).await;
    }

    serve_dir_listing(path, virtual_path).await
}

#[cfg(feature="serve_dir")]
async fn serve_dir_listing<P: AsRef<Path>, B: AsRef<Path>>(path: P, virtual_path: &[B]) -> Result<Response> {
    let mut dir = match fs::read_dir(path.as_ref()).await {
        Ok(dir) => dir,
        Err(err) => match err.kind() {
            io::ErrorKind::NotFound => return Ok(Response::not_found()),
            std::io::ErrorKind::PermissionDenied => {
                warn!("Asked to serve {}, but permission denied by OS", path.as_ref().display());
                return Ok(Response::not_found());
            },
            _ => return warn_unexpected(err, path.as_ref(), line!()),
        }
    };

    let breadcrumbs: PathBuf = virtual_path.iter().collect();
    let mut document = Document::new();

    document.add_heading(H1, format!("Index of /{}", breadcrumbs.display()));
    document.add_blank_line();

    if virtual_path.get(0).map(<_>::as_ref) != Some(Path::new("")) {
        document.add_link("..", "📁 ../");
    }

    while let Some(entry) = dir.next_entry().await.context("Failed to list directory")? {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let is_dir = entry.file_type().await
            .with_context(|| format!("Failed to get file type of `{}`", entry.path().display()))?
            .is_dir();
        let trailing_slash = if is_dir { "/" } else { "" };
        let uri = format!("./{}{}", file_name, trailing_slash);

        document.add_link(uri.as_str(), format!("{icon} {name}{trailing_slash}",
            icon = if is_dir { '📁' } else { '📄' },
            name = file_name,
            trailing_slash = trailing_slash
        ));
    }

    Ok(document.into())
}

#[cfg(feature="serve_dir")]
pub fn guess_mime_from_path<P: AsRef<Path>>(path: P) -> Mime {
    let path = path.as_ref();
    let extension = path.extension().and_then(|s| s.to_str());
    let extension = match extension {
        Some(extension) => extension,
        None => return mime::APPLICATION_OCTET_STREAM,
    };

    if let "gemini" | "gmi" = extension {
        return crate::GEMINI_MIME.clone();
    }

    mime_guess::from_ext(extension).first_or_octet_stream()
}

#[cfg(feature="serve_dir")]
/// Print a warning to the log asking to file an issue and respond with "Unexpected Error"
pub (crate) fn warn_unexpected(err: impl std::fmt::Debug, path: &Path, line: u32) -> Result<Response> {
    warn!(
        concat!(
            "Unexpected error serving path {} at util.rs:{}, please report to ",
            env!("CARGO_PKG_REPOSITORY"),
            "/issues: {:?}",
        ),
        path.display(),
        line,
        err
    );
    Response::server_error("Unexpected error")
}

/// A convenience trait alias for `AsRef<T> + Into<T::Owned>`,
/// most commonly used to accept `&str` or `String`:
///
/// `Cowy<str>` ⇔ `AsRef<str> + Into<String>`
pub trait Cowy<T>
where
    Self: AsRef<T> + Into<T::Owned>,
    T: ToOwned + ?Sized,
{}

impl<C, T> Cowy<T> for C
where
    C: AsRef<T> + Into<T::Owned>,
    T: ToOwned + ?Sized,
{}

/// A utility for catching unwinds on Futures.
///
/// This is adapted from the futures-rs CatchUnwind, in an effort to reduce the large
/// amount of dependencies tied into the feature that provides this simple struct.
#[must_use = "futures do nothing unless polled"]
pub (crate) struct HandlerCatchUnwind {
    future: AssertUnwindSafe<crate::HandlerResponse>,
}

impl HandlerCatchUnwind {
    pub(super) fn new(future: AssertUnwindSafe<crate::HandlerResponse>) -> Self {
        Self { future }
    }
}

impl Future for HandlerCatchUnwind {
    type Output = Result<Result<Response>, Box<dyn std::any::Any + Send>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context
    ) -> Poll<Self::Output> {
        match catch_unwind(AssertUnwindSafe(|| self.future.as_mut().poll(cx))) {
            Ok(res) => res.map(Ok),
            Err(e) => Poll::Ready(Err(e))
        }
    }
}

pub(crate) async fn opt_timeout<T>(duration: Option<time::Duration>, future: impl Future<Output = T>) -> Result<T, time::error::Elapsed> {
    match duration {
        Some(duration) => time::timeout(duration, future).await,
        None => Ok(future.await),
    }
}
