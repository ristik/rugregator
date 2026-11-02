//! The connection layer: an explicit HTTP/1 accept loop in place of `axum::serve`.
//!
//! Owning the loop buys what the service needs for bounded, joinable request lifetimes:
//!
//! * **Write accounting.** A response keeps its unit of the global budget until the bytes have
//!   been written to the socket: the response body arms the connection with the unit and a write
//!   deadline when hyper has framed it; the connection releases it when hyper's flush completes,
//!   or fails the write when the deadline passes (a slow reader cannot hold capacity).
//! * **Disconnect detection while pipelined.** hyper skips its EOF probe while the next request
//!   is already buffered. A watcher on a duplicate of the socket peeks for EOF/RST and drops the
//!   connection (and with it every request future, queue entry and reservation) at once.
//! * **Shutdown.** Connections are tracked in a `JoinSet`: graceful shutdown stops accepting and
//!   lets requests finish, and at the grace deadline the remaining connections are aborted and
//!   joined for real.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::{Extension, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::Interest;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, Sleep};
use tracing::{debug, warn};

use crate::longpoll::ActiveHandle;

/// Transport bounds. Each connection costs two descriptors (the socket and the duplicate used by
/// the close watcher), so `max_connections` also bounds descriptor use.
#[derive(Debug, Clone, Copy)]
pub struct TransportConfig {
    /// Bound on reading a request head (slow-header clients).
    pub header_read_timeout: Duration,
    /// Connections served at once. At the bound the loop stops accepting (new peers wait in the
    /// kernel backlog) until a connection closes.
    pub max_connections: usize,
    /// `SO_SNDBUF` of accepted sockets (the kernel default when `None`). Mostly a test hook: a
    /// small buffer makes write backpressure deterministic.
    pub send_buffer: Option<usize>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            max_connections: 10_000,
            send_buffer: None,
        }
    }
}

/// Per-connection state shared between the response body and the socket wrapper.
#[derive(Default)]
pub struct ConnCtx {
    /// The unit of the global budget of the response being written, and the deadline of that write.
    pending: Mutex<Option<(Option<ActiveHandle>, Instant)>>,
}

impl ConnCtx {
    /// A response exists and is about to be written: from the first byte, the write must finish
    /// by `deadline`; `handle` (if the request holds one) is released when the flush completes
    /// or the connection closes. Armed when the response is built, before hyper frames or
    /// flushes anything, so even a body larger than hyper's write buffer (which blocks in
    /// backpressure before the body is dropped) and replies without a handle are bounded.
    pub fn arm_write(&self, handle: Option<ActiveHandle>, deadline: Instant) {
        *self.pending.lock().unwrap_or_else(|p| p.into_inner()) = Some((handle, deadline));
    }

    /// The armed write deadline, if a response is being written.
    pub fn armed_deadline(&self) -> Option<Instant> {
        self.deadline()
    }

    fn deadline(&self) -> Option<Instant> {
        self.pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|(_, d)| *d)
    }

    fn release(&self) {
        drop(
            self.pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .take(),
        );
    }
}

/// The socket with write accounting.
struct Io {
    inner: TcpStream,
    ctx: Arc<ConnCtx>,
    sleep: Option<(Instant, Pin<Box<Sleep>>)>,
}

impl Io {
    /// Fail the write once the armed response's deadline has passed.
    fn check_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        match self.ctx.deadline() {
            None => self.sleep = None,
            Some(deadline) => {
                if self.sleep.as_ref().map(|(d, _)| *d) != Some(deadline) {
                    self.sleep = Some((deadline, Box::pin(tokio::time::sleep_until(deadline))));
                }
                if let Some((_, sleep)) = self.sleep.as_mut() {
                    if sleep.as_mut().poll(cx).is_ready() {
                        self.ctx.release();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "response write deadline exceeded",
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}

impl AsyncRead for Io {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_deadline(cx)?;
        let r = Pin::new(&mut self.inner).poll_flush(cx);
        if matches!(r, Poll::Ready(Ok(()))) {
            // Every framed byte has been handed to the socket: the response is written.
            self.ctx.release();
        }
        r
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for Io {
    fn drop(&mut self) {
        self.ctx.release();
    }
}

/// Resolves when the peer has closed (EOF/FIN) or reset the connection. Watches a duplicate of
/// the socket, so nothing is consumed. Close readiness (`EPOLLRDHUP` / `EV_EOF`) stays observable
/// while unread bytes are queued in front of the FIN, which a peek cannot see: a peek keeps
/// returning the same unread byte. Unread data is therefore not a close; the peek only
/// recognises an orderly EOF or an error, and is re-polled at a bounded rate.
async fn peer_closed(watcher: TcpStream) {
    let mut byte = [0u8; 1];
    loop {
        match watcher.ready(Interest::READABLE).await {
            Ok(ready) if ready.is_read_closed() || ready.is_error() => return,
            Ok(_) => {}
            Err(_) => return,
        }
        match watcher.peek(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
}

/// A running server: stop it gracefully, then force and join what is left.
pub struct Server {
    stop: watch::Sender<Option<Instant>>,
    task: JoinHandle<usize>,
    pub local_addr: std::net::SocketAddr,
}

impl Server {
    /// Stop accepting, let in-flight requests finish for at most `grace`, then abort and join the
    /// remaining connections. Returns how many connections had to be cut at the deadline.
    pub async fn shutdown(self, grace: Duration) -> usize {
        let _ = self.stop.send(Some(Instant::now() + grace));
        self.task.await.unwrap_or(0)
    }

    /// Wait for the accept loop to end by itself (listener failure).
    pub async fn wait(&mut self) {
        let _ = (&mut self.task).await;
    }
}

/// Serve `router` on `listener` with the default bounds.
pub fn spawn(listener: TcpListener, router: Router) -> Server {
    spawn_with(listener, router, TransportConfig::default())
}

/// Serve `router` on `listener`.
pub fn spawn_with(listener: TcpListener, router: Router, config: TransportConfig) -> Server {
    let local_addr = listener.local_addr().expect("listener address");
    let (stop, stop_rx) = watch::channel::<Option<Instant>>(None);
    let task = tokio::spawn(accept_loop(listener, router, stop_rx, config));
    Server {
        stop,
        task,
        local_addr,
    }
}

async fn accept_loop(
    listener: TcpListener,
    router: Router,
    mut stop: watch::Receiver<Option<Instant>>,
    config: TransportConfig,
) -> usize {
    let mut conns: JoinSet<()> = JoinSet::new();
    let slots = Arc::new(Semaphore::new(config.max_connections.max(1)));
    let deadline = 'accepting: loop {
        // A connection slot first: at the bound nothing is accepted.
        let permit = loop {
            tokio::select! {
                p = Arc::clone(&slots).acquire_owned() => break p.expect("slots stay open"),
                changed = stop.changed() => {
                    if changed.is_err() {
                        break 'accepting Instant::now();
                    }
                    if let Some(d) = *stop.borrow() {
                        break 'accepting d;
                    }
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        };
        loop {
            tokio::select! {
                accepted = listener.accept() => match accepted {
                    Ok((stream, peer)) => {
                        let _ = stream.set_nodelay(true);
                        if let Some(n) = config.send_buffer {
                            let _ = socket2::SockRef::from(&stream).set_send_buffer_size(n);
                        }
                        conns.spawn(serve_connection(
                            stream,
                            router.clone(),
                            stop.clone(),
                            config,
                            permit,
                        ));
                        debug!(%peer, "connection accepted");
                        break;
                    }
                    Err(e) => {
                        // EMFILE and friends: back off instead of spinning.
                        warn!(err = %e, "accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                },
                changed = stop.changed() => {
                    if changed.is_err() {
                        break 'accepting Instant::now();
                    }
                    if let Some(d) = *stop.borrow() {
                        break 'accepting d;
                    }
                }
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
            }
        }
    };
    drop(listener);
    // Graceful: connections were told through `stop`; wait for them until the deadline.
    let drained = tokio::time::timeout_at(deadline, async {
        while conns.join_next().await.is_some() {}
    })
    .await;
    if drained.is_ok() {
        return 0;
    }
    let cut = conns.len();
    conns.abort_all();
    while conns.join_next().await.is_some() {}
    cut
}

async fn serve_connection(
    stream: TcpStream,
    router: Router,
    mut stop: watch::Receiver<Option<Instant>>,
    config: TransportConfig,
    _slot: OwnedSemaphorePermit,
) {
    let ctx = Arc::new(ConnCtx::default());
    // A duplicate descriptor for the close watcher (the original belongs to hyper).
    let watcher = match stream
        .into_std()
        .and_then(|std| Ok((std.try_clone()?, std)))
        .and_then(|(dup, std)| {
            dup.set_nonblocking(true)?;
            Ok((TcpStream::from_std(dup)?, TcpStream::from_std(std)?))
        }) {
        Ok((watcher, stream)) => (watcher, stream),
        Err(e) => {
            warn!(err = %e, "cannot set up connection");
            return;
        }
    };
    let (watcher, stream) = watcher;
    let io = TokioIo::new(Io {
        inner: stream,
        ctx: Arc::clone(&ctx),
        sleep: None,
    });
    let service = TowerToHyperService::new(router.layer(Extension(Arc::clone(&ctx))));
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(config.header_read_timeout)
        .serve_connection(io, service);
    tokio::pin!(conn);
    let closed = peer_closed(watcher);
    tokio::pin!(closed);
    let mut graceful = false;
    loop {
        tokio::select! {
            res = conn.as_mut() => {
                if let Err(e) = res {
                    debug!(err = %e, "connection ended with an error");
                }
                return;
            }
            // The peer is gone: dropping the connection drops every in-flight request future.
            _ = &mut closed => {
                debug!("peer closed; cancelling the connection's requests");
                return;
            }
            changed = stop.changed(), if !graceful => {
                if changed.is_ok() && stop.borrow().is_some() {
                    graceful = true;
                    conn.as_mut().graceful_shutdown();
                }
            }
        }
    }
}
