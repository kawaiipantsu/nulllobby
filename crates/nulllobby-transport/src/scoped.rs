use crate::{BoxStream, ByteStream, ConnectionState, NetworkObserver};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::{OwnedSemaphorePermit, watch},
    task::JoinHandle,
};

pub struct ScopedStream {
    io: DuplexStream,
    task: JoinHandle<()>,
    _permits: Vec<OwnedSemaphorePermit>,
    pending: Option<OwnedSemaphorePermit>,
    observer: std::sync::Arc<dyn NetworkObserver>,
}
impl ScopedStream {
    pub fn wrap<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        mut stream: S,
        mut close: watch::Receiver<bool>,
        permits: Vec<OwnedSemaphorePermit>,
        pending: OwnedSemaphorePermit,
        observer: std::sync::Arc<dyn NetworkObserver>,
    ) -> BoxStream {
        let (io, mut adapter) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            if *close.borrow() {
                return;
            }
            tokio::select! { _ = tokio::io::copy_bidirectional(&mut stream, &mut adapter) => {}, _ = close.changed() => {} }
        });
        Box::new(Self {
            io,
            task,
            _permits: permits,
            pending: Some(pending),
            observer,
        })
    }
}
impl ByteStream for ScopedStream {
    fn connection_state(&mut self, state: ConnectionState) {
        self.observer.connection_state(state);
    }
    fn authenticated(&mut self) {
        self.pending.take();
    }
}
impl Drop for ScopedStream {
    fn drop(&mut self) {
        self.observer.connection_state(ConnectionState::Closing);
        self.task.abort();
    }
}
impl AsyncRead for ScopedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}
impl AsyncWrite for ScopedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModePolicy, TransportKind};
    use std::{sync::Arc, time::Duration};
    use tokio::{io::AsyncReadExt, sync::Semaphore};
    #[tokio::test]
    async fn close_before_subscription_cannot_admit_a_new_stream() {
        let (close, receiver) = watch::channel(false);
        drop(receiver);
        close.send_replace(true);
        let (stream, _other) = tokio::io::duplex(8);
        let pending = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let mut stream = ScopedStream::wrap(
            stream,
            close.subscribe(),
            vec![],
            pending,
            Arc::new(ModePolicy(TransportKind::Tor)),
        );
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }
}
