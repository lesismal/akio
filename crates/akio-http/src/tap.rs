//! Body taps (ADR-116): what a response filter sets on the head of a streamed response to see its
//! body as it is sent, a cache keeping a copy, say, without holding the response back.

use std::sync::{Arc, Mutex, PoisonError};

/// How a tapped body ended, as [`BodyTap::end`] hears it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TapEnd {
    /// [`BodyStream::finish`](crate::BodyStream::finish): every byte was written.
    Finished,
    /// [`BodyStream::finish_with_trailers`](crate::BodyStream::finish_with_trailers): every byte
    /// was written, and trailer fields followed.
    Trailers,
    /// The body did not end: the stream was dropped unfinished, or a write failed (the client
    /// went, or fell too far behind), or the stream never started.
    Cut,
}

/// Sees a streamed response's body as it is sent: set by a response filter on the head of a
/// streamed response with [`Response::tap_body`](crate::Response::tap_body) (ADR-116).
///
/// [`data`](BodyTap::data) gets each piece of the body as it goes to the connection, after any
/// content coding ([`Response::set_stream_coding`](crate::Response::set_stream_coding)) and
/// without the transport's framing (chunk sizes, HTTP/2 frames): the bytes of the representation
/// the head describes. A write that fails is not seen. [`end`](BodyTap::end) is called once,
/// last. The calls come from whatever thread writes the stream, one at a time; they should be
/// quick, as the writer waits for them.
pub trait BodyTap: Send + 'static {
    /// A piece of the body, valid for this call only.
    fn data(&mut self, data: &[u8]);

    /// The body ended, as `end` says.
    fn end(&mut self, end: TapEnd);
}

/// A tap as a [`Response`](crate::Response) carries it: shared, so the response stays `Clone`
/// (a clone of the head carries the same tap, which only the stream that takes it uses).
#[derive(Clone)]
pub(crate) struct TapSlot(Arc<Mutex<Option<Box<dyn BodyTap>>>>);

impl std::fmt::Debug for TapSlot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TapSlot")
    }
}

impl TapSlot {
    pub(crate) fn new(tap: Box<dyn BodyTap>) -> TapSlot {
        TapSlot(Arc::new(Mutex::new(Some(tap))))
    }

    /// The tap, for the stream; `None` once a stream took it.
    pub(crate) fn take(&self) -> Option<StreamTap> {
        let tap = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        Some(StreamTap {
            state: Mutex::new(TapState {
                tap: Some(tap),
                failed: false,
            }),
        })
    }
}

/// A stream's tap: told each write, and how the stream ended; told [`TapEnd::Cut`] when dropped
/// before it was told anything else.
pub(crate) struct StreamTap {
    /// The lock keeps a stream written from several threads seen in the order it was written.
    state: Mutex<TapState>,
}

struct TapState {
    /// Taken when told how the body ended.
    tap: Option<Box<dyn BodyTap>>,
    /// A write failed: the body will not be whole.
    failed: bool,
}

impl StreamTap {
    /// `data` was written, with `ok` saying whether the write went through.
    pub(crate) fn wrote(&self, data: &[u8], ok: bool) {
        let mut s = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !ok {
            s.failed = true;
        } else if !s.failed && !data.is_empty() {
            if let Some(t) = s.tap.as_mut() {
                t.data(data);
            }
        }
    }

    /// The stream ended as `end` says (or was cut, if a write failed).
    pub(crate) fn end(self, end: TapEnd) {
        let mut s = self
            .state
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner);
        let end = if s.failed { TapEnd::Cut } else { end };
        if let Some(mut t) = s.tap.take() {
            t.end(end);
        }
    }
}

impl Drop for TapState {
    fn drop(&mut self) {
        if let Some(mut t) = self.tap.take() {
            t.end(TapEnd::Cut);
        }
    }
}
