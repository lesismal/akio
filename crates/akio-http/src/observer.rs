//! A listener's response observer (ADR-158, akit A29): told of each response a request asked to
//! be observed for, on the thread that sends it, with a few words the request carried inline.

use std::{sync::Arc, time::Instant};

use crate::message::{Request, Response};

/// Told of the responses of the requests that asked for it ([`Context::set_observed`]): an
/// access log, request metrics, a trace, without a boxed closure per request
/// ([`Context::add_response_filter`] costs one).
///
/// Set once per listener, with [`HttpAcceptor::observer`] (HTTP/1.1 and HTTP/2). A request
/// opts in with [`Context::set_observed`], storing two words of its own inline (a metrics
/// slot, a log shard): no allocation and no reference count every thread shares.
///
/// [`on_response`](Self::on_response) runs once per observed request, when its response goes
/// to the connection, on the thread that sends it: the I/O thread for a response sent from the
/// handler, the thread that answers a detached or suspended request, the one that starts a
/// streamed response (with its head: the body is not sent yet). It sees the response as it
/// goes, after the response filters, the extra headers and any held head (ADR-128). It must
/// not block, as a response filter must not.
///
/// A request whose response is never sent (its context, [`Detached`] or [`Suspended`] dropped
/// unanswered, as a proxy may do once its client went) is not observed: register
/// [`Context::on_end`] for those. A response sent after its client went (a detached request
/// answered to a closed connection, its bytes dropped) is observed as it was sent.
///
/// [`Context::set_observed`]: crate::Context::set_observed
/// [`Context::add_response_filter`]: crate::Context::add_response_filter
/// [`Context::on_end`]: crate::Context::on_end
/// [`HttpAcceptor::observer`]: crate::HttpAcceptor::observer
/// [`Detached`]: crate::Detached
/// [`Suspended`]: crate::Suspended
pub trait ResponseObserver: Send + Sync + 'static {
    /// The response of an observed request is being sent, with the words the request set and
    /// the time it set them ([`Context::set_observed`](crate::Context::set_observed)).
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant);
}

/// A connection's own handle on its listener's observer: requests clone this one, whose count
/// only that connection's requests touch, rather than one every thread shares (rule 12). One
/// allocation per connection, made only when the listener has an observer.
struct PerConn(Arc<dyn ResponseObserver>);

impl ResponseObserver for PerConn {
    #[inline]
    fn on_response(&self, resp: &Response, req: &Request, words: [u64; 2], started: Instant) {
        self.0.on_response(resp, req, words, started);
    }
}

/// The handle a new connection of a listener with observer `obs` gives its requests.
pub(crate) fn per_conn(obs: &Arc<dyn ResponseObserver>) -> Arc<dyn ResponseObserver> {
    Arc::new(PerConn(obs.clone()))
}
