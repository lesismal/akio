//! Companion of the book's "Migrating from tokio" guide: bridging `akio`'s callbacks with code
//! that lives elsewhere (another runtime, a worker thread). No async runtime is needed here; a
//! ten-line `block_on` stands in for one, and the same calls work from a tokio task.
//!
//! `cargo run -p akio-http --example guide-bridge`

use std::{
    future::Future,
    pin::pin,
    sync::{Arc, mpsc},
    task::{Context as TaskCx, Poll, Wake, Waker},
    thread,
};

use akio::{Engine, Listener};
use akio_http::{
    Context, Detached, Response, Router,
    client::{Client, ClientRequest},
    serve,
};

// ANCHOR: worker
/// A job for code outside `akio`: the request's `Detached` handle travels with it.
struct Job {
    name: String,
    reply: Detached,
}

/// Starts a worker (it could be a tokio runtime: `rx` would be a tokio channel and the loop a
/// task). `Detached::respond` is callable from any thread.
fn start_worker() -> mpsc::Sender<Job> {
    let (tx, rx) = mpsc::channel::<Job>();
    thread::spawn(move || {
        for job in rx {
            let body = format!("hello {}, from the worker\n", job.name);
            job.reply.respond(Response::text(200, body));
        }
    });
    tx
}
// ANCHOR_END: worker

// ANCHOR: block_on
/// A minimal executor: parks the thread until the future's waker fires.
fn block_on<F: Future>(fut: F) -> F::Output {
    struct Unpark(thread::Thread);
    impl Wake for Unpark {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(Unpark(thread::current())));
    let mut cx = TaskCx::from_waker(&waker);
    let mut fut = pin!(fut);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        thread::park();
    }
}
// ANCHOR_END: block_on

fn main() -> std::io::Result<()> {
    // ANCHOR: handoff
    let jobs = start_worker();
    let app = Router::new().get("/hello/:name", move |ctx: &mut Context| {
        let name = ctx.param("name").unwrap_or("?").to_owned();
        let Some(reply) = ctx.detach() else { return };
        if let Err(mpsc::SendError(job)) = jobs.send(Job { name, reply }) {
            job.reply.respond(Response::text(503, "worker gone\n"));
        }
    });
    // ANCHOR_END: handoff
    let engine = Arc::new(
        Engine::builder()
            .listen(Listener::tcp("127.0.0.1:0".parse().unwrap()).serve(serve(app)))
            .client_threads(1)
            .build()?,
    );
    engine.start()?;
    let url = format!("http://{}/hello/tokio", engine.local_addrs()[0]);

    // ANCHOR: await
    // `ResponseFuture` is a `Future`: `.await` it inside any executor (tokio included).
    let client = Client::new(engine.clone());
    let resp = block_on(async { client.send(ClientRequest::get(&url)).await });
    // ANCHOR_END: await
    print!("{}", String::from_utf8_lossy(&resp.expect("response").body));

    engine.shutdown();
    engine.wait();
    Ok(())
}
