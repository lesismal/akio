//! One only-http [`Service`] for every HTTP playback format: requests ending in `.flv` go to
//! [`HttpFlv`] (HTTP-FLV, or WS-FLV on a WebSocket upgrade), `.m3u8` and `.ts` to [`Hls`].
//!
//! ```no_run
//! use only::{Engine, Listener};
//! use only_http::{Router, serve};
//! use only_media::{Hub, hls::{Hls, HlsConfig}, http::MediaHttp, httpflv::{HttpFlv, HttpFlvConfig}};
//!
//! let hub = Hub::default();
//! let media = MediaHttp::new()
//!     .flv(HttpFlv::new(hub.clone(), HttpFlvConfig::default()))
//!     .hls(Hls::new(hub.clone(), HlsConfig::default()));
//! // GET /live/s.flv, ws://.../live/s.flv, GET /live/s/index.m3u8
//! let app = Router::new().get("/*path", media);
//! let engine = Engine::builder()
//!     .listen(Listener::tcp("127.0.0.1:8080".parse().unwrap()).serve(serve(app)))
//!     .build()
//!     .unwrap();
//! ```

use only_http::{Context, Service};

use crate::{hls::Hls, httpflv::HttpFlv};

/// Dispatches HTTP playback requests by extension.
#[derive(Debug, Clone, Default)]
pub struct MediaHttp {
    flv: Option<HttpFlv>,
    hls: Option<Hls>,
}

impl MediaHttp {
    /// A service with no format enabled (everything is 404).
    pub fn new() -> MediaHttp {
        MediaHttp::default()
    }

    /// Serves `.flv` requests with `flv`.
    #[must_use]
    pub fn flv(mut self, flv: HttpFlv) -> MediaHttp {
        self.flv = Some(flv);
        self
    }

    /// Serves `.m3u8` and `.ts` requests with `hls`.
    #[must_use]
    pub fn hls(mut self, hls: Hls) -> MediaHttp {
        self.hls = Some(hls);
        self
    }
}

impl Service for MediaHttp {
    fn call(&self, ctx: &mut Context) {
        let p = ctx.path();
        if p.ends_with(".flv") {
            if let Some(f) = &self.flv {
                return f.call(ctx);
            }
        } else if p.ends_with(".m3u8") || p.ends_with(".ts") {
            if let Some(h) = &self.hls {
                return h.call(ctx);
            }
        }
        ctx.text(404, "not found");
    }
}
