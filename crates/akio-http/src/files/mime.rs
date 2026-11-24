//! Content types for [`Files`](super::Files) (ADR-124): a table by file extension as Go's
//! `mime.TypeByExtension` has it (its built-in types, and on Unix the system's `mime.types`),
//! and Go's `http.DetectContentType` sniffing (the WHATWG MIME sniffing algorithm's subset).

use std::{
    collections::HashMap,
    fs,
    path::Path,
    sync::{Arc, OnceLock},
};

/// Content types by file extension; see [`Files::mime_types`](super::Files::mime_types).
/// Extensions compare case-insensitively.
#[derive(Clone, Debug, Default)]
pub struct MimeTypes {
    /// Lowercase extension, without its dot, to its type.
    map: HashMap<String, Arc<str>>,
}

/// Go's built-in table (`mime/type.go`, Go 1.27), without the dots.
const BUILTIN: &[(&str, &str)] = &[
    ("ai", "application/postscript"),
    ("apk", "application/vnd.android.package-archive"),
    ("apng", "image/apng"),
    ("avif", "image/avif"),
    ("bin", "application/octet-stream"),
    ("bmp", "image/bmp"),
    ("com", "application/octet-stream"),
    ("css", "text/css; charset=utf-8"),
    ("csv", "text/csv; charset=utf-8"),
    ("doc", "application/msword"),
    (
        "docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    ("ehtml", "text/html; charset=utf-8"),
    ("eml", "message/rfc822"),
    ("eps", "application/postscript"),
    ("exe", "application/octet-stream"),
    ("flac", "audio/flac"),
    ("gif", "image/gif"),
    ("gz", "application/gzip"),
    ("htm", "text/html; charset=utf-8"),
    ("html", "text/html; charset=utf-8"),
    ("ico", "image/vnd.microsoft.icon"),
    ("ics", "text/calendar; charset=utf-8"),
    ("jfif", "image/jpeg"),
    ("jpeg", "image/jpeg"),
    ("jpg", "image/jpeg"),
    ("js", "text/javascript; charset=utf-8"),
    ("json", "application/json"),
    ("m4a", "audio/mp4"),
    ("mjs", "text/javascript; charset=utf-8"),
    ("mp3", "audio/mpeg"),
    ("mp4", "video/mp4"),
    ("oga", "audio/ogg"),
    ("ogg", "audio/ogg"),
    ("ogv", "video/ogg"),
    ("opus", "audio/ogg"),
    ("pdf", "application/pdf"),
    ("pjp", "image/jpeg"),
    ("pjpeg", "image/jpeg"),
    ("png", "image/png"),
    ("ppt", "application/vnd.ms-powerpoint"),
    (
        "pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    ("ps", "application/postscript"),
    ("rdf", "application/rdf+xml"),
    ("rtf", "application/rtf"),
    ("shtml", "text/html; charset=utf-8"),
    ("svg", "image/svg+xml"),
    ("text", "text/plain; charset=utf-8"),
    ("tif", "image/tiff"),
    ("tiff", "image/tiff"),
    ("txt", "text/plain; charset=utf-8"),
    ("vtt", "text/vtt; charset=utf-8"),
    ("wasm", "application/wasm"),
    ("wav", "audio/wav"),
    ("weba", "audio/webm"),
    ("webm", "video/webm"),
    ("webp", "image/webp"),
    ("xbl", "text/xml; charset=utf-8"),
    ("xbm", "image/x-xbitmap"),
    ("xht", "application/xhtml+xml"),
    ("xhtml", "application/xhtml+xml"),
    ("xls", "application/vnd.ms-excel"),
    (
        "xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    ("xml", "text/xml; charset=utf-8"),
    ("xsl", "text/xml; charset=utf-8"),
    ("zip", "application/zip"),
];

/// The shared-mime-info databases Go reads first, in order; the first that opens is used alone.
const GLOBS: &[&str] = &["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"];
/// Without one, the `mime.types` files Go reads, each over the last.
const TYPE_FILES: &[&str] = &[
    "/etc/mime.types",
    "/etc/apache2/mime.types",
    "/etc/apache/mime.types",
    "/etc/httpd/conf/mime.types",
];

/// The most lines read from one system file, and the most extensions kept: a bound on what a
/// file the operator did not write can make the table hold.
const MAX_LINES: usize = 1 << 16;
const MAX_TYPES: usize = 1 << 14;

impl MimeTypes {
    /// No types.
    pub fn empty() -> MimeTypes {
        MimeTypes::default()
    }

    /// Go's built-in table (`mime.TypeByExtension` without the system's files): `.html`,
    /// `.css`, `.js` and `.txt` with `charset=utf-8`, `.xml` as `text/xml; charset=utf-8`,
    /// `.avif`, `.webp`, `.wasm` and 60 more.
    pub fn builtin() -> MimeTypes {
        let mut t = MimeTypes::empty();
        for (ext, ty) in BUILTIN {
            t.map.insert((*ext).to_owned(), Arc::from(*ty));
        }
        t
    }

    /// The table Go's `mime` package has on Unix: [`builtin`](MimeTypes::builtin), then the
    /// system's shared-mime-info database (`/usr/share/mime/globs2`, adding extensions the
    /// built-in table lacks), or without one the `mime.types` files (`/etc/mime.types`, ...,
    /// each over the last, the built-in types included). A `text/` type without a charset gets
    /// `charset=utf-8`. Read once per process and cached; it reads files, so call it off the
    /// I/O threads, where the configuration is built.
    pub fn system() -> Arc<MimeTypes> {
        static CACHE: OnceLock<Arc<MimeTypes>> = OnceLock::new();
        CACHE
            .get_or_init(|| {
                let mut t = MimeTypes::builtin();
                t.load_system(GLOBS, TYPE_FILES);
                Arc::new(t)
            })
            .clone()
    }

    /// [`system`](MimeTypes::system)'s loading, from the files given.
    fn load_system(&mut self, globs: &[&str], type_files: &[&str]) {
        for g in globs {
            if let Ok(text) = fs::read_to_string(g) {
                self.load_globs(&text);
                return;
            }
        }
        for f in type_files {
            if let Ok(text) = fs::read_to_string(f) {
                self.load_mime_types(&text);
            }
        }
    }

    /// A shared-mime-info `globs2` file (`weight:type:*.ext`, by weight): an extension takes the
    /// first type given for it, and keeps a built-in one.
    fn load_globs(&mut self, text: &str) {
        for line in text.lines().take(MAX_LINES) {
            let mut f = line.split(':');
            let (Some(weight), Some(ty), Some(glob)) = (f.next(), f.next(), f.next()) else {
                continue;
            };
            if weight.is_empty() || weight.starts_with('#') || glob.len() < 3 {
                continue;
            }
            let Some(ext) = glob.strip_prefix("*.") else {
                continue;
            };
            if ext.contains(['?', '*', '[']) || self.get(ext).is_some() {
                continue;
            }
            self.insert(ext, ty);
        }
    }

    /// A `mime.types` file (`type ext ext ...`, `#` comments): each extension takes its type,
    /// over a type given before (a built-in one included).
    fn load_mime_types(&mut self, text: &str) {
        for line in text.lines().take(MAX_LINES) {
            let mut f = line.split_whitespace();
            let Some(ty) = f.next() else { continue };
            if ty.starts_with('#') {
                continue;
            }
            for ext in f {
                if ext.starts_with('#') {
                    break;
                }
                self.insert(ext, ty);
            }
        }
    }

    /// Sets the type of files with extension `ext` (without its dot), as Go's
    /// `mime.AddExtensionType` does: a `text/` type without a charset gets `charset=utf-8`. A
    /// type without a `/`, or an empty extension, is left out; so is a new extension once the
    /// table holds 16384.
    pub fn insert(&mut self, ext: &str, content_type: &str) {
        let ext = ext.strip_prefix('.').unwrap_or(ext);
        let ty = content_type.trim();
        let Some((main, _)) = ty.split_once('/') else {
            return;
        };
        if ext.is_empty() || main.is_empty() || ty.contains(['\r', '\n']) {
            return;
        }
        let key = ext.to_ascii_lowercase();
        if self.map.len() >= MAX_TYPES && !self.map.contains_key(&key) {
            return;
        }
        let mut ty = ty.to_owned();
        if main.eq_ignore_ascii_case("text") && !ty.to_ascii_lowercase().contains("charset=") {
            ty.push_str("; charset=utf-8");
        }
        self.map.insert(key, Arc::from(ty));
    }

    /// The type of files with extension `ext` (without its dot).
    pub fn get(&self, ext: &str) -> Option<&str> {
        self.lookup(ext).map(|t| &**t)
    }

    fn lookup(&self, ext: &str) -> Option<&Arc<str>> {
        match self.map.get(ext) {
            Some(t) => Some(t),
            None if ext.bytes().any(|b| b.is_ascii_uppercase()) => {
                self.map.get(&ext.to_ascii_lowercase())
            }
            None => None,
        }
    }

    /// The type of the file at `path`, by its extension.
    pub(crate) fn for_path(&self, path: &Path) -> Option<Arc<str>> {
        let ext = path.extension()?.to_str()?;
        self.lookup(ext).cloned()
    }

    /// How many extensions the table has.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table has none.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// How many bytes [`sniff`] looks at.
pub const SNIFF_LEN: usize = 512;

/// The content type of `data`, the first bytes of a file, as Go's `http.DetectContentType`
/// works it out (the WHATWG MIME sniffing algorithm's subset Go implements): HTML by its first
/// tag, XML, PDF, PostScript, images, audio and video, fonts, archives, WebAssembly, then
/// `text/plain; charset=utf-8` for bytes with no binary control characters, else
/// `application/octet-stream`. At most the first 512 bytes are looked at.
pub fn sniff(data: &[u8]) -> &'static str {
    let data = data.get(..SNIFF_LEN).unwrap_or(data);
    let ws = data
        .iter()
        .position(|b| !matches!(b, b'\t' | b'\n' | 0x0c | b'\r' | b' '))
        .unwrap_or(data.len());
    let text = data.get(ws..).unwrap_or(&[]);
    for tag in HTML {
        if html(text, tag) {
            return "text/html; charset=utf-8";
        }
    }
    if text.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    for (pat, mask, ct) in MASKED_HEAD {
        if masked(data, pat, mask) {
            return ct;
        }
    }
    for (sig, ct) in EXACT {
        if data.starts_with(sig) {
            return ct;
        }
    }
    for (pat, mask, ct) in MASKED {
        if masked(data, pat, mask) {
            return ct;
        }
    }
    if mp4(data) {
        return "video/mp4";
    }
    for (sig, ct) in EXACT_TAIL {
        if data.starts_with(sig) {
            return ct;
        }
    }
    if masked(
        data,
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0LP",
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xFF\xFF",
    ) {
        return "application/vnd.ms-fontobject";
    }
    for (sig, ct) in FONTS_AND_ARCHIVES {
        if data.starts_with(sig) {
            return ct;
        }
    }
    let binary = text.iter().any(|&b| {
        b <= 0x08 || b == 0x0b || (0x0e..=0x1a).contains(&b) || (0x1c..=0x1f).contains(&b)
    });
    if binary {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
}

/// The tags that make a document HTML, compared case-insensitively and followed by a space or
/// `>`.
const HTML: &[&[u8]] = &[
    b"<!DOCTYPE HTML",
    b"<HTML",
    b"<HEAD",
    b"<SCRIPT",
    b"<IFRAME",
    b"<H1",
    b"<DIV",
    b"<FONT",
    b"<TABLE",
    b"<A",
    b"<STYLE",
    b"<TITLE",
    b"<B",
    b"<BODY",
    b"<BR",
    b"<P",
    b"<!--",
];

fn html(data: &[u8], tag: &[u8]) -> bool {
    let (Some(head), Some(&end)) = (data.get(..tag.len()), data.get(tag.len())) else {
        return false;
    };
    let same = head.iter().zip(tag).all(|(&d, &t)| {
        if t.is_ascii_uppercase() {
            d & 0xDF == t
        } else {
            d == t
        }
    });
    same && matches!(end, b' ' | b'>')
}

fn masked(data: &[u8], pat: &[u8], mask: &[u8]) -> bool {
    pat.len() == mask.len()
        && data.len() >= pat.len()
        && data
            .iter()
            .zip(pat)
            .zip(mask)
            .all(|((d, p), m)| d & m == *p)
}

/// Before the images: PDF, PostScript and the byte order marks.
const MASKED_HEAD: &[(&[u8], &[u8], &str)] = &[
    (b"%PDF-", b"\xFF\xFF\xFF\xFF\xFF", "application/pdf"),
    (
        b"%!PS-Adobe-",
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "application/postscript",
    ),
    (
        b"\xFE\xFF\0\0",
        b"\xFF\xFF\0\0",
        "text/plain; charset=utf-16be",
    ),
    (
        b"\xFF\xFE\0\0",
        b"\xFF\xFF\0\0",
        "text/plain; charset=utf-16le",
    ),
    (
        b"\xEF\xBB\xBF\0",
        b"\xFF\xFF\xFF\0",
        "text/plain; charset=utf-8",
    ),
];

const EXACT: &[(&[u8], &str)] = &[
    (b"\0\0\x01\0", "image/x-icon"),
    (b"\0\0\x02\0", "image/x-icon"),
    (b"BM", "image/bmp"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
];

const MASKED: &[(&[u8], &[u8], &str)] = &[
    (
        b"RIFF\0\0\0\0WEBPVP",
        b"\xFF\xFF\xFF\xFF\0\0\0\0\xFF\xFF\xFF\xFF\xFF\xFF",
        "image/webp",
    ),
    (
        b"\x89PNG\x0D\x0A\x1A\x0A",
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "image/png",
    ),
    (b"\xFF\xD8\xFF", b"\xFF\xFF\xFF", "image/jpeg"),
    (
        b"FORM\0\0\0\0AIFF",
        b"\xFF\xFF\xFF\xFF\0\0\0\0\xFF\xFF\xFF\xFF",
        "audio/aiff",
    ),
    (b"ID3", b"\xFF\xFF\xFF", "audio/mpeg"),
    (b"OggS\0", b"\xFF\xFF\xFF\xFF\xFF", "application/ogg"),
    (
        b"MThd\0\0\0\x06",
        b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
        "audio/midi",
    ),
    (
        b"RIFF\0\0\0\0AVI ",
        b"\xFF\xFF\xFF\xFF\0\0\0\0\xFF\xFF\xFF\xFF",
        "video/avi",
    ),
    (
        b"RIFF\0\0\0\0WAVE",
        b"\xFF\xFF\xFF\xFF\0\0\0\0\xFF\xFF\xFF\xFF",
        "audio/wave",
    ),
];

const EXACT_TAIL: &[(&[u8], &str)] = &[(b"\x1A\x45\xDF\xA3", "video/webm")];

const FONTS_AND_ARCHIVES: &[(&[u8], &str)] = &[
    (b"\0\x01\0\0", "font/ttf"),
    (b"OTTO", "font/otf"),
    (b"ttcf", "font/collection"),
    (b"wOFF", "font/woff"),
    (b"wOF2", "font/woff2"),
    (b"\x1F\x8B\x08", "application/x-gzip"),
    (b"PK\x03\x04", "application/zip"),
    (b"Rar!\x1A\x07\0", "application/x-rar-compressed"),
    (b"Rar!\x1A\x07\x01\0", "application/x-rar-compressed"),
    (b"\0asm", "application/wasm"),
];

/// An ISO BMFF `ftyp` box naming an `mp4` brand (the major brand, or a compatible one).
fn mp4(data: &[u8]) -> bool {
    let Some(size) = data.get(..4) else {
        return false;
    };
    let size = u32::from_be_bytes([size[0], size[1], size[2], size[3]]) as usize;
    if data.len() < 12 || data.len() < size || size % 4 != 0 || data.get(4..8) != Some(b"ftyp") {
        return false;
    }
    (8..size)
        .step_by(4)
        .filter(|&st| st != 12)
        .any(|st| data.get(st..st + 3) == Some(b"mp4"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_types() {
        let t = MimeTypes::builtin();
        assert_eq!(t.get("xml"), Some("text/xml; charset=utf-8"));
        assert_eq!(t.get("AVIF"), Some("image/avif"));
        assert_eq!(t.get("html"), Some("text/html; charset=utf-8"));
        assert_eq!(t.get("nope"), None);
        assert_eq!(t.len(), BUILTIN.len());
    }

    #[test]
    fn system_files_as_go_reads_them() {
        let dir = std::env::temp_dir().join(format!("akio-mime-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let types = dir.join("mime.types");
        fs::write(
            &types,
            "# comment\ntext/x-foo foo FOO2 # trailing\napplication/x-bar bar\nimage/x-png png\n",
        )
        .unwrap();
        let globs = dir.join("globs2");
        let missing = dir.join("missing");
        // No globs2: mime.types, over the built-in types.
        let mut t = MimeTypes::builtin();
        t.load_system(
            &[missing.to_str().unwrap()],
            &[types.to_str().unwrap(), missing.to_str().unwrap()],
        );
        assert_eq!(t.get("foo"), Some("text/x-foo; charset=utf-8"));
        assert_eq!(t.get("foo2"), Some("text/x-foo; charset=utf-8"));
        assert_eq!(t.get("bar"), Some("application/x-bar"));
        assert_eq!(t.get("trailing"), None);
        assert_eq!(t.get("png"), Some("image/x-png"));
        // A globs2 file is read alone, first type wins, built-in types kept.
        fs::write(
            &globs,
            "# weight\n50:text/x-baz:*.baz\n40:text/plain:*.baz\n50:image/x-png:*.png\n50:x/y:*.[ch]\n",
        )
        .unwrap();
        let mut t = MimeTypes::builtin();
        t.load_system(&[globs.to_str().unwrap()], &[types.to_str().unwrap()]);
        assert_eq!(t.get("baz"), Some("text/x-baz; charset=utf-8"));
        assert_eq!(t.get("png"), Some("image/png"));
        assert_eq!(t.get("foo"), None);
        assert_eq!(t.get("[ch]"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sniffing_as_go() {
        // Go's net/http sniff_test.go cases.
        let cases: &[(&[u8], &str)] = &[
            (b"", "text/plain; charset=utf-8"),
            (b"\x01\x02\x03", "application/octet-stream"),
            (b"\x00", "application/octet-stream"),
            (b"Hello, world!", "text/plain; charset=utf-8"),
            (b"<!DOCTYPE HTML>...", "text/html; charset=utf-8"),
            (b"   <!doctype html>...", "text/html; charset=utf-8"),
            (b"<html", "text/plain; charset=utf-8"),
            (
                b"<HtMl><bOdY>blah blah blah</body></html>",
                "text/html; charset=utf-8",
            ),
            (b"\n<?xml!", "text/xml; charset=utf-8"),
            (b"%PDF-1.4", "application/pdf"),
            (b"%!PS-Adobe-3.0", "application/postscript"),
            (b"\xFE\xFF\x00\x00", "text/plain; charset=utf-16be"),
            (b"\xEF\xBB\xBFhi", "text/plain; charset=utf-8"),
            (b"GIF87a", "image/gif"),
            (b"GIF89a...", "image/gif"),
            (b"\x89PNG\x0D\x0A\x1A\x0A", "image/png"),
            (b"\xFF\xD8\xFF", "image/jpeg"),
            (b"RIFF\x00\x00\x00\x00WEBPVP8 ", "image/webp"),
            (b"BMxx", "image/bmp"),
            (b"ID3\x03", "audio/mpeg"),
            (b"OggS\x00", "application/ogg"),
            (b"MThd\x00\x00\x00\x06\x00\x01", "audio/midi"),
            (b"RIFF,O\n\x00WAVEfmt \x10", "audio/wave"),
            (
                b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom<\x06t\xbfmdat",
                "video/mp4",
            ),
            (b"\x1A\x45\xDF\xA3\x01\x00", "video/webm"),
            (b"wOFF", "font/woff"),
            (b"\x1F\x8B\x08\x08", "application/x-gzip"),
            (b"PK\x03\x04\x0A\x00", "application/zip"),
            (b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
            (b"\x00\x61\x73\x6D\x01\x00", "application/wasm"),
        ];
        for (data, want) in cases {
            assert_eq!(sniff(data), *want, "{:?}", String::from_utf8_lossy(data));
        }
        // Only the first 512 bytes count.
        let mut long = vec![b'a'; 512];
        long.push(0);
        assert_eq!(sniff(&long), "text/plain; charset=utf-8");
    }
}
