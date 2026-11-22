//! Dictionaries (RFC 8878 section 5): raw content, or the format `zstd --train` writes (magic
//! number, Dictionary_ID, entropy tables, repeat offsets, content).

use std::sync::Arc;

use crate::Error;
use crate::decode::DictTables;
use crate::fse;
use crate::huffman;
use crate::tables::{LL_MAX_LOG, MAX_LL, MAX_ML, MAX_OF, ML_MAX_LOG, OF_MAX_LOG};

/// Magic number of a dictionary in the trained format.
const DICT_MAGIC: u32 = 0xEC30_A437;

/// A Zstandard dictionary, for [`compress_with_dictionary`](crate::compress_with_dictionary),
/// [`decompress_with_dictionary`](crate::decompress_with_dictionary) and the streaming
/// [`Compressor`](crate::Compressor) / [`Decompressor`](crate::Decompressor).
///
/// Either *raw content* (any bytes: earlier data that matches may refer back into, as if it
/// preceded the input; Dictionary_ID 0, so frames do not name it) or the *trained format* of
/// `zstd --train` (RFC 8878 section 5): a Dictionary_ID that frames carry, entropy tables that
/// the first block may reuse instead of describing its own, the starting repeat offsets, and
/// the content. Cloning is cheap (the parsed dictionary is shared).
///
/// ```
/// use akio_zstd::{Dictionary, Level, compress_with_dictionary, decompress_with_dictionary};
///
/// let dict = Dictionary::raw(b"{\"name\": \"\", \"email\": \"\", \"roles\": [\"admin\"]}");
/// let msg = b"{\"name\": \"ada\", \"email\": \"ada@example.com\", \"roles\": [\"admin\"]}";
/// let packed = compress_with_dictionary(Level::DEFAULT, msg, &dict);
/// assert!(packed.len() < akio_zstd::compress(Level::DEFAULT, msg).len());
/// assert_eq!(decompress_with_dictionary(&packed, 1 << 10, &dict).unwrap(), msg);
/// ```
#[derive(Clone)]
pub struct Dictionary(pub(crate) Arc<Inner>);

pub(crate) struct Inner {
    pub(crate) id: u32,
    pub(crate) content: Vec<u8>,
    pub(crate) entropy: Option<Entropy>,
}

/// The entropy tables of a trained dictionary, for both sides.
pub(crate) struct Entropy {
    pub(crate) dtables: DictTables,
    /// Huffman weights of every symbol (the implied last one included).
    pub(crate) huf_weights: Vec<u8>,
    /// Normalized counts and accuracy logs of the literal length, offset and match length codes.
    pub(crate) norms: [(Vec<i16>, u32); 3],
    pub(crate) reps: [u32; 3],
}

impl std::fmt::Debug for Dictionary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dictionary")
            .field("id", &self.0.id)
            .field("content_len", &self.0.content.len())
            .field("entropy", &self.0.entropy.is_some())
            .finish()
    }
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

impl Dictionary {
    /// A dictionary from its bytes: the trained format when they start with its magic number
    /// (`37 A4 30 EC`), raw content otherwise (as libzstd's `ZSTD_dct_auto`).
    ///
    /// Fails with [`Error::BadDictionary`] when a trained dictionary's tables are invalid or
    /// its repeat offsets are zero or larger than its content.
    pub fn new(bytes: &[u8]) -> Result<Dictionary, Error> {
        if le32(bytes, 0) == Some(DICT_MAGIC) {
            Self::trained(bytes)
        } else {
            Ok(Self::raw(bytes))
        }
    }

    /// `bytes` as raw content (Dictionary_ID 0), whatever they start with.
    pub fn raw(bytes: &[u8]) -> Dictionary {
        Dictionary(Arc::new(Inner {
            id: 0,
            content: bytes.to_vec(),
            entropy: None,
        }))
    }

    fn trained(b: &[u8]) -> Result<Dictionary, Error> {
        let bad = Error::BadDictionary;
        let id = le32(b, 4).ok_or(bad)?;
        let mut p = 8;
        let (weights, nsym, hsize) = huffman::read_weights(b.get(p..).ok_or(bad)?).ok_or(bad)?;
        let huf_desc = &b[p..p + hsize];
        p += hsize;
        // Offsets, match lengths, literal lengths, in that order.
        let mut read = |max: usize, max_log: u32| -> Result<(Vec<i16>, u32), Error> {
            let mut norm = [0i16; 256];
            let (max_sv, log, size) =
                fse::read_ncount(b.get(p..).ok_or(bad)?, max, &mut norm).ok_or(bad)?;
            if log > max_log {
                return Err(bad);
            }
            p += size;
            Ok((norm[..=max_sv].to_vec(), log))
        };
        let of = read(MAX_OF, OF_MAX_LOG)?;
        let ml = read(MAX_ML, ML_MAX_LOG)?;
        let ll = read(MAX_LL, LL_MAX_LOG)?;
        let mut reps = [0u32; 3];
        for r in &mut reps {
            *r = le32(b, p).ok_or(bad)?;
            p += 4;
        }
        let content = b[p..].to_vec();
        if reps.iter().any(|&r| r == 0 || r as usize > content.len()) {
            return Err(bad);
        }
        let dtables = DictTables::new(
            huf_desc,
            [(&ll.0, ll.1), (&of.0, of.1), (&ml.0, ml.1)],
            reps,
        )
        .ok_or(bad)?;
        Ok(Dictionary(Arc::new(Inner {
            id,
            content,
            entropy: Some(Entropy {
                dtables,
                huf_weights: weights[..nsym].to_vec(),
                norms: [ll, of, ml],
                reps,
            }),
        })))
    }

    /// The Dictionary_ID frames compressed with this dictionary carry (0: none, as for raw
    /// content).
    pub fn id(&self) -> u32 {
        self.0.id
    }

    /// The content that matches may refer back into.
    pub fn content(&self) -> &[u8] {
        &self.0.content
    }

    /// Whether the dictionary is in the trained format (with entropy tables).
    pub fn is_trained(&self) -> bool {
        self.0.entropy.is_some()
    }
}
