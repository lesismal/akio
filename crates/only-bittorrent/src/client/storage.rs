//! Where a torrent's data lives: the [`Storage`] trait (reads and writes by offset in the
//! torrent's concatenated data), files below a directory ([`FileStorage`]) or memory
//! ([`MemoryStorage`]). The client calls storage only from the logical pool, never from an
//! I/O thread.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::SystemTime;

use crate::metainfo::Info;

/// A torrent's data, addressed by offset in its concatenated files.
pub trait Storage: Send + Sync + 'static {
    /// Reads `len` bytes at `offset`; missing data is an error.
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>>;
    /// Writes `data` at `offset`.
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()>;
    /// Whether any data may be present already (worth hash-checking when the torrent starts).
    fn may_have_data(&self) -> bool {
        true
    }
    /// The size and modification time of each of the torrent's files, in [`Info::files`]
    /// order (`None` for a file that does not exist, and for padding), so fast-resume data can
    /// be checked against what is on disk (ADR-033). The default, `None`, is storage without
    /// files: resume data is then trusted if [`may_have_data`](Self::may_have_data), and
    /// dropped if not.
    fn file_stamps(&self) -> Option<Vec<Option<FileStamp>>> {
        None
    }
}

/// A file's size and modification time, as fast-resume data records them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileStamp {
    /// Size in bytes.
    pub size: u64,
    /// Last modification (the Unix epoch where the platform has none).
    pub mtime: SystemTime,
}

impl FileStamp {
    /// A file of `size` bytes modified at `mtime`.
    pub fn new(size: u64, mtime: SystemTime) -> FileStamp {
        FileStamp { size, mtime }
    }

    /// The stamp of the file at `path` (`None` if there is none).
    pub fn of(path: &Path) -> Option<FileStamp> {
        let m = std::fs::metadata(path).ok()?;
        m.is_file().then(|| FileStamp {
            size: m.len(),
            mtime: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
        })
    }
}

/// Files below a directory: `dir/name` for a single-file torrent, `dir/name/...` for a
/// multi-file one. Files are created on first write; padding files are never written.
#[derive(Debug)]
pub struct FileStorage {
    info: Info,
    paths: Vec<PathBuf>,
    files: Vec<Mutex<Option<File>>>,
    /// Empty files were created (they get no write of their own).
    empty_done: std::sync::atomic::AtomicBool,
}

impl FileStorage {
    /// Storage for `info` below `dir`.
    pub fn new(dir: impl AsRef<Path>, info: &Info) -> FileStorage {
        let base = dir.as_ref().to_path_buf();
        let paths = info
            .files
            .iter()
            .map(|f| {
                let mut p = base.clone();
                if !info.single_file {
                    p.push(&info.name);
                }
                p.extend(&f.path);
                p
            })
            .collect::<Vec<_>>();
        FileStorage {
            files: paths.iter().map(|_| Mutex::new(None)).collect(),
            empty_done: std::sync::atomic::AtomicBool::new(false),
            paths,
            info: info.clone(),
        }
    }

    /// The path of file `i`.
    pub fn path(&self, i: usize) -> &Path {
        &self.paths[i]
    }

    fn with_file<R>(
        &self,
        i: usize,
        create: bool,
        f: impl FnOnce(&File) -> io::Result<R>,
    ) -> io::Result<R> {
        let mut g = self.files[i].lock().unwrap_or_else(|p| p.into_inner());
        if g.is_none() {
            let p = &self.paths[i];
            let file = if create {
                if let Some(dir) = p.parent() {
                    std::fs::create_dir_all(dir)?;
                }
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .truncate(false)
                    .open(p)?
            } else {
                match OpenOptions::new().read(true).write(true).open(p) {
                    Ok(f) => f,
                    Err(_) => OpenOptions::new().read(true).open(p)?,
                }
            };
            *g = Some(file);
        }
        match g.as_ref() {
            Some(file) => f(file),
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }
}

#[cfg(unix)]
fn read_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.read_exact_at(buf, off)
}

#[cfg(unix)]
fn write_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    f.write_all_at(buf, off)
}

impl Storage for FileStorage {
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        let mut pos = 0usize;
        for s in self.info.segments(offset, len as u64) {
            let n = s.len as usize;
            if self.info.files[s.file].padding {
                // Zeros.
            } else {
                self.with_file(s.file, false, |f| {
                    read_at(f, &mut out[pos..pos + n], s.offset)
                })?;
            }
            pos += n;
        }
        if pos != len {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(out)
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        if !self
            .empty_done
            .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            for (i, f) in self.info.files.iter().enumerate() {
                if f.length == 0 && !f.padding {
                    self.with_file(i, true, |_| Ok(()))?;
                }
            }
        }
        let mut pos = 0usize;
        for s in self.info.segments(offset, data.len() as u64) {
            let n = s.len as usize;
            if !self.info.files[s.file].padding {
                self.with_file(s.file, true, |f| write_at(f, &data[pos..pos + n], s.offset))?;
            }
            pos += n;
        }
        Ok(())
    }

    fn may_have_data(&self) -> bool {
        self.paths.iter().any(|p| p.exists())
    }

    fn file_stamps(&self) -> Option<Vec<Option<FileStamp>>> {
        Some(
            self.info
                .files
                .iter()
                .zip(&self.paths)
                .map(|(f, p)| if f.padding { None } else { FileStamp::of(p) })
                .collect(),
        )
    }
}

/// The whole torrent in memory (tests, small torrents, data already at hand).
#[derive(Debug)]
pub struct MemoryStorage {
    data: Mutex<Vec<u8>>,
    filled: bool,
}

impl MemoryStorage {
    /// Empty storage of `len` bytes (zeros).
    pub fn new(len: u64) -> MemoryStorage {
        MemoryStorage {
            data: Mutex::new(vec![0; len as usize]),
            filled: false,
        }
    }

    /// Storage holding `data` already (a seeder's).
    pub fn with_data(data: Vec<u8>) -> MemoryStorage {
        MemoryStorage {
            data: Mutex::new(data),
            filled: true,
        }
    }

    /// A copy of the data.
    pub fn snapshot(&self) -> Vec<u8> {
        self.data.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl Storage for MemoryStorage {
    fn read(&self, offset: u64, len: usize) -> io::Result<Vec<u8>> {
        let d = self.data.lock().unwrap_or_else(|p| p.into_inner());
        let start = offset as usize;
        d.get(start..start + len)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        let mut d = self.data.lock().unwrap_or_else(|p| p.into_inner());
        let start = offset as usize;
        match d.get_mut(start..start + data.len()) {
            Some(dst) => {
                dst.copy_from_slice(data);
                Ok(())
            }
            None => Err(io::ErrorKind::InvalidInput.into()),
        }
    }

    fn may_have_data(&self) -> bool {
        self.filled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metainfo::Builder;

    #[test]
    fn file_storage_spans_files() {
        let dir = std::env::temp_dir().join(format!("only-bt-storage-{}", crate::rand_u32()));
        let files = vec![
            (vec!["a".to_owned()], vec![1u8; 10]),
            (vec!["sub".to_owned(), "b".to_owned()], vec![2u8; 7]),
        ];
        let mi = Builder::new("t")
            .piece_length(16)
            .build_files(&files)
            .unwrap();
        let s = FileStorage::new(&dir, &mi.info);
        assert!(!s.may_have_data());
        let all: Vec<u8> = [vec![1u8; 10], vec![2u8; 7]].concat();
        s.write(0, &all[..12]).unwrap();
        s.write(12, &all[12..]).unwrap();
        assert_eq!(s.read(8, 5).unwrap(), vec![1, 1, 2, 2, 2]);
        assert_eq!(
            std::fs::read(dir.join("t").join("sub").join("b")).unwrap(),
            vec![2u8; 7]
        );
        assert!(s.may_have_data());
        assert!(s.read(16, 5).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let m = MemoryStorage::new(4);
        m.write(1, b"ab").unwrap();
        assert_eq!(m.snapshot(), b"\0ab\0");
        assert!(m.write(3, b"xy").is_err());
    }
}
