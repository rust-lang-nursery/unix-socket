//! Support for Unix domain socket clients and servers.
#![warn(missing_docs)]
#![doc(html_root_url="https://sfackler.github.io/rust-unix-socket/doc/v0.4.1")]
#![cfg_attr(feature = "socket_timeout", feature(duration))]
#![cfg_attr(all(test, feature = "socket_timeout"), feature(duration_span))]

extern crate debug_builders;
extern crate libc;

use debug_builders::DebugStruct;
use std::ascii;
use std::convert::AsRef;
use std::cmp::{self, Ordering};
use std::ffi::OsStr;
use std::io;
use std::net::Shutdown;
use std::iter::IntoIterator;
use std::mem;
use std::os::unix::io::{RawFd, AsRawFd};
use std::os::unix::ffi::OsStrExt;
use std::fmt;
use std::path::Path;

extern "C" {
    fn socketpair(domain: libc::c_int,
                  ty: libc::c_int,
                  proto: libc::c_int,
                  sv: *mut [libc::c_int; 2])
                  -> libc::c_int;

    #[cfg(feature = "socket_timeout")]
    fn getsockopt(socket: libc::c_int,
                  level: libc::c_int,
                  option_name: libc::c_int,
                  option_value: *mut libc::c_void,
                  option_len: *mut libc::c_void)
                  -> libc::c_int;
}

fn sun_path_offset() -> usize {
    unsafe {
        // Work with an actual instance of the type since using a null pointer is UB
        let addr: libc::sockaddr_un = mem::uninitialized();
        let base = &addr as *const _ as usize;
        let path = &addr.sun_path as *const _ as usize;
        path - base
    }
}

struct Inner(RawFd);

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
        }
    }
}

impl Inner {
    unsafe fn new() -> io::Result<Inner> {
        let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Inner(fd))
        }
    }

    unsafe fn new_pair() -> io::Result<(Inner, Inner)> {
        let mut fds = [0, 0];
        let res = socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, &mut fds);
        if res < 0 {
            return Err(io::Error::last_os_error());
        }
        debug_assert_eq!(res, 0);
        Ok((Inner(fds[0]), Inner(fds[1])))
    }

    fn try_clone(&self) -> io::Result<Inner> {
        let fd = unsafe { libc::dup(self.0) };
        if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Inner(fd))
        }
    }
}

unsafe fn sockaddr_un<P: AsRef<Path>>(path: P)
        -> io::Result<(libc::sockaddr_un, libc::socklen_t)> {
    let mut addr: libc::sockaddr_un = mem::zeroed();
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;

    let bytes = path.as_ref().as_os_str().as_bytes();

    match (bytes.get(0), bytes.len().cmp(&addr.sun_path.len())) {
        // Abstract paths don't need a null terminator
        (Some(&0), Ordering::Greater) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "path must be no longer than SUN_LEN"))
        }
        (_, Ordering::Greater) | (_, Ordering::Equal) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                      "path must be shorter than SUN_LEN"));
        }
        _ => {}
    }
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes.iter()) {
        *dst = *src as libc::c_char;
    }
    // null byte for pathname addresses is already there because we zeroed the struct

    let mut len = sun_path_offset() + bytes.len();
    match bytes.get(0) {
        Some(&0) | None => {}
        Some(_) => len += 1
    }
    Ok((addr, len as libc::socklen_t))
}

/// The kind of an address associated with a Unix socket.
#[derive(Debug, Clone, Copy)]
pub enum AddressKind<'a> {
    /// An unnamed address.
    Unnamed,
    /// An address corresponding to a path on the filesystem.
    Pathname(&'a Path),
    /// An address in an abstract namespace unrelated to the filesystem.
    ///
    /// Abstract addresses are a nonportable Linux extension.
    Abstract(&'a [u8]),
}

/// An address associated with a Unix socket.
pub struct SocketAddr {
    addr: libc::sockaddr_un,
    len: libc::socklen_t,
}

impl Clone for SocketAddr {
    fn clone(&self) -> SocketAddr {
        SocketAddr {
            addr: self.addr,
            len: self.len,
        }
    }
}

impl SocketAddr {
    fn new(fd: RawFd,
           f: unsafe extern "system" fn(libc::c_int,
                                        *mut libc::sockaddr,
                                        *mut libc::socklen_t) -> libc::c_int)
           -> io::Result<SocketAddr> {
        unsafe {
            let mut addr: libc::sockaddr_un = mem::zeroed();
            let mut len = mem::size_of::<libc::sockaddr_un>() as libc::socklen_t;
            let ret = f(fd, &mut addr as *mut _ as *mut _, &mut len);

            if ret != 0 {
                return Err(io::Error::last_os_error());
            }

            if addr.sun_family != libc::AF_UNIX as libc::sa_family_t {
                return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                          "file descriptor did not correspond to a Unix socket"));
            }

            Ok(SocketAddr {
                addr: addr,
                len: len,
            })
        }
    }

    /// Returns the value of the address.
    pub fn address<'a>(&'a self) -> AddressKind<'a> {
        let len = self.len as usize - sun_path_offset();
        let path = unsafe { mem::transmute::<&[libc::c_char], &[u8]>(&self.addr.sun_path) };

        // OSX seems to return a len of 16 and a zeroed sun_path for unnamed addresses
        if len == 0 || (cfg!(not(target_os = "linux")) && self.addr.sun_path[0] == 0) {
            AddressKind::Unnamed
        } else if self.addr.sun_path[0] == 0 {
            AddressKind::Abstract(&path[1..len])
        } else {
            AddressKind::Pathname(OsStr::from_bytes(&path[..len - 1]).as_ref())
        }
    }
}

impl fmt::Debug for SocketAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self.address() {
            AddressKind::Unnamed => write!(fmt, "(unnamed)"),
            AddressKind::Abstract(name) => write!(fmt, "{} (abstract)", AsciiEscaped(name)),
            AddressKind::Pathname(path) => write!(fmt, "{:?} (pathname)", path)
        }
    }
}

struct AsciiEscaped<'a>(&'a [u8]);

impl<'a> fmt::Display for AsciiEscaped<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "\""));
        for byte in self.0.iter().cloned().flat_map(ascii::escape_default) {
            try!(write!(fmt, "{}", byte as char));
        }
        write!(fmt, "\"")
    }
}

/// A stream which communicates over a Unix domain socket.
///
/// # Examples
///
/// ```rust,no_run
/// use unix_socket::UnixStream;
/// use std::io::prelude::*;
///
/// let mut stream = UnixStream::connect("/path/to/my/socket").unwrap();
/// stream.write_all(b"hello world").unwrap();
/// let mut response = String::new();
/// stream.read_to_string(&mut response).unwrap();
/// println!("{}", response);
/// ```
pub struct UnixStream {
    inner: Inner,
}

impl fmt::Debug for UnixStream {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = DebugStruct::new(fmt, "UnixStream")
            .field("fd", &self.inner.0);
        if let Ok(addr) = self.local_addr() {
            builder = builder.field("local", &addr);
        }
        if let Ok(addr) = self.peer_addr() {
            builder = builder.field("peer", &addr);
        }
        builder.finish()
    }
}

impl UnixStream {
    /// Connect to the socket named by `path`.
    ///
    /// Linux provides, as a nonportable extension, a separate "abstract"
    /// address namespace as opposed to filesystem-based addressing. If `path`
    /// begins with a null byte, it will be interpreted as an "abstract"
    /// address. Otherwise, it will be interpreted as a "pathname" address,
    /// corresponding to a path on the filesystem.
    pub fn connect<P: AsRef<Path>>(path: P) -> io::Result<UnixStream> {
        unsafe {
            let inner = try!(Inner::new());
            let (addr, len) = try!(sockaddr_un(path));

            let ret = libc::connect(inner.0, &addr as *const _ as *const _, len);
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(UnixStream {
                    inner: inner,
                })
            }
        }
    }

    /// Create an unnamed pair of connected sockets.
    ///
    /// Returns two `UnixStream`s which are connected to each other.
    pub fn unnamed() -> io::Result<(UnixStream, UnixStream)> {
        unsafe {
            let (i1, i2) = try!(Inner::new_pair());
            Ok((UnixStream { inner: i1 }, UnixStream { inner: i2 }))
        }
    }

    /// Create a new independently owned handle to the underlying socket.
    ///
    /// The returned `UnixStream` is a reference to the same stream that this
    /// object references. Both handles will read and write the same stream of
    /// data, and options set on one stream will be propogated to the other
    /// stream.
    pub fn try_clone(&self) -> io::Result<UnixStream> {
        Ok(UnixStream {
            inner: try!(self.inner.try_clone())
        })
    }

    /// Returns the socket address of the local half of this connection.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::new(self.inner.0, libc::getsockname)
    }

    /// Returns the socket address of the remote half of this connection.
    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::new(self.inner.0, libc::getpeername)
    }

    /// Sets the read timeout for the socket.
    ///
    /// If the provided value is `None`, then `read` calls will block
    /// indefinitely. It is an error to pass the zero `Duration` to this
    /// method.
    ///
    /// Requires the `socket_timeout` feature.
    #[cfg(feature = "socket_timeout")]
    pub fn set_read_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.set_timeout(timeout, libc::SO_RCVTIMEO)
    }

    /// Sets the write timeout for the socket.
    ///
    /// If the provided value is `None`, then `write` calls will block
    /// indefinitely. It is an error to pass the zero `Duration` to this
    /// method.
    ///
    /// Requires the `socket_timeout` feature.
    #[cfg(feature = "socket_timeout")]
    pub fn set_write_timeout(&self, timeout: Option<std::time::Duration>) -> io::Result<()> {
        self.set_timeout(timeout, libc::SO_SNDTIMEO)
    }

    #[cfg(feature = "socket_timeout")]
    fn set_timeout(&self, dur: Option<std::time::Duration>, kind: libc::c_int) -> io::Result<()> {
        let timeout = match dur {
            Some(dur) => {
                if dur.secs() == 0 && dur.extra_nanos() == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput,
                                              "cannot set a 0 duration timeout"));
                }

                let secs = if dur.secs() > libc::time_t::max_value() as u64 {
                    libc::time_t::max_value()
                } else {
                    dur.secs() as libc::time_t
                };
                let mut timeout = libc::timeval {
                    tv_sec: secs,
                    tv_usec: (dur.extra_nanos() / 1000) as libc::suseconds_t,
                };
                if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
                    timeout.tv_usec = 1;
                }
                timeout
            }
            None => {
                libc::timeval {
                    tv_sec: 0,
                    tv_usec: 0,
                }
            }
        };

        let ret = unsafe {
            libc::setsockopt(self.inner.0,
                             libc::SOL_SOCKET,
                             kind,
                             &timeout as *const _ as *const _,
                             mem::size_of::<libc::timeval>() as libc::socklen_t)
        };
        if ret != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Returns the read timeout of this socket.
    ///
    /// Requires the `socket_timeout` feature.
    #[cfg(feature = "socket_timeout")]
    pub fn read_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.timeout(libc::SO_RCVTIMEO)
    }

    /// Returns the write timeout of this socket.
    ///
    /// Requires the `socket_timeout` feature.
    #[cfg(feature = "socket_timeout")]
    pub fn write_timeout(&self) -> io::Result<Option<std::time::Duration>> {
        self.timeout(libc::SO_SNDTIMEO)
    }

    #[cfg(feature = "socket_timeout")]
    fn timeout(&self, kind: libc::c_int) -> io::Result<Option<std::time::Duration>> {
        let timeout = unsafe {
            let mut timeout: libc::timeval = mem::zeroed();
            let mut size = mem::size_of::<libc::timeval>() as libc::socklen_t;
            let ret = getsockopt(self.inner.0,
                                 libc::SOL_SOCKET,
                                 kind,
                                 &mut timeout as *mut _ as *mut _,
                                 &mut size as *mut _ as *mut _);
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            timeout
        };

        if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
            Ok(None)
        } else {
            Ok(Some(std::time::Duration::new(timeout.tv_sec as u64,
                                             (timeout.tv_usec as u32) * 1000)))
        }
    }

    /// Shut down the read, write, or both halves of this connection.
    ///
    /// This function will cause all pending and future I/O calls on the
    /// specified portions to immediately return with an appropriate value
    /// (see the documentation of `Shutdown`).
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };

        let ret = unsafe { libc::shutdown(self.inner.0, how) };
        if ret != 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

fn calc_len(buf: &[u8]) -> libc::size_t {
    cmp::min(libc::size_t::max_value() as usize, buf.len()) as libc::size_t
}

impl io::Read for UnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::recv(self.inner.0, buf.as_mut_ptr() as *mut _, calc_len(buf), 0)
        };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

impl io::Write for UnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = unsafe {
            libc::send(self.inner.0, buf.as_ptr() as *const _, calc_len(buf), 0)
        };

        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl AsRawFd for UnixStream {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.0
    }
}

#[cfg(feature = "from_raw_fd")]
impl std::os::unix::io::FromRawFd for UnixStream {
    /// Requires the `from_raw_fd` feature.
    unsafe fn from_raw_fd(fd: RawFd) -> UnixStream {
        UnixStream {
            inner: Inner(fd)
        }
    }
}

/// A structure representing a Unix domain socket server.
///
/// # Examples
///
/// ```rust,no_run
/// use std::thread;
/// use unix_socket::{UnixStream, UnixListener};
///
/// fn handle_client(stream: UnixStream) {
///     // ...
/// }
///
/// let listener = UnixListener::bind("/path/to/the/socket").unwrap();
///
/// // accept connections and process them, spawning a new thread for each one
/// for stream in listener.incoming() {
///     match stream {
///         Ok(stream) => {
///             /* connection succeeded */
///             thread::spawn(|| handle_client(stream));
///         }
///         Err(err) => {
///             /* connection failed */
///             break;
///         }
///     }
/// }
///
/// // close the listener socket
/// drop(listener);
/// ```
pub struct UnixListener {
    inner: Inner,
}

impl fmt::Debug for UnixListener {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = DebugStruct::new(fmt, "UnixListener")
            .field("fd", &self.inner.0);
        if let Ok(addr) = self.local_addr() {
            builder = builder.field("local", &addr);
        }
        builder.finish()
    }
}

impl UnixListener {
    /// Creates a new `UnixListener` which will be bound to the specified
    /// socket.
    ///
    /// Linux provides, as a nonportable extension, a separate "abstract"
    /// address namespace as opposed to filesystem-based addressing. If `path`
    /// begins with a null byte, it will be interpreted as an "abstract"
    /// address. Otherwise, it will be interpreted as a "pathname" address,
    /// corresponding to a path on the filesystem.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<UnixListener> {
        unsafe {
            let inner = try!(Inner::new());
            let (addr, len) = try!(sockaddr_un(path));

            let ret = libc::bind(inner.0, &addr as *const _ as *const _, len);
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

            let ret = libc::listen(inner.0, 128);
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(UnixListener {
                    inner: inner,
                })
            }
        }
    }

    /// Accepts a new incoming connection to this listener.
    pub fn accept(&self) -> io::Result<UnixStream> {
        unsafe {
            let ret = libc::accept(self.inner.0, 0 as *mut _, 0 as *mut _);
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(UnixStream {
                    inner: Inner(ret)
                })
            }
        }
    }

    /// Create a new independently owned handle to the underlying socket.
    ///
    /// The returned `UnixListener` is a reference to the same socket that this
    /// object references. Both handles can be used to accept incoming
    /// connections and options set on one listener will affect the other.
    pub fn try_clone(&self) -> io::Result<UnixListener> {
        Ok(UnixListener {
            inner: try!(self.inner.try_clone())
        })
    }

    /// Returns the socket address of the local half of this connection.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        SocketAddr::new(self.inner.0, libc::getsockname)
    }

    /// Returns an iterator over incoming connections.
    ///
    /// The iterator will never return `None`.
    pub fn incoming<'a>(&'a self) -> Incoming<'a> {
        Incoming {
            listener: self
        }
    }
}

impl AsRawFd for UnixListener {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.0
    }
}

#[cfg(feature = "from_raw_fd")]
impl std::os::unix::io::FromRawFd for UnixListener {
    /// Requires the `from_raw_fd` feature.
    unsafe fn from_raw_fd(fd: RawFd) -> UnixListener {
        UnixListener {
            inner: Inner(fd)
        }
    }
}

impl<'a> IntoIterator for &'a UnixListener {
    type Item = io::Result<UnixStream>;
    type IntoIter = Incoming<'a>;

    fn into_iter(self) -> Incoming<'a> {
        self.incoming()
    }
}

/// An iterator over incoming connections to a `UnixListener`.
///
/// It will never return `None`.
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a UnixListener,
}

impl<'a> Iterator for Incoming<'a> {
    type Item = io::Result<UnixStream>;

    fn next(&mut self) -> Option<io::Result<UnixStream>> {
        Some(self.listener.accept())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (usize::max_value(), None)
    }
}

#[cfg(test)]
mod test {
    extern crate tempdir;

    use std::thread;
    use std::io;
    use std::io::prelude::*;
    use self::tempdir::TempDir;

    use {UnixListener, UnixStream};

    macro_rules! or_panic {
        ($e:expr) => {
            match $e {
                Ok(e) => e,
                Err(e) => panic!("{}", e),
            }
        }
    }

    #[test]
    fn basic() {
        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");
        let msg1 = b"hello";
        let msg2 = b"world!";

        let listener = or_panic!(UnixListener::bind(&socket_path));
        let thread = thread::spawn(move || {
            let mut stream = or_panic!(listener.accept());
            let mut buf = [0; 5];
            or_panic!(stream.read(&mut buf));
            assert_eq!(&msg1[..], &buf[..]);
            or_panic!(stream.write_all(msg2));
        });

        let mut stream = or_panic!(UnixStream::connect(&socket_path));
        or_panic!(stream.write_all(msg1));
        let mut buf = vec![];
        or_panic!(stream.read_to_end(&mut buf));
        assert_eq!(&msg2[..], &buf[..]);
        drop(stream);

        thread.join().unwrap();
    }

    #[test]
    fn unnamed() {
        let msg1 = b"hello";
        let msg2 = b"world!";

        let (mut s1, mut s2) = or_panic!(UnixStream::unnamed());
        let thread = thread::spawn(move || {
            // s1 must be moved in or the test will hang!
            let mut buf = [0; 5];
            or_panic!(s1.read(&mut buf));
            assert_eq!(&msg1[..], &buf[..]);
            or_panic!(s1.write_all(msg2));
        });

        or_panic!(s2.write_all(msg1));
        let mut buf = vec![];
        or_panic!(s2.read_to_end(&mut buf));
        assert_eq!(&msg2[..], &buf[..]);
        drop(s2);

        thread.join().unwrap();
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore)]
    fn abstract_address() {
        let socket_path = "\0the path";
        let msg1 = b"hello";
        let msg2 = b"world!";

        let listener = or_panic!(UnixListener::bind(&socket_path));
        let thread = thread::spawn(move || {
            let mut stream = or_panic!(listener.accept());
            let mut buf = [0; 5];
            or_panic!(stream.read(&mut buf));
            assert_eq!(&msg1[..], &buf[..]);
            or_panic!(stream.write_all(msg2));
        });

        let mut stream = or_panic!(UnixStream::connect(&socket_path));
        or_panic!(stream.write_all(msg1));
        let mut buf = vec![];
        or_panic!(stream.read_to_end(&mut buf));
        assert_eq!(&msg2[..], &buf[..]);
        drop(stream);

        thread.join().unwrap();
    }

    #[test]
    fn try_clone() {
        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");
        let msg1 = b"hello";
        let msg2 = b"world";

        let listener = or_panic!(UnixListener::bind(&socket_path));
        let thread = thread::spawn(move || {
            let mut stream = or_panic!(listener.accept());
            or_panic!(stream.write_all(msg1));
            or_panic!(stream.write_all(msg2));
        });

        let mut stream = or_panic!(UnixStream::connect(&socket_path));
        let mut stream2 = or_panic!(stream.try_clone());

        let mut buf = [0; 5];
        or_panic!(stream.read(&mut buf));
        assert_eq!(&msg1[..], &buf[..]);
        or_panic!(stream2.read(&mut buf));
        assert_eq!(&msg2[..], &buf[..]);

        thread.join().unwrap();
    }

    #[test]
    fn iter() {
        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");

        let listener = or_panic!(UnixListener::bind(&socket_path));
        let thread = thread::spawn(move || {
            for stream in listener.incoming().take(2) {
                let mut stream = or_panic!(stream);
                let mut buf = [0];
                or_panic!(stream.read(&mut buf));
            }
        });

        for _ in 0..2 {
            let mut stream = or_panic!(UnixStream::connect(&socket_path));
            or_panic!(stream.write_all(&[0]));
        }

        thread.join().unwrap();
    }

    #[test]
    fn long_path() {
        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("asdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasdfasd\
                                           fasdfasasdfasdfasdasdfasdfasdfadfasdfasdfasdfasdfasdf");
        match UnixStream::connect(&socket_path) {
            Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {}
            Err(e) => panic!("unexpected error {}", e),
            Ok(_) => panic!("unexpected success"),
        }

        match UnixListener::bind(&socket_path) {
            Err(ref e) if e.kind() == io::ErrorKind::InvalidInput => {}
            Err(e) => panic!("unexpected error {}", e),
            Ok(_) => panic!("unexpected success"),
        }
    }

    #[test]
    #[cfg(feature = "socket_timeout")]
    fn timeouts() {
        use std::time::Duration;

        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");

        let _listener = or_panic!(UnixListener::bind(&socket_path));

        let stream = or_panic!(UnixStream::connect(&socket_path));
        let dur = Duration::new(15410, 0);

        assert_eq!(None, or_panic!(stream.read_timeout()));

        or_panic!(stream.set_read_timeout(Some(dur)));
        assert_eq!(Some(dur), or_panic!(stream.read_timeout()));

        assert_eq!(None, or_panic!(stream.write_timeout()));

        or_panic!(stream.set_write_timeout(Some(dur)));
        assert_eq!(Some(dur), or_panic!(stream.write_timeout()));

        or_panic!(stream.set_read_timeout(None));
        assert_eq!(None, or_panic!(stream.read_timeout()));

        or_panic!(stream.set_write_timeout(None));
        assert_eq!(None, or_panic!(stream.write_timeout()));
    }

    #[test]
    #[cfg(feature = "socket_timeout")]
    fn test_read_timeout() {
        use std::time::Duration;

        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");

        let _listener = or_panic!(UnixListener::bind(&socket_path));

        let mut stream = or_panic!(UnixStream::connect(&socket_path));
        or_panic!(stream.set_read_timeout(Some(Duration::from_millis(1000))));

        let mut buf = [0; 10];
        let wait = Duration::span(|| {
            let kind = stream.read(&mut buf).err().expect("expected error").kind();
            assert!(kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut);
        });
        assert!(wait > Duration::from_millis(400));
        assert!(wait < Duration::from_millis(1600));
    }

    #[test]
    #[cfg(feature = "socket_timeout")]
    fn test_read_with_timeout() {
        use std::time::Duration;

        let dir = or_panic!(TempDir::new("unix_socket"));
        let socket_path = dir.path().join("sock");

        let listener = or_panic!(UnixListener::bind(&socket_path));

        let mut stream = or_panic!(UnixStream::connect(&socket_path));
        or_panic!(stream.set_read_timeout(Some(Duration::from_millis(1000))));

        let mut other_end = or_panic!(listener.accept());
        or_panic!(other_end.write_all(b"hello world"));

        let mut buf = [0; 11];
        or_panic!(stream.read(&mut buf));
        assert_eq!(b"hello world", &buf[..]);

        let wait = Duration::span(|| {
            let kind = stream.read(&mut buf).err().expect("expected error").kind();
            assert!(kind == io::ErrorKind::WouldBlock || kind == io::ErrorKind::TimedOut);
        });
        assert!(wait > Duration::from_millis(400));
        assert!(wait < Duration::from_millis(1600));
    }
}
