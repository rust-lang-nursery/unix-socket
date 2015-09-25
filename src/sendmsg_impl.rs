use std::io;
use std::ptr;
use std::mem;
use std::os::unix::io::RawFd;
use std::slice;

use libc;

mod raw {
    use libc;
    extern "system" {
        pub fn sendmsg(socket: libc::c_int, msg: *const libc::c_void, flags: libc::c_int) -> libc::ssize_t;
        pub fn recvmsg(socket: libc::c_int, msg: *mut libc::c_void, flags: libc::c_int) -> libc::ssize_t;
    }

    #[allow(dead_code)]
    extern {
        pub static cmsghdr_size: libc::size_t;
        pub static iovec_size: libc::size_t;
        pub static msghdr_size: libc::size_t;
        pub static ucred_size: libc::size_t;

        pub static scm_credentials: libc::c_int;
        pub static scm_rights: libc::c_int;

        pub static so_passcred: libc::c_int;

        pub static msg_eor: libc::c_int;
        pub static msg_trunc: libc::c_int;
        pub static msg_ctrunc: libc::c_int;
        pub static msg_errqueue: libc::c_int;
        pub static msg_dontwait: libc::c_int;
        pub static msg_cmsg_cloexec: libc::c_int;
        pub static msg_nosignal: libc::c_int;
        pub static msg_peek: libc::c_int;
        pub static msg_waitall: libc::c_int;

        pub fn cmsg_firsthdr(msgh: *const libc::c_void) -> *const libc::c_void;
        pub fn cmsg_nxthdr(msgh: *const libc::c_void, cmsg: *const libc::c_void) -> *const libc::c_void;
        pub fn cmsg_align(len: libc::size_t) -> libc::size_t;
        pub fn cmsg_space(len: libc::size_t) -> libc::size_t;
        pub fn cmsg_len(len: libc::size_t) -> libc::size_t;
        pub fn cmsg_data(cmsg: *const libc::c_void) -> *const libc::c_void;
    }
}

pub use self::raw::so_passcred as SO_PASSCRED;

pub use self::raw::scm_credentials as SCM_CREDENTIALS;
pub use self::raw::scm_rights as SCM_RIGHTS;

use self::raw::msg_eor as MSG_EOR;
use self::raw::msg_trunc as MSG_TRUNC;
use self::raw::msg_ctrunc as MSG_CTRUNC;
use self::raw::msg_errqueue as MSG_ERRQUEUE;
use self::raw::msg_dontwait as MSG_DONTWAIT;
use self::raw::msg_cmsg_cloexec as MSG_CMSG_CLOEXEC;
use self::raw::msg_nosignal as MSG_NOSIGNAL;
use self::raw::msg_peek as MSG_PEEK;
use self::raw::msg_waitall as MSG_WAITALL;

pub unsafe fn sendmsg(
    socket: libc::c_int, 
    dst: Option<(libc::sockaddr_un, libc::socklen_t)>, 
    buffers: &[&[u8]],
    ctrl_msgs: &[ControlMsg],
    flags: SendMsgFlags) -> io::Result<usize> {

    let mut msg: MsgHdr = mem::zeroed();

    // Initialize destination field
    if let Some((addr, len)) = dst {
        msg.msg_name = (&addr as *const libc::sockaddr_un) as *const libc::c_void;
        msg.msg_namelen = len;
    }

    // Initialize scatter/gather vector
    let mut iovecs = Vec::with_capacity(buffers.len());
    for buf in buffers {
        iovecs.push(IoVec::new(buf));
    }
    msg.msg_iov = iovecs.as_mut_ptr() as *mut libc::c_void;
    msg.msg_iovlen = iovecs.len() as libc::size_t;

    // Initialize control message struct

    let mut total_space: usize = 0;
    for ctrl_msg in ctrl_msgs.iter().cloned() {
        let size = match ctrl_msg {
            ControlMsg::Rights(fds) => (mem::size_of::<libc::c_int>() * fds.len()) as libc::size_t,
            ControlMsg::Credentials(..) => mem::size_of::<UCred>() as libc::size_t,
            _ => unimplemented!(),
        };
        total_space += raw::cmsg_space(size) as usize;
    }

    let mut ctrl_buf = &mut Vec::<u8>::with_capacity(total_space)[..];
    msg.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = total_space as libc::size_t;

    let msg_addr = (&msg as *const MsgHdr) as *const libc::c_void;
    let mut cur_cmsg = raw::cmsg_firsthdr(msg_addr);
    for ctrl_msg in ctrl_msgs.iter().cloned() {
        if cur_cmsg == ptr::null() {
            panic!("programming error: buffer too small");
        }

        let cmsg = cur_cmsg as *mut CmsgHdr;
        match ctrl_msg {
            // NOTE: Add handlers for new messages here
            ControlMsg::Rights(fds) => {
                (*cmsg).cmsg_len = raw::cmsg_len((mem::size_of::<libc::c_int>() * fds.len()) as libc::size_t) as libc::size_t;
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_RIGHTS;
                let data = raw::cmsg_data(cur_cmsg) as *mut libc::c_int;
                ptr::copy_nonoverlapping(fds.as_ptr(), data, fds.len());
            },
            ControlMsg::Credentials(ucred) => {
                (*cmsg).cmsg_len = raw::cmsg_len(mem::size_of::<UCred>() as libc::size_t) as libc::size_t;
                (*cmsg).cmsg_level = libc::SOL_SOCKET;
                (*cmsg).cmsg_type = SCM_CREDENTIALS;
                let data = raw::cmsg_data(cur_cmsg) as *mut UCred;
                ptr::write(data, ucred);
            }
            _ => unreachable!(),
        }

        cur_cmsg = raw::cmsg_nxthdr(msg_addr, cur_cmsg);
    }
    
    let res = raw::sendmsg(socket, msg_addr, flags.as_cint());
    if res < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as usize)
    }
}

pub struct InternalRecvMsgResult {
    pub data_bytes: usize,
    pub control_msgs: Vec<ControlMsg>,
    pub flags: RecvMsgResultFlags,
}

pub unsafe fn recvmsg(
    socket: libc::c_int, 
    buffers: &[&mut [u8]],
    cmsg_buffer: &mut [u8],
    flags: RecvMsgFlags,
    sender_addr: *mut libc::sockaddr,
    sender_len: *mut libc::socklen_t) -> io::Result<InternalRecvMsgResult> {

    let mut msg: MsgHdr = mem::zeroed();

    msg.msg_name = sender_addr as *const libc::c_void;
    msg.msg_namelen = *sender_len;

    // Initialize scatter/gather vector
    let mut iovecs = Vec::with_capacity(buffers.len());
    for buf in buffers {
        iovecs.push(IoVec::new(buf));
    }
    msg.msg_iov = iovecs.as_mut_ptr() as *mut libc::c_void;
    msg.msg_iovlen = (mem::size_of::<IoVec>() * iovecs.len()) as libc::size_t;

    // Initialize control message struct
    msg.msg_control = cmsg_buffer.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buffer.len() as libc::size_t;

    let msg_addr = (&mut msg as *mut MsgHdr) as *mut libc::c_void;
    let recvmsg_res = raw::recvmsg(socket, msg_addr, flags.as_cint());
    if recvmsg_res < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut cmsgs = vec![];

    let mut cur_cmsg = raw::cmsg_firsthdr(msg_addr);
    while cur_cmsg != ptr::null() {
        // NOTE: Add handlers for new messages here
        let cmsg = cur_cmsg as *mut CmsgHdr;
        if (*cmsg).cmsg_level == libc::SOL_SOCKET {
            if (*cmsg).cmsg_type == SCM_CREDENTIALS {
                    let ucred = raw::cmsg_data(cur_cmsg) as *mut UCred;
                    assert_eq!((ucred as i64) + mem::size_of::<UCred>() as i64 - cur_cmsg as i64, (*cmsg).cmsg_len as i64);
                    cmsgs.push(ControlMsg::Credentials((*ucred).clone()));
            } else if (*cmsg).cmsg_type == SCM_RIGHTS {
                let mut fds = vec![];
                let data = raw::cmsg_data(cur_cmsg) as *mut libc::c_int;
                let length = ((*cmsg).cmsg_len as i64 - (data as i64 - cur_cmsg as i64)) as usize;
                assert_eq!(length % mem::size_of::<libc::c_int>(), 0);
                let passed_fds = slice::from_raw_parts(data, length / mem::size_of::<libc::c_int>());
                for &fd in passed_fds {
                    fds.push(fd);
                }
                cmsgs.push(ControlMsg::Rights(fds));
            } else {
                cmsgs.push(ControlMsg::Unknown{ level: (*cmsg).cmsg_level, typ: (*cmsg).cmsg_type });
            }
        } else {
            cmsgs.push(ControlMsg::Unknown{ level: (*cmsg).cmsg_level, typ: (*cmsg).cmsg_type });
        }

        cur_cmsg = raw::cmsg_nxthdr(msg_addr, cur_cmsg);
    }


    *sender_len = msg.msg_namelen;
    Ok(InternalRecvMsgResult {
        data_bytes: recvmsg_res as usize,
        control_msgs: cmsgs,
        flags: RecvMsgResultFlags::from_cint(msg.msg_flags),
    })
}

#[derive(Clone, Copy, Debug)]
/// Flags given to sendmsg.  See sendmsg(2) for more details.
pub struct SendMsgFlags {
    dont_wait: bool,
    end_of_record: bool,
    no_signal: bool,
}

#[derive(Clone, Copy, Debug)]
/// Flags given to recvmsg.  See recvmsg(2) for more details.
pub struct RecvMsgFlags {
    cmsg_cloexec: bool,
    dont_wait: bool,
    peek: bool,
    wait_all: bool,
    // TODO: Add support for MSG_ERRQUEUE (need to support more cmsgs)
}

#[derive(Clone, Copy, Debug)]
/// Flags returned by recvmsg.  See recvmsg(2) for more details.
pub struct RecvMsgResultFlags {
    end_of_record: bool,
    truncated: bool,
    control_truncated: bool,
}

impl SendMsgFlags {
    /// Create a default SendMsgFlags
    pub fn new() -> SendMsgFlags {
        SendMsgFlags {
            dont_wait: false,
            end_of_record: false,
            no_signal: false,
        }
    }

    /// Do not block (MSG_DONTWAIT)
    pub fn dont_wait(mut self, v: bool) -> SendMsgFlags {
        self.dont_wait = v;
        self
    }

    /// Mark this packet as the end of a record (used for SOCK_SEQPACKET connections) (MSG_EOR)
    pub fn end_of_record(mut self, v: bool) -> SendMsgFlags {
        self.end_of_record = v;
        self
    }

    /// Do not receive SIGPIPE if the other end breaks the connection (MSG_NOSIGNAL)
    pub fn no_signal(mut self, v: bool) -> SendMsgFlags {
        self.no_signal = v;
        self
    }

    fn as_cint(&self) -> libc::c_int {
        let mut result = 0;
        if self.dont_wait { result |= MSG_DONTWAIT; }
        if self.end_of_record { result |= MSG_EOR; }
        if self.no_signal { result |= MSG_NOSIGNAL; }
        result
    }
}

impl RecvMsgFlags {
    /// Create a default RecvMsgFlags
    pub fn new() -> RecvMsgFlags {
        RecvMsgFlags {
            cmsg_cloexec: false,
            dont_wait: false,
            peek: false,
            wait_all: false,
        }
    }

    /// Sets the close-on-exec flag for any file descriptors received via SCM_RIGHTS (MSG_CMSG_CLOEXEC)
    pub fn cmsg_cloexec(mut self, v: bool) -> RecvMsgFlags {
        self.cmsg_cloexec = v;
        self
    }

    /// Do not block (MSG_DONTWAIT)
    pub fn dont_wait(mut self, v: bool) -> RecvMsgFlags {
        self.dont_wait = v;
        self
    }

    /// Do not remove the retrieved data from the receive queue (the next call will return the same data) (MSG_PEEK)
    pub fn peek(mut self, v: bool) -> RecvMsgFlags {
        self.peek = v;
        self
    }

    /// Wait for the buffers to be filled (may still be interrupted by a signal or the socket hanging up) (MSG_WAITALL)
    pub fn wait_all(mut self, v: bool) -> RecvMsgFlags {
        self.wait_all = v;
        self
    }

    fn as_cint(&self) -> libc::c_int {
        let mut result = 0;
        if self.cmsg_cloexec { result |= MSG_CMSG_CLOEXEC; }
        if self.dont_wait { result |= MSG_DONTWAIT; }
        if self.peek { result |= MSG_PEEK; }
        if self.wait_all { result |= MSG_WAITALL; }
        result
    }
}

impl RecvMsgResultFlags {
    /// The returned data marks the end of a record (used for SOCK_SEQPACKET) (MSG_EOR)
    pub fn end_of_record(&self) -> bool {
        self.end_of_record
    }

    /// Some data was discarded due to the provided buffers being too short (MSG_TRUNC)
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// Some control data was discarded (MSG_CTRUNC)
    pub fn control_truncated(&self) -> bool {
        self.control_truncated
    }

    fn from_cint(flags: libc::c_int) -> RecvMsgResultFlags {
        RecvMsgResultFlags {
            end_of_record: (flags & MSG_EOR) != 0,
            truncated: (flags & MSG_TRUNC) != 0,
            control_truncated: (flags & MSG_CTRUNC) != 0,
        }
    }
}

#[repr(C)]
struct MsgHdr {
    pub msg_name: *const libc::c_void,
    pub msg_namelen: libc::socklen_t,
    pub msg_iov: *mut libc::c_void,
    pub msg_iovlen: libc::size_t,
    pub msg_control: *mut libc::c_void,
    pub msg_controllen: libc::size_t,
    pub msg_flags: libc::c_int,
}

#[test]
fn msghdr_size_correctness() {
    assert_eq!(raw::msghdr_size as usize, mem::size_of::<MsgHdr>());
}

#[repr(C)]
struct IoVec {
    base: *const libc::c_void,
    len: libc::size_t,
}

impl IoVec {
    fn new(buf: &[u8]) -> IoVec {
        IoVec {
            base: buf.as_ptr() as *const libc::c_void,
            len: buf.len() as libc::size_t,
        }
    }
}

#[test]
fn iovec_size_correctness() {
    assert_eq!(raw::iovec_size as usize, mem::size_of::<IoVec>());
}

#[repr(C)]
struct CmsgHdr {
    cmsg_len: libc::size_t,
    cmsg_level: libc::c_int,
    cmsg_type: libc::c_int,
}

#[test]
fn cmsghdr_size_correctness() {
    assert_eq!(raw::cmsghdr_size as usize, mem::size_of::<CmsgHdr>());
}

/// Unix credential that can be sent/received over Unix sockets using `ControlMsg::Credential`
///
/// This is a Rust version of `struct ucred` from sys/socket.h
#[derive(Clone, Debug)]
pub struct UCred{
    /// The sender's process id
    pub pid: libc::pid_t, 
    /// The sender's user id
    pub uid: libc::uid_t, 
    /// The sender's group id
    pub gid: libc::gid_t,
}

#[test]
fn ucred_size_correctness() {
    assert_eq!(raw::ucred_size as usize, mem::size_of::<UCred>());
}

/// Ancillary messages that can be sent/received over Unix sockets using `sendmsg`/`recvmsg`.
#[derive(Clone, Debug)]
pub enum ControlMsg {
    /// Message used to transfer file descriptors
    Rights(Vec<RawFd>),
    /// Message used to provide kernel-verified Unix credentials of the sender
    Credentials(UCred),
    /// Any unimplemented message
    Unknown {
        /// cmsg_level of the unimplemented message
        level: libc::c_int,
        /// cmsg_type of the unimplemented message
        typ: libc::c_int,
    },
    // To add support for more messages, define the message in ControlMsg,
    // and near the relevant NOTE comments above.
}
