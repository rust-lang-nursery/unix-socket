extern crate libc;
extern crate unix_socket;

use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;

#[cfg(feature = "sendmsg")]
use unix_socket::{ControlMsg, UCred, UnixDatagram, RecvMsgFlags, SendMsgFlags};

#[cfg(feature = "sendmsg")]
fn handle_parent(sock: UnixDatagram) {
    let (parent2, child2) = UnixDatagram::pair().unwrap();

    let cmsg = ControlMsg::Rights(vec![child2.as_raw_fd()]);
    let cmsg2 = unsafe { ControlMsg::Credentials(UCred{
        pid: libc::getpid(),
        uid: libc::getuid(),
        gid: libc::getgid(),
    }) };
    println!("cmsg {:?}", cmsg2);
    let sent_bytes = sock.sendmsg::<&Path>(None, &[&[]], &[cmsg, cmsg2], SendMsgFlags::default()).unwrap();
    assert_eq!(sent_bytes, 0);
    drop(child2);
    println!("Parent sent child SCM_RIGHTS fd");

    let mut buf = &mut [0u8; 4096];
    let read = parent2.recv(buf).unwrap();
    assert_eq!(&buf[..read], "Hello, world!".as_bytes());
    println!("Parent received message from child via SCM_RIGHTS fd");
}

#[cfg(feature = "sendmsg")]
fn handle_child(sock: UnixDatagram) {
    sock.set_passcred(true).unwrap();
    let mut cmsg_buf = &mut [0u8; 4096];
    let result = sock.recvmsg(&[&mut[]], cmsg_buf, RecvMsgFlags::default()).unwrap();
    assert_eq!(result.control_msgs.len(), 2);

    let mut new_sock = None;
    let mut creds = None;
    for cmsg in result.control_msgs {
        match cmsg.clone() {
            ControlMsg::Rights(fds) => {
                assert!(new_sock.is_none());
                assert_eq!(fds.len(), 1);
                unsafe {
                    new_sock = Some(UnixDatagram::from_raw_fd(fds[0]));
                }
                println!("Child received SCM_RIGHTS fd");
            },
            ControlMsg::Credentials(ucred) => {
                assert!(creds.is_none());
                creds = Some(ucred);
                println!("Child received SCM_CREDENTIALS");
            },
            _ => unreachable!(),
        }
    }

    let creds = creds.unwrap();
    unsafe {
        assert_eq!(creds.uid, libc::getuid());
        assert_eq!(creds.gid, libc::getgid());
        assert!(creds.pid != 0);
    }
    let sent = new_sock.unwrap().send("Hello, world!".as_bytes()).unwrap();
    println!("Child sent message to parent via SCM_RIGHTS fd");
    assert_eq!(sent, 13);
}

#[cfg(feature = "sendmsg")]
fn main() {
    let (parent_sock, child_sock) = UnixDatagram::pair().unwrap();
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        handle_child(child_sock);
    } else {
        handle_parent(parent_sock);
    }
}

#[cfg(not(feature = "sendmsg"))]
fn main() {
}
