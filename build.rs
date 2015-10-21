extern crate gcc;

fn main() {
    gcc::compile_library("libcmsg_manip.a", &["src/cmsg_manip/cmsg.c"]);
}
