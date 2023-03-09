use std::os::{fd::AsRawFd, unix::net::UnixStream};

use passfd::FdPassingExt;
use userfaultfd::UffdBuilder;

#[ctor::ctor]
fn ctor() {
    let uffd = UffdBuilder::new().create().unwrap();
    let stream = UnixStream::connect("/tmp/mevi.sock").unwrap();
    stream.send_fd(uffd.as_raw_fd()).unwrap();
    std::mem::forget(uffd);
}
