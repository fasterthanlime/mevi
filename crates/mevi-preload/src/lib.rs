use std::{
    io::Write,
    os::{fd::AsRawFd, unix::net::UnixStream},
};

use passfd::FdPassingExt;
use userfaultfd::{FeatureFlags, UffdBuilder};

#[ctor::ctor]
fn ctor() {
    println!("Register number: {}", userfaultfd::raw::UFFDIO_REGISTER);

    let uffd = UffdBuilder::new()
        .user_mode_only(false)
        .require_features(
            FeatureFlags::EVENT_REMAP | FeatureFlags::EVENT_REMOVE | FeatureFlags::EVENT_UNMAP,
        )
        .create()
        .unwrap();

    let mut stream = UnixStream::connect("/tmp/mevi.sock").unwrap();
    let pid: u64 = std::process::id() as _;
    let pid_bytes = pid.to_be_bytes();
    stream.write_all(&pid_bytes).unwrap();

    stream.send_fd(uffd.as_raw_fd()).unwrap();
    std::mem::forget(uffd);
}
