use std::{os::unix::net::UnixListener, sync::mpsc};

use color_eyre::eyre::Result;
use mevi_common::MeviEvent;

mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/tracer.skel.rs",
    ));
}

pub struct EbpfDriver;

impl mevi_driver::Driver for EbpfDriver {
    fn build(
        &self,
        tx: mpsc::SyncSender<MeviEvent>,
        listener: UnixListener,
    ) -> Result<Box<dyn mevi_driver::Tracer>> {
        Ok(Box::new(EbpfTracer { tx, listener }))
    }
}

struct EbpfTracer {
    tx: mpsc::SyncSender<MeviEvent>,
    listener: UnixListener,
}

impl mevi_driver::Tracer for EbpfTracer {
    fn run(&mut self) -> Result<()> {
        loop {}
    }
}
