use std::{os::unix::net::UnixListener, sync::mpsc};

use color_eyre::Result;
use mevi_common::MeviEvent;

mod tracer;
pub(crate) mod userfault;

pub type PtraceUffdTracer = tracer::Tracer;

pub struct PtraceUffdDriver;

impl mevi_driver::Driver for PtraceUffdDriver {
    fn build(
        &self,
        tx: mpsc::SyncSender<MeviEvent>,
        listener: UnixListener,
    ) -> Result<Box<dyn mevi_driver::Tracer>> {
        Ok(Box::new(PtraceUffdTracer::new(tx, listener)?))
    }
}
