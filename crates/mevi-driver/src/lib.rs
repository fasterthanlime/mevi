use std::{os::unix::net::UnixListener, sync::mpsc};

use color_eyre::Result;

use mevi_common::MeviEvent;

/// Driver is the entrypoint for creating a [`Tracer`] instance.
pub trait Driver {
    /// Builds a [`Tracer`] listening on the given unix socket and sending back
    /// events on the given [`mpsc::SyncSender`].
    fn build(
        &self,
        tx: mpsc::SyncSender<MeviEvent>,
        listener: UnixListener,
    ) -> Result<Box<dyn Tracer>>;
}

/// Tracer contains the tracing logic, and is usually run in its own thread.
pub trait Tracer {
    /// Runs the tracing logic until the tracer process is closed or an
    /// unrecoverable is encountered.
    fn run(&mut self) -> Result<()>;
}
