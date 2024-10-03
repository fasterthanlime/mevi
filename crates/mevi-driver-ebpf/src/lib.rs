use std::{
    ffi::{c_char, CStr, CString},
    mem::MaybeUninit,
    os::unix::net::UnixListener,
    process::{exit, Command, Stdio},
    sync::{mpsc, Arc},
    time::Duration,
};

use color_eyre::eyre::Result;
use libbpf_rs::{
    skel::{OpenSkel, SkelBuilder},
    AsRawLibbpf, MapCore, MapFlags,
};
use mevi_common::{MeviEvent, TraceeId, TraceePayload};
use nix::{
    sys::{
        signal::{kill, SigSet, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{execvp, fork, getpid, ForkResult, Pid},
};
use tracing::trace;

mod bpf;

pub struct EbpfDriver;

impl mevi_driver::Driver for EbpfDriver {
    fn build(
        &self,
        tx: mpsc::SyncSender<MeviEvent>,
        listener: UnixListener,
    ) -> Result<Box<dyn mevi_driver::Tracer>> {
        let tracer = EbpfTracer::new(tx, listener)?;
        Ok(Box::new(tracer))
    }
}

#[derive(Debug, Clone)]
struct EbpfTracer {
    tx: Arc<mpsc::SyncSender<MeviEvent>>,
    listener: Arc<UnixListener>,
}

impl EbpfTracer {
    fn new(tx: mpsc::SyncSender<MeviEvent>, listener: UnixListener) -> Result<Self> {
        let tx = Arc::new(tx);
        let listener = Arc::new(listener);

        Ok(Self { tx, listener })
    }
}

impl mevi_driver::Tracer for EbpfTracer {
    fn run(&mut self) -> Result<()> {
        let mut skel_builder = bpf::TracerSkelBuilder::default();
        skel_builder.obj_builder.debug(true);

        let mut object_open = MaybeUninit::uninit();
        let mut open_skel = skel_builder.open(&mut object_open)?;

        open_skel.maps.events.set_max_entries(256 * 1024)?;

        let skel = open_skel.load()?;

        let pid = getpid();
        let key = pid.as_raw();
        let key_bytes = bytemuck::bytes_of(&key);
        let value: c_char = 0;
        let value_bytes = bytemuck::bytes_of(&value);
        skel.maps
            .tracees
            .update(key_bytes, value_bytes, MapFlags::ANY)
            .unwrap();

        let callback = |bytes: &[u8]| -> i32 {
            let _memory_change: &'_ bpf::MemoryChange = bytemuck::from_bytes(bytes);
            0
        };

        let mut ringbuffer_builder = libbpf_rs::RingBufferBuilder::default();
        ringbuffer_builder.add(&skel.maps.events, callback)?;
        let ringbuffer = ringbuffer_builder.build()?;

        // TODO: Attach program when they are ready. Meanwhile, the command
        // should execute correctly.

        // skel.attach()?

        let mut args = std::env::args();
        let mut cmd = Command::new(args.next().unwrap());
        cmd.args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().unwrap();

        loop {
            ringbuffer.poll(Duration::from_micros(1000))?;

            if let Some(_) = child.try_wait()? {
                break;
            }
        }

        ringbuffer.consume()?;

        Ok(())
    }
}
