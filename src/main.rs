use std::{os::unix::process::CommandExt, process::Command};

use nix::{
    sys::{
        ptrace::{self},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut cmd = Command::new("../mem-hog/target/release/mem-hog");
    unsafe {
        cmd.pre_exec(|| {
            ptrace::traceme()?;
            Ok(())
        });
    }

    let child = cmd.spawn()?;
    let pid = Pid::from_raw(child.id() as _);
    waitpid(pid, None)?;

    loop {
        syscall_step(pid)?;
        syscall_step(pid)?;
        on_sys_exit(pid)?;
    }
}

fn syscall_step(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        ptrace::syscall(pid, None)?;

        match waitpid(pid, None)? {
            WaitStatus::Stopped(_, Signal::SIGTRAP) => break Ok(()),
            WaitStatus::Exited(_, status) => {
                eprintln!("Child exited with status {status}");
                std::process::exit(status);
            }
            _ => continue,
        }
    }
}

fn on_sys_exit(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    let regs = ptrace::getregs(pid)?;
    let syscall = regs.orig_rax as i64;
    let ret = regs.rax as i64;

    match syscall {
        libc::SYS_mmap if regs.r8 == (-1_i32 as u32) as _ => {
            let len = regs.rsi as usize;
            eprintln!("mmap-allocated {} bytes at {:#x}", len, ret);
        }
        _other => {
            // let's ignore that for now
        }
    }

    Ok(())
}
