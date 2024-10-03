use std::{ffi::c_int, ops::Range};

use bytemuck::AnyBitPattern;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bpf/tracer.skel.rs",
));

#[repr(C)]
#[derive(Debug, Clone, Copy, AnyBitPattern)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
}

impl From<Range<u64>> for MemoryRange {
    fn from(value: Range<u64>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

impl Into<Range<u64>> for MemoryRange {
    fn into(self) -> Range<u64> {
        Range {
            start: self.start,
            end: self.end,
        }
    }
}

pub type MemoryChangeKind = c_int;
pub const MEMORY_CHANGE_KIND_MAP: c_int = 1;
pub const MEMORY_CHANGE_KIND_REMAP: c_int = 1;
pub const MEMORY_CHANGE_KIND_UNMAP: c_int = 1;
pub const MEMORY_CHANGE_KIND_PAGE_OUT: c_int = 1;

pub type MemoryState = c_int;
pub const MEMORY_STATE_RESIDENT: c_int = 1;
pub const MEMORY_STATE_NOT_RESIDENT: c_int = 2;
pub const MEMORY_STATE_UNTRACKED: c_int = 3;

#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
pub struct MemoryChange {
    pub kind: MemoryChangeKind,
    pub payload: MemoryChangePayload,
}

#[repr(C)]
#[derive(Clone, Copy, AnyBitPattern)]
pub union MemoryChangePayload {
    pub map: MemoryChangeMap,
    pub remap: MemoryChangeRemap,
    pub unmap: MemoryChangeUnmap,
    pub page_out: MemoryChangePageOut,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, AnyBitPattern)]
pub struct MemoryChangeMap {
    pub range: MemoryRange,
    pub state: MemoryState,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, AnyBitPattern)]
pub struct MemoryChangeRemap {
    pub old_range: MemoryRange,
    pub new_range: MemoryRange,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, AnyBitPattern)]
pub struct MemoryChangeUnmap {
    pub range: MemoryRange,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, AnyBitPattern)]
pub struct MemoryChangePageOut {
    pub range: MemoryRange,
}
