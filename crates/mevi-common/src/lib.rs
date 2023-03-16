use std::{fmt, ops::Range, sync::mpsc};

use humansize::{make_format, BINARY};
use rangemap::RangeMap;
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum MemState {
    Resident,
    NotResident,
    Untracked,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct TraceeId(pub u64);

impl fmt::Display for TraceeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}]", self.0)
    }
}

#[cfg(feature = "nix")]
impl From<nix::unistd::Pid> for TraceeId {
    fn from(pid: nix::unistd::Pid) -> Self {
        Self(pid.as_raw() as _)
    }
}

#[cfg(feature = "nix")]
impl From<TraceeId> for nix::unistd::Pid {
    fn from(id: TraceeId) -> Self {
        Self::from_raw(id.0 as _)
    }
}

pub type MemMap = RangeMap<u64, MemState>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum MeviEvent {
    Snapshot(Vec<TraceeSnapshot>),
    TraceeEvent(TraceeId, TraceePayload),
}

pub fn serialize_many(events: &[MeviEvent]) -> postcard::Result<Vec<u8>> {
    postcard::to_allocvec(events)
}

pub fn deserialize_many(data: &[u8]) -> postcard::Result<Vec<MeviEvent>> {
    postcard::from_bytes(data)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceeSnapshot {
    pub tid: TraceeId,
    pub cmdline: Vec<String>,
    pub map: MemMap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TraceePayload {
    Map {
        range: Range<u64>,
        state: MemState,
        _guard: MapGuard,
    },
    Connected {
        source: ConnectSource,
        uffd: u64,
    },
    Execve,
    MemStateChange {
        range: Range<u64>,
        state: MemState,
    },
    Unmap {
        range: Range<u64>,
    },
    Remap {
        old_range: Range<u64>,
        new_range: Range<u64>,
        _guard: MapGuard,
    },
    CmdLineChange {
        cmdline: Vec<String>,
    },
    Exit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnectSource {
    Uds,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MapGuard {
    #[serde(skip)]
    _inner: Option<mpsc::Sender<()>>,
}

// Safety: the non-Sync `mpsc::Sender` inside of `MapGuard` is never accessed.
unsafe impl Sync for MapGuard {}

impl MapGuard {
    pub fn new(tx: mpsc::Sender<()>) -> Self {
        Self { _inner: Some(tx) }
    }
}

impl Clone for MapGuard {
    fn clone(&self) -> Self {
        Self { _inner: None }
    }
}

impl TraceePayload {
    pub fn apply_to_memmap(&self, map: &mut MemMap) {
        match self {
            TraceePayload::Map { range, state, .. } => {
                map.insert(range.clone(), *state);
            }
            TraceePayload::Connected { .. } => {
                // do nothing
            }
            TraceePayload::Execve => {
                // all the mappings are invalidated on exec
                map.clear();
            }
            TraceePayload::MemStateChange { range, state } => {
                map.insert(range.clone(), *state);
            }
            TraceePayload::Unmap { range } => {
                if range.start >= range.end {
                    panic!("unmap range is invalid: {range:x?}");
                }
                map.remove(range.clone());
            }
            TraceePayload::Remap {
                old_range,
                new_range,
                _guard,
            } => {
                let formatter = make_format(BINARY);

                if old_range.start == new_range.start {
                    // we either grew in place or shrunk in place

                    // if we shrunk, unmap the extra pages
                    if new_range.end < old_range.end {
                        info!(
                            "remap: range shrunk by {}, now is {:x?}",
                            formatter((old_range.end - new_range.end) as _),
                            new_range,
                        );
                        map.remove(new_range.end..old_range.end);
                    }

                    // if we grew, mark the new pages as not resident
                    if new_range.end > old_range.end {
                        let new_pages = old_range.end..new_range.end;
                        info!(
                            "remap: range grew by {}, now is {:x?}. marking {new_pages:x?} as not resident",
                            formatter((new_range.end - old_range.end) as _),
                            new_range
                        );
                        map.insert(new_pages, MemState::NotResident);
                    }
                } else {
                    // the new range is elsewhere - we need to copy the state
                    let mut merge_state = MemMap::default();
                    // by default everything is non-resident
                    merge_state.insert(new_range.clone(), MemState::NotResident);

                    // now copy over old state
                    for (old_subrange, old_state) in map.overlapping(old_range) {
                        let mut subrange_old = old_subrange.clone();
                        // clamp to old range (in case it "spilled" left or right outside of the old range)
                        if subrange_old.start < old_range.start {
                            subrange_old.start = old_range.start;
                        }
                        if subrange_old.end > old_range.end {
                            subrange_old.end = old_range.end;
                        }

                        let mut subrange_new = subrange_old.clone();

                        // remap to new range
                        if new_range.start < old_range.start {
                            // new range is to the left of old range
                            let diff = old_range.start.checked_sub(new_range.start).unwrap();
                            subrange_new.start -= diff;
                            subrange_new.end -= diff;
                        } else {
                            // new range is to the right of old range (or didn't move)
                            let diff = new_range.start.checked_sub(old_range.start).unwrap();
                            subrange_new.start += diff;
                            subrange_new.end += diff;
                        }

                        // clamp to new range (in case we shrunk)
                        if subrange_new.start < new_range.start {
                            subrange_new.start = new_range.start;
                        }
                        if subrange_new.end > new_range.end {
                            subrange_new.end = new_range.end;
                        }

                        if subrange_new.start < subrange_new.end {
                            tracing::debug!(
                                "remap: {:x?} ({}) => {:x?} ({}) = {:?}",
                                subrange_old,
                                formatter(subrange_old.end - subrange_old.start),
                                subrange_new,
                                formatter(subrange_new.end - subrange_new.start),
                                old_state
                            );
                            merge_state.insert(subrange_new, *old_state);
                        } else {
                            // this can happen if we shrunk, just ignore that update
                        }
                    }

                    // now remove old range
                    map.remove(old_range.clone());

                    // and merge in the new state
                    for (subrange, state) in merge_state.into_iter() {
                        map.insert(subrange, state);
                    }
                }
            }
            TraceePayload::CmdLineChange { .. } => {
                // do nothing
            }
            TraceePayload::Exit { .. } => {
                // do nothing
            }
        }
    }
}
