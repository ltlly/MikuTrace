//! Compact owned and mmap-backed storage for MemShadow records and byte events.

use std::collections::{btree_map, BTreeMap, HashMap};
use std::io;
use std::ops::{Bound, Deref, DerefMut, RangeBounds};
use std::sync::Arc;

use memmap2::Mmap;

use crate::sidecar_io::invalid_data;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::CheckedBitPattern, bytemuck::NoUninit)]
pub enum ByteEventKind {
    Read = 0,
    Write = 1,
    External = 2,
}

impl ByteEventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "r",
            Self::Write => "w",
            Self::External => "x",
        }
    }

    pub fn is_write(self) -> bool {
        matches!(self, Self::Write | Self::External)
    }
}

impl PartialEq<&str> for ByteEventKind {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Eight-byte byte-level event. The trace index is checked before narrowing.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::CheckedBitPattern, bytemuck::NoUninit)]
pub struct ByteEvent {
    idx: u32,
    pub byte: u8,
    pub kind: ByteEventKind,
    reserved: u16,
}

const _: [(); 8] = [(); std::mem::size_of::<ByteEvent>()];

impl ByteEvent {
    pub fn try_new(idx: usize, byte: u8, kind: ByteEventKind) -> Option<Self> {
        Some(Self {
            idx: u32::try_from(idx).ok()?,
            byte,
            kind,
            reserved: 0,
        })
    }

    pub fn new(idx: usize, byte: u8, kind: ByteEventKind) -> Self {
        Self::try_new(idx, byte, kind).expect("trace record index exceeds compact u32 layout")
    }

    pub fn idx(&self) -> usize {
        self.idx as usize
    }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct EventList([ByteEvent]);

impl EventList {
    fn from_slice(events: &[ByteEvent]) -> &Self {
        // SAFETY: EventList is transparent over [ByteEvent], including metadata.
        unsafe { &*(std::ptr::from_ref(events) as *const Self) }
    }

    pub fn as_slice(&self) -> &[ByteEvent] {
        &self.0
    }
}

impl Deref for EventList {
    type Target = [ByteEvent];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<'a> IntoIterator for &'a EventList {
    type Item = &'a ByteEvent;
    type IntoIter = std::slice::Iter<'a, ByteEvent>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl PartialEq for EventList {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl Eq for EventList {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct AddressEntry {
    pub addr: u64,
    pub start: u64,
    pub len: u64,
}

#[derive(Debug, Clone)]
pub enum ByteEvents {
    Building(BTreeMap<u64, Vec<ByteEvent>>),
    Owned {
        addresses: Vec<AddressEntry>,
        events: Vec<ByteEvent>,
    },
    Mapped {
        map: Arc<Mmap>,
        addresses_offset: usize,
        addresses_len: usize,
        events_offset: usize,
        events_len: usize,
    },
}

pub type ByteEventsIter<'a> = Box<dyn Iterator<Item = (&'a u64, &'a EventList)> + 'a>;

impl Default for ByteEvents {
    fn default() -> Self {
        Self::Building(BTreeMap::new())
    }
}

impl From<BTreeMap<u64, Vec<ByteEvent>>> for ByteEvents {
    fn from(value: BTreeMap<u64, Vec<ByteEvent>>) -> Self {
        Self::Building(value)
    }
}

impl ByteEvents {
    pub fn finalize(&mut self) {
        let building = match std::mem::take(self) {
            Self::Building(building) => building,
            other => {
                *self = other;
                return;
            }
        };
        let event_count = building.values().map(Vec::len).sum();
        let mut addresses = Vec::with_capacity(building.len());
        let mut events = Vec::with_capacity(event_count);
        for (addr, mut list) in building {
            list.sort_by_key(ByteEvent::idx);
            let start = events.len();
            let len = list.len();
            events.append(&mut list);
            addresses.push(AddressEntry {
                addr,
                start: start as u64,
                len: len as u64,
            });
        }
        *self = Self::Owned { addresses, events };
    }

    pub fn entry(&mut self, addr: u64) -> btree_map::Entry<'_, u64, Vec<ByteEvent>> {
        match self {
            Self::Building(building) => building.entry(addr),
            _ => panic!("cannot mutate a finalized or mapped byte index"),
        }
    }

    pub fn values_mut(&mut self) -> btree_map::ValuesMut<'_, u64, Vec<ByteEvent>> {
        match self {
            Self::Building(building) => building.values_mut(),
            _ => panic!("cannot mutate a finalized or mapped byte index"),
        }
    }

    pub(crate) fn into_building(self) -> BTreeMap<u64, Vec<ByteEvent>> {
        match self {
            Self::Building(building) => building,
            _ => panic!("parallel partial must contain a mutable byte index"),
        }
    }

    pub fn get(&self, addr: &u64) -> Option<&EventList> {
        match self {
            Self::Building(building) => building
                .get(addr)
                .map(|events| EventList::from_slice(events)),
            _ => {
                let addresses = self.address_entries();
                let pos = addresses
                    .binary_search_by_key(addr, |entry| entry.addr)
                    .ok()?;
                let entry = &addresses[pos];
                Some(EventList::from_slice(self.events(entry)))
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Building(building) => building.len(),
            _ => self.address_entries().len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn event_count(&self) -> usize {
        match self {
            Self::Building(building) => building.values().map(Vec::len).sum(),
            Self::Owned { events, .. } => events.len(),
            Self::Mapped { events_len, .. } => *events_len,
        }
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped { .. })
    }

    pub fn mapped_bytes(&self) -> usize {
        match self {
            Self::Mapped { map, .. } => map.len(),
            _ => 0,
        }
    }

    pub fn heap_event_bytes(&self) -> usize {
        match self {
            Self::Building(building) => building
                .values()
                .map(|events| events.capacity() * std::mem::size_of::<ByteEvent>())
                .sum(),
            Self::Owned { events, .. } => events.capacity() * std::mem::size_of::<ByteEvent>(),
            Self::Mapped { .. } => 0,
        }
    }

    pub fn estimated_heap_bytes(&self) -> usize {
        let address_bytes = match self {
            Self::Building(building) => building.len().saturating_mul(96),
            Self::Owned { addresses, .. } => addresses.capacity().saturating_mul(24),
            Self::Mapped { .. } => 0,
        };
        address_bytes.saturating_add(self.heap_event_bytes())
    }

    pub fn estimated_heap_bytes_with_event_count(&self, event_count: usize) -> usize {
        match self {
            Self::Building(building) => building
                .len()
                .saturating_mul(96)
                .saturating_add(event_count.saturating_mul(32)),
            _ => self.estimated_heap_bytes(),
        }
    }

    pub fn iter(&self) -> ByteEventsIter<'_> {
        match self {
            Self::Building(building) => Box::new(
                building
                    .iter()
                    .map(|(addr, events)| (addr, EventList::from_slice(events))),
            ),
            _ => Box::new(
                self.address_entries()
                    .iter()
                    .map(move |entry| (&entry.addr, EventList::from_slice(self.events(entry)))),
            ),
        }
    }

    pub fn range<R>(&self, range: R) -> ByteEventsIter<'_>
    where
        R: RangeBounds<u64>,
    {
        match self {
            Self::Building(building) => Box::new(
                building
                    .range(range)
                    .map(|(addr, events)| (addr, EventList::from_slice(events))),
            ),
            _ => {
                let addresses = self.address_entries();
                let start = match range.start_bound() {
                    Bound::Included(addr) => addresses.partition_point(|entry| entry.addr < *addr),
                    Bound::Excluded(addr) => addresses.partition_point(|entry| entry.addr <= *addr),
                    Bound::Unbounded => 0,
                };
                let end = match range.end_bound() {
                    Bound::Included(addr) => addresses.partition_point(|entry| entry.addr <= *addr),
                    Bound::Excluded(addr) => addresses.partition_point(|entry| entry.addr < *addr),
                    Bound::Unbounded => addresses.len(),
                };
                Box::new(
                    addresses[start..end]
                        .iter()
                        .map(move |entry| (&entry.addr, EventList::from_slice(self.events(entry)))),
                )
            }
        }
    }

    pub fn keys(&self) -> Box<dyn Iterator<Item = &u64> + '_> {
        match self {
            Self::Building(building) => Box::new(building.keys()),
            _ => Box::new(self.address_entries().iter().map(|entry| &entry.addr)),
        }
    }

    pub(crate) fn finalized_parts(&self) -> Option<(&[AddressEntry], &[ByteEvent])> {
        match self {
            Self::Owned { addresses, events } => Some((addresses, events)),
            Self::Mapped { .. } => Some((self.address_entries(), self.events_slice())),
            Self::Building(_) => None,
        }
    }

    fn address_entries(&self) -> &[AddressEntry] {
        match self {
            Self::Owned { addresses, .. } => addresses,
            Self::Mapped {
                map,
                addresses_offset,
                addresses_len,
                ..
            } => bytemuck::cast_slice(
                &map[*addresses_offset..*addresses_offset + addresses_len * 24],
            ),
            Self::Building(_) => &[],
        }
    }

    fn events(&self, entry: &AddressEntry) -> &[ByteEvent] {
        let start = entry.start as usize;
        let end = start + entry.len as usize;
        &self.events_slice()[start..end]
    }

    fn events_slice(&self) -> &[ByteEvent] {
        match self {
            Self::Owned { events, .. } => events,
            Self::Mapped {
                map,
                events_offset,
                events_len,
                ..
            } => {
                let bytes = &map[*events_offset..*events_offset + events_len * 8];
                // SAFETY: from_mapped validates every event bit pattern and alignment;
                // the read-only mapping cannot change those values afterwards.
                unsafe {
                    std::slice::from_raw_parts(bytes.as_ptr().cast::<ByteEvent>(), *events_len)
                }
            }
            Self::Building(_) => &[],
        }
    }

    pub(crate) fn from_mapped(
        map: Arc<Mmap>,
        addresses_offset: usize,
        addresses_len: usize,
        events_offset: usize,
        events_len: usize,
        n_records: usize,
    ) -> io::Result<Self> {
        let address_bytes = map
            .get(addresses_offset..addresses_offset + addresses_len * 24)
            .ok_or_else(|| invalid_data("memshadow address section outside sidecar"))?;
        let addresses: &[AddressEntry] = bytemuck::try_cast_slice(address_bytes)
            .map_err(|_| invalid_data("misaligned memshadow address section"))?;
        let event_bytes = map
            .get(events_offset..events_offset + events_len * 8)
            .ok_or_else(|| invalid_data("memshadow event section outside sidecar"))?;
        let events: &[ByteEvent] = bytemuck::checked::try_cast_slice(event_bytes)
            .map_err(|_| invalid_data("invalid memshadow byte event"))?;
        if events.iter().any(|event| event.idx() >= n_records) {
            return Err(invalid_data(
                "memshadow sidecar byte event idx out of range",
            ));
        }
        let mut expected_start = 0usize;
        let mut previous_addr = None;
        for entry in addresses {
            if previous_addr.is_some_and(|addr| entry.addr <= addr) {
                return Err(invalid_data("memshadow addresses are not strictly sorted"));
            }
            if entry.len == 0 || entry.start as usize != expected_start {
                return Err(invalid_data("memshadow address ranges are not contiguous"));
            }
            let start = usize::try_from(entry.start)
                .map_err(|_| invalid_data("memshadow event offset overflow"))?;
            let len = usize::try_from(entry.len)
                .map_err(|_| invalid_data("memshadow event length overflow"))?;
            let end = start
                .checked_add(len)
                .filter(|end| *end <= events_len)
                .ok_or_else(|| invalid_data("memshadow address event range out of bounds"))?;
            if !events[start..end]
                .windows(2)
                .all(|pair| pair[0].idx <= pair[1].idx)
            {
                return Err(invalid_data("memshadow byte events are not idx sorted"));
            }
            expected_start = end;
            previous_addr = Some(entry.addr);
        }
        if expected_start != events_len {
            return Err(invalid_data(
                "memshadow events are not covered by addresses",
            ));
        }
        Ok(Self::Mapped {
            map,
            addresses_offset,
            addresses_len,
            events_offset,
            events_len,
        })
    }
}

impl<'a> IntoIterator for &'a ByteEvents {
    type Item = (&'a u64, &'a EventList);
    type IntoIter = ByteEventsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl PartialEq for ByteEvents {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl Eq for ByteEvents {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct MemRec {
    pub idx: usize,
    pub addr: u64,
    pub value: u64,
    pub size: u32,
    pub reserved: u32,
}

const _: [(); 32] = [(); std::mem::size_of::<MemRec>()];

#[derive(Debug, Clone)]
pub enum MemRecords {
    Owned(Vec<MemRec>),
    Mapped {
        map: Arc<Mmap>,
        offset: usize,
        len: usize,
    },
}

impl Default for MemRecords {
    fn default() -> Self {
        Self::Owned(Vec::new())
    }
}

impl From<Vec<MemRec>> for MemRecords {
    fn from(value: Vec<MemRec>) -> Self {
        Self::Owned(value)
    }
}

impl MemRecords {
    pub fn push(&mut self, rec: MemRec) {
        self.owned_mut().push(rec);
    }

    pub fn append(&mut self, other: &mut Self) {
        self.owned_mut().append(other.owned_mut());
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped { .. })
    }

    pub fn heap_bytes(&self) -> usize {
        match self {
            Self::Owned(records) => records.capacity().saturating_mul(32),
            Self::Mapped { .. } => 0,
        }
    }

    fn owned_mut(&mut self) -> &mut Vec<MemRec> {
        match self {
            Self::Owned(records) => records,
            Self::Mapped { .. } => panic!("cannot mutate mmap-backed memory records"),
        }
    }

    pub(crate) fn from_mapped(
        map: Arc<Mmap>,
        offset: usize,
        len: usize,
        n_records: usize,
    ) -> io::Result<Self> {
        let bytes = map
            .get(offset..offset + len * 32)
            .ok_or_else(|| invalid_data("memshadow record section outside sidecar"))?;
        let records: &[MemRec] = bytemuck::try_cast_slice(bytes)
            .map_err(|_| invalid_data("misaligned memshadow record section"))?;
        if records.iter().any(|rec| rec.idx >= n_records) {
            return Err(invalid_data("memshadow sidecar record idx out of range"));
        }
        if !records.windows(2).all(|pair| pair[0].idx <= pair[1].idx) {
            return Err(invalid_data("memshadow records are not idx sorted"));
        }
        Ok(Self::Mapped { map, offset, len })
    }

    fn as_slice(&self) -> &[MemRec] {
        match self {
            Self::Owned(records) => records,
            Self::Mapped { map, offset, len } => {
                bytemuck::cast_slice(&map[*offset..*offset + len * 32])
            }
        }
    }
}

impl Deref for MemRecords {
    type Target = [MemRec];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl DerefMut for MemRecords {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.owned_mut()
    }
}

impl<'a> IntoIterator for &'a MemRecords {
    type Item = &'a MemRec;
    type IntoIter = std::slice::Iter<'a, MemRec>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl PartialEq for MemRecords {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}
impl Eq for MemRecords {}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct CopySourceEntry {
    pub dst: u64,
    pub idx: u64,
    pub src: u64,
}

#[derive(Debug, Clone)]
pub enum CopySources {
    Building(HashMap<(u64, usize), u64>),
    Owned(Vec<CopySourceEntry>),
    Mapped {
        map: Arc<Mmap>,
        offset: usize,
        len: usize,
    },
}

impl Default for CopySources {
    fn default() -> Self {
        Self::Building(HashMap::new())
    }
}

impl From<HashMap<(u64, usize), u64>> for CopySources {
    fn from(value: HashMap<(u64, usize), u64>) -> Self {
        Self::Building(value)
    }
}

impl CopySources {
    pub fn finalize(&mut self) {
        let building = match std::mem::take(self) {
            Self::Building(building) => building,
            other => {
                *self = other;
                return;
            }
        };
        let mut entries = building
            .into_iter()
            .map(|((dst, idx), src)| CopySourceEntry {
                dst,
                idx: idx as u64,
                src,
            })
            .collect::<Vec<_>>();
        entries.sort_unstable_by_key(|entry| (entry.dst, entry.idx));
        *self = Self::Owned(entries);
    }

    pub fn insert(&mut self, key: (u64, usize), src: u64) {
        match self {
            Self::Building(building) => {
                building.insert(key, src);
            }
            _ => panic!("cannot mutate finalized or mapped copy sources"),
        }
    }

    pub fn get(&self, key: &(u64, usize)) -> Option<&u64> {
        match self {
            Self::Building(building) => building.get(key),
            _ => {
                let entries = self.as_entries();
                let pos = entries
                    .binary_search_by_key(&(key.0, key.1 as u64), |entry| (entry.dst, entry.idx))
                    .ok()?;
                Some(&entries[pos].src)
            }
        }
    }

    pub fn len(&self) -> usize {
        match self {
            Self::Building(building) => building.len(),
            Self::Owned(entries) => entries.len(),
            Self::Mapped { len, .. } => *len,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_mapped(&self) -> bool {
        matches!(self, Self::Mapped { .. })
    }

    pub fn is_finalized(&self) -> bool {
        !matches!(self, Self::Building(_))
    }

    pub fn heap_bytes(&self) -> usize {
        match self {
            Self::Building(building) => building.len().saturating_mul(64),
            Self::Owned(entries) => entries.capacity().saturating_mul(24),
            Self::Mapped { .. } => 0,
        }
    }

    pub fn iter(&self) -> Box<dyn Iterator<Item = (u64, usize, u64)> + '_> {
        match self {
            Self::Building(building) => {
                Box::new(building.iter().map(|(&(dst, idx), &src)| (dst, idx, src)))
            }
            _ => Box::new(
                self.as_entries()
                    .iter()
                    .map(|entry| (entry.dst, entry.idx as usize, entry.src)),
            ),
        }
    }

    fn as_entries(&self) -> &[CopySourceEntry] {
        match self {
            Self::Owned(entries) => entries,
            Self::Mapped { map, offset, len } => {
                bytemuck::cast_slice(&map[*offset..*offset + len * 24])
            }
            Self::Building(_) => &[],
        }
    }

    pub(crate) fn from_mapped(
        map: Arc<Mmap>,
        offset: usize,
        len: usize,
        n_records: usize,
    ) -> io::Result<Self> {
        let bytes = map
            .get(offset..offset + len * 24)
            .ok_or_else(|| invalid_data("memshadow copy section outside sidecar"))?;
        let entries: &[CopySourceEntry] = bytemuck::try_cast_slice(bytes)
            .map_err(|_| invalid_data("misaligned memshadow copy section"))?;
        if entries.iter().any(|entry| entry.idx as usize >= n_records) {
            return Err(invalid_data(
                "memshadow sidecar copy_source idx out of range",
            ));
        }
        if !entries
            .windows(2)
            .all(|pair| (pair[0].dst, pair[0].idx) < (pair[1].dst, pair[1].idx))
        {
            return Err(invalid_data(
                "memshadow copy sources are not strictly sorted",
            ));
        }
        Ok(Self::Mapped { map, offset, len })
    }
}

impl PartialEq for CopySources {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len()
            && self
                .iter()
                .all(|(dst, idx, src)| other.get(&(dst, idx)).copied() == Some(src))
    }
}
impl Eq for CopySources {}
