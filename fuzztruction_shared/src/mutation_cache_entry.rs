use llvm_stackmap::LLVMInstruction;
use memoffset::offset_of;

use crate::{mutation_cache::MutationCacheEntryFlags, types::MutationSiteID, util};
use std::{alloc, convert::TryInto};

const MAX_MASK_LEN: usize = 1024 * 1024 * 64;

#[repr(C)]
#[derive(Debug, PartialEq)]
pub struct MutationCacheEntryMetadata {
    /// A unique ID used to map mutation entries onto PatchPoint instances.
    /// We need this field, since the `vma` might differ between multiple
    /// fuzzer instances.
    id: MutationSiteID,
    llvm_instruction: LLVMInstruction,

    vma: u64,
    flags: u8,

    spill_slot: llvm_stackmap::Location,
    target_value_size_bits: u32,

    read_pos_bits: u32,
    /// The length of the mask stored at MutationCacheEntry.msk. If `loc_size` is > 0,
    /// the mask contains `loc_size` additional bytes that can be used in case the
    /// mutation stub `read_pos` overflows and reads more then msk_len bytes, in this case
    /// any following invocation will read these padding bytes that are not mutated (see agent.rs).
    msk_len: u32,
}

#[repr(C)]
pub struct MutationCacheEntry {
    pub metadata: MutationCacheEntryMetadata,
    /// The mask that is applied in chunks of size `loc_size` each time the mutated
    /// location is accessed. If `loc_size` > 0, then the mask is msk_len + loc_size bytes
    /// long, else it is msk_len bytes in size.
    pub msk: [u8; 0],
}

impl PartialEq for MutationCacheEntry {
    fn eq(&self, other: &Self) -> bool {
        self.metadata == other.metadata && self.get_msk_as_slice() == other.get_msk_as_slice()
    }
}

impl std::fmt::Debug for MutationCacheEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MutationCacheEntry")
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl MutationCacheEntry {
    pub fn new(
        id: MutationSiteID,
        llvm_instruction: LLVMInstruction,
        vma: u64,
        flags: u8,
        spill_slot: llvm_stackmap::Location,
        target_value_size_bits: u32,
        msk_len: u32,
    ) -> Box<MutationCacheEntry> {
        assert!(msk_len < MAX_MASK_LEN as u32);
        let target_value_size_byte = target_value_size_bits.div_ceil(8);

        // In case loc_size > 0, we pad the msk_len by loc_size bytes thus if the
        // mutation site is hit more often than anticipated, we can apply these
        // additional `loc_size` bytes as mask (which is always 0, since it does not belong to the mutated part of the mask)
        let mut padded_msk_len = msk_len as usize;

        // This is a DST, so we need to calculate the size.
        let mut alloc_size = std::mem::size_of::<MutationCacheEntry>() + msk_len as usize;

        // Add the padding explained above (also see jit gen_mutation_gpr).
        if msk_len > 0 {
            alloc_size += target_value_size_byte as usize;
            padded_msk_len += 8;
        }

        // Align to 8 byte, thus if stored consectively in memory the next struct is properly aligned.
        // This is not important for the Box allocated below, but later when we are managing our own
        // array of MutationCacheEntry's.
        alloc_size += 8 - (alloc_size % 8);
        let mut entry = util::alloc_box_aligned_zeroed::<MutationCacheEntry>(alloc_size);

        entry.metadata = MutationCacheEntryMetadata {
            id,
            llvm_instruction,
            vma,
            flags,
            spill_slot,
            target_value_size_bits,
            read_pos_bits: 0,
            msk_len,
        };

        // Initialize the msk to 0x00
        unsafe {
            std::ptr::write_bytes(
                entry.get_msk_as_ptr::<u8>(),
                0x00,
                padded_msk_len, // Also zero the padding.
            );
        }

        entry
    }

    pub fn layout() -> alloc::Layout {
        alloc::Layout::new::<MutationCacheEntry>()
    }

    pub fn clone_into_box(self: &MutationCacheEntry) -> Box<MutationCacheEntry> {
        let size = self.size();
        let mut entry: Box<MutationCacheEntry> = util::alloc_box_aligned_zeroed(size);

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.as_ptr() as *const u8,
                entry.as_mut_ptr() as *mut u8,
                size,
            );
        }

        entry
    }

    pub fn clone_with_new_msk(
        self: &MutationCacheEntry,
        new_msk_len: u32,
    ) -> Box<MutationCacheEntry> {
        assert!(
            new_msk_len <= MAX_MASK_LEN as u32 && new_msk_len > 0,
            "new_msk_len={}",
            new_msk_len
        );

        let mut new_size = std::mem::size_of_val(self) + new_msk_len as usize;

        // Padding for read overlow (see new())
        if new_msk_len > 0 {
            new_size += 8;
        }

        // Alignment
        new_size += 8 - (new_size % 8);

        // Zeroed memory
        let mut entry: Box<MutationCacheEntry> = util::alloc_box_aligned_zeroed(new_size);

        // Copy the metadata and mask of the old entry into the new one.
        let mut bytes_to_copy = self.size_wo_overflow_padding();
        if self.msk_len() > new_msk_len {
            // If we are shrinking the msk, do not copy all data from the old entry.
            bytes_to_copy -= (self.msk_len() - new_msk_len) as usize;
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.as_ptr() as *const u8,
                entry.as_mut_ptr() as *mut u8,
                bytes_to_copy,
            );
        }

        // Adapt metadata to changed values.
        entry.metadata.msk_len = new_msk_len;
        entry
    }

    /// Get the offset off the msk_len field.
    /// We do not want to make the msk_len field public, thus we need this method.
    pub fn offsetof_msk_len() -> usize {
        offset_of!(MutationCacheEntryMetadata, msk_len)
    }

    pub fn id(&self) -> MutationSiteID {
        self.metadata.id
    }

    /// The LLVM instruction this patch point targets.
    pub fn llvm_instruction(&self) -> LLVMInstruction {
        self.metadata.llvm_instruction
    }

    pub fn vma(&self) -> u64 {
        self.metadata.vma
    }

    pub fn spill_slot(&self) -> &llvm_stackmap::Location {
        &self.metadata.spill_slot
    }

    fn target_value_size_bit(&self) -> u32 {
        self.metadata.target_value_size_bits
    }

    fn target_value_size_byte(&self) -> u32 {
        self.target_value_size_bit().div_ceil(8)
    }

    pub fn msk_len(&self) -> u32 {
        self.metadata.msk_len
    }

    pub fn enable_tracing(&mut self) -> &mut Self {
        self.set_flag(MutationCacheEntryFlags::TracingEnabled)
    }

    pub fn disable_tracing(&mut self) -> &mut Self {
        self.unset_flag(MutationCacheEntryFlags::TracingEnabled)
    }

    pub fn enable(&mut self) -> &mut Self {
        self.unset_flag(MutationCacheEntryFlags::Disable)
    }

    pub fn disable(&mut self) -> &mut Self {
        self.set_flag(MutationCacheEntryFlags::Disable)
    }

    pub fn enabled(&self) -> bool {
        !self.is_flag_set(MutationCacheEntryFlags::Disable)
    }

    pub fn set_flag(&mut self, flag: MutationCacheEntryFlags) -> &mut Self {
        self.metadata.flags |= flag as u8;
        self
    }

    pub fn flags(&self) -> u8 {
        self.metadata.flags
    }

    pub fn set_flags(&mut self, val: u8) {
        self.metadata.flags = val;
    }

    pub fn unset_flag(&mut self, flag: MutationCacheEntryFlags) -> &mut Self {
        self.metadata.flags &= !(flag as u8);
        self
    }

    pub fn reset_flags(&mut self) -> &mut Self {
        self.metadata.flags = MutationCacheEntryFlags::None as u8;
        self
    }

    pub fn is_flag_set(&self, flag: MutationCacheEntryFlags) -> bool {
        (self.metadata.flags & flag as u8) > 0
    }

    /// The size in bytes of the whole entry. Cloning a MutationCacheEntry requires
    /// to copy .size() bytes from a pointer of type MutationCacheEntry.
    pub fn size(&self) -> usize {
        let mut ret = self.size_wo_overflow_padding();
        if self.msk_len() > 0 {
            // The msk is padded with an additional element which is used in case
            // read_pos overflows.
            ret += self.target_value_size_byte() as usize;
        }

        // Size is always a multiple of 8 to guarantee proper alignment
        ret += 8 - (ret % 8);

        ret
    }

    fn size_wo_overflow_padding(&self) -> usize {
        std::mem::size_of::<MutationCacheEntryMetadata>() + self.msk_len() as usize
    }

    pub fn as_ptr(&self) -> *const MutationCacheEntry {
        self as *const MutationCacheEntry
    }

    pub fn as_mut_ptr(&mut self) -> *mut MutationCacheEntry {
        self as *mut MutationCacheEntry
    }

    // This is actually undefined behavior :)
    #[allow(invalid_reference_casting)]
    pub unsafe fn alias_mut(&self) -> &mut MutationCacheEntry {
        let ptr = self as *const MutationCacheEntry as *mut MutationCacheEntry;
        &mut *ptr
    }

    pub fn get_msk_as_ptr<T>(&self) -> *mut T {
        self.msk.as_ptr() as *mut T
    }

    pub fn get_msk_as_slice(&self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut(self.get_msk_as_ptr(), self.metadata.msk_len as usize)
        }
    }

    pub fn get_padding_as_slice(&self) -> Option<&[u8]> {
        if self.msk_len() > 0 {
            // The msk is padded with an additional element which is used in case
            // read_pos overflows.
            unsafe {
                let ret = std::slice::from_raw_parts_mut(
                    self.get_msk_as_ptr::<u8>()
                        .offset(self.metadata.msk_len as isize),
                    self.target_value_size_byte() as usize,
                );
                Some(ret)
            }
        } else {
            None
        }
    }

    pub fn is_nop(&self) -> bool {
        let msk = self.get_msk_as_slice();
        if msk.is_empty() {
            return true;
        }
        msk.iter().all(|v| *v == 0)
    }

    pub fn chunk_size_bits(&self) -> u16 {
        match self.llvm_instruction() {
            LLVMInstruction::Br => {
                let ret = self.target_value_size_bit().try_into().unwrap();
                assert!(ret == 1);
                ret
            }
            LLVMInstruction::Load
            | LLVMInstruction::Store
            | LLVMInstruction::InjectedCall
            | LLVMInstruction::CustomPatchPoint => self.target_value_size_bit().try_into().unwrap(),
            LLVMInstruction::Switch => self.target_value_size_bit().try_into().unwrap(),
            LLVMInstruction::Select => self.target_value_size_bit().try_into().unwrap(),
            LLVMInstruction::ICmp => self.target_value_size_bit().try_into().unwrap(),
            LLVMInstruction::Call => {
                let ret = self.target_value_size_bit().try_into().unwrap();
                assert!(ret == 1);
                ret
            }
            _ => {
                todo!("{:#?}", self.llvm_instruction())
            }
        }
    }

    pub fn chunk_size_bytes(&self) -> u16 {
        let chunk_size_bits = self.chunk_size_bits();
        if chunk_size_bits % 8 > 0 {
            (chunk_size_bits / 8) + 1
        } else {
            chunk_size_bits / 8
        }
    }

    pub fn read_pos_bits(&self) -> u32 {
        self.metadata.read_pos_bits
    }

    pub fn read_pos_bits_offset() -> usize {
        let offset = offset_of!(MutationCacheEntry, metadata);
        // Just so that we know that this was changed.
        debug_assert_eq!(offset, 0);

        offset + offset_of!(MutationCacheEntryMetadata, read_pos_bits)
    }

    pub fn msk_start_offset() -> usize {
        offset_of!(MutationCacheEntry, msk)
    }
}
