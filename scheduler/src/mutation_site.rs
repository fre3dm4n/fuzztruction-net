use std::{
    assert_matches::assert_matches,
    convert::TryInto,
    fs::{self, OpenOptions},
    ops::Range,
    path::Path,
};

use fuzztruction_shared::{
    constants::PATCH_POINT_SIZE, mutation_cache::MutationCacheEntryFlags,
    mutation_cache_entry::MutationCacheEntry, types::MutationSiteID,
};

use llvm_stackmap::{LLVMInstruction, LocationType};
use proc_maps::{self, MapRange};

use crate::llvm_stackmap::{Location, StackMap};

use serde::{Deserialize, Serialize};

/// See /usr/include/llvm/IR/Instruction.def for further more IDs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum LLVMIns {
    Br = 2,
    Switch = 3,
    IndirectBr = 4,
    ICmp = 53,
    Select = 57,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct MutationSite {
    /// A unique ID that identifies this MutationSite.
    id: MutationSiteID,
    /// The VMA of the function that contains this MutationSite.
    function_address: u64,
    /// The VMA base if this mutation site belongs to binary that is position independent.
    base: u64,
    /// The VMA of this mutation site. If this belongs to a PIC binary, `address`
    /// is only an offset relative to `base`.
    address: u64,
    /// The LLVM instruction targeted by this mutation site.
    llvm_instruction: LLVMInstruction,
    /// The stack slot the to be mutated value is spilled into.
    spill_slot: Location,
    /// The location of the value that was spilled into the `spill_slot`.
    /// This is used to determine the values size, because the spill slot is
    /// located on the stack and therefore has a size that is a multiple of 8 (on 64bit).
    target_value_size_in_bit: u32,
    /// The memory mapping this mutation site belongs to.
    mapping: MapRange,
}

impl MutationSite {
    pub fn new(
        base: u64,
        address: u64,
        llvm_id: u64,
        spill_slot: Location,
        target_value_size_in_bit: u32,
        mapping: MapRange,
        function_address: u64,
    ) -> Self {
        assert!(address + base > 0);

        // For now we only support a single recorded location per patch point.
        MutationSite {
            id: MutationSiteID::get(address as usize, mapping.inode, mapping.offset),
            address,
            llvm_instruction: llvm_id.try_into().unwrap(),
            spill_slot,
            target_value_size_in_bit,
            base,
            mapping,
            function_address,
        }
    }

    pub fn id(&self) -> MutationSiteID {
        self.id
    }

    pub fn llvm_ins(&self) -> LLVMInstruction {
        self.llvm_instruction
    }

    pub fn mapping(&self) -> &MapRange {
        &self.mapping
    }

    pub fn function_address(&self) -> u64 {
        self.function_address
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn vma(&self) -> u64 {
        self.base + self.address
    }

    pub fn vma_range(&self) -> Range<u64> {
        self.vma()..(self.vma() + PATCH_POINT_SIZE as u64)
    }

    pub fn spill_slot(&self) -> &Location {
        &self.spill_slot
    }

    pub fn target_value_size_bit(&self) -> u32 {
        self.target_value_size_in_bit
    }

    /// # Safety
    /// This is used for testing only.
    pub unsafe fn set_target_value_size_in_bits(&mut self, val: u32) {
        self.target_value_size_in_bit = val;
    }

    pub fn target_value_size_byte(&self) -> u32 {
        self.target_value_size_bit().div_ceil(8)
    }

    pub fn into_mutation_cache_entry(&self) -> Box<MutationCacheEntry> {
        self.into()
    }

    pub fn load(path: &Path) -> Vec<MutationSite> {
        let file = OpenOptions::new().read(true).open(path).unwrap();
        serde_json::from_reader(file).unwrap()
    }

    pub fn dump(path: &Path, patch_points: &[MutationSite]) {
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .unwrap();
        serde_json::to_writer(file, patch_points).unwrap();
    }
}

pub fn from_stackmap(
    map: &StackMap,
    mapping: &MapRange,
    elf_file: &elf::ElfBytes<elf::endian::AnyEndian>,
) -> Vec<MutationSite> {
    let mut idx: usize = 0;
    let mut patch_points = Vec::new();

    // If it is PIC, the base is the start address of the mapping.
    // If not, the addresses in the stackmap are absolute.
    assert!(matches!(
        elf_file.ehdr.e_type,
        elf::abi::ET_DYN | elf::abi::ET_EXEC
    ));
    let is_pic = elf_file.ehdr.e_type == elf::abi::ET_DYN;
    let base = is_pic.then(|| mapping.start()).unwrap_or(0) as u64;

    //let mut seen_vmas = HashSet::new();

    for function in &map.stk_size_records {
        assert!(function.function_address > 0);
        let records = &map.stk_map_records[idx..(idx + function.record_count as usize)];
        records.iter().for_each(|record| {
            if record.locations.is_empty() {
                log::warn!("StkMapRecord without recorded locations");
            }
            let locations = &record.locations;
            assert_eq!(locations.len(), 2);

            // Order is defined by the order we pushed these as argument for the
            // patch point intrinsic.
            let spill_slot_location = &locations[0];
            assert_matches!(
                spill_slot_location.loc_type,
                LocationType::Register | LocationType::Direct
            );

            assert!(locations[1].loc_type == LocationType::Constant);
            let target_value_size = locations[1].offset_or_constant;
            // The size of the recorded value must be positive.
            assert!(target_value_size > 0);

            let mut vma =
                (function.function_address as usize + record.instruction_offset as usize) as u64;
            // Rebased function address
            let mut function_address = base + function.function_address;

            if is_pic {
                vma -= mapping.offset as u64;
                function_address -= mapping.offset as u64;

                // Sanity check
                let absolute_vma = vma + mapping.start() as u64;
                assert!(
                    (mapping.start() as u64 + mapping.size() as u64) > absolute_vma,
                    "vma 0x{:x} is too big for mapping {:#?}! record={:#?}",
                    absolute_vma,
                    mapping,
                    record
                );
            }

            let pp = MutationSite::new(
                base,
                vma,
                record.patch_point_id,
                *spill_slot_location,
                target_value_size.try_into().unwrap(),
                mapping.clone(),
                function_address,
            );

            // if !seen_vmas.insert(pp.vma()) {
            //     let other = patch_points.iter().find(|p: &&PatchPoint| p.vma() == pp.vma()).unwrap();
            //     panic!("Duplicated VMA A={:#?}\nB={:#?}", pp, other);
            // }
            patch_points.push(pp);
        });
        idx += function.record_count as usize;
    }

    patch_points
}

pub fn elf_is_pic(path: impl AsRef<Path>) -> Option<bool> {
    let data = fs::read(path).unwrap();
    let file = match elf::ElfBytes::<elf::endian::AnyEndian>::minimal_parse(&data) {
        Ok(f) => f,
        Err(_) => panic!("File not found"),
    };
    Some(file.ehdr.e_type == elf::abi::ET_DYN)
}

impl From<&MutationSite> for Box<MutationCacheEntry> {
    fn from(pp: &MutationSite) -> Self {
        MutationCacheEntry::new(
            pp.id(),
            pp.llvm_ins(),
            pp.vma(),
            MutationCacheEntryFlags::None as u8,
            *pp.spill_slot(),
            pp.target_value_size_bit(),
            0,
        )
    }
}
