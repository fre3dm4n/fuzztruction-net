use crate::mem::MappedMemoryConfig;
use core::panic;
use fuzztruction_shared::abi;
use fuzztruction_shared::constants::PATCH_POINT_SIZE;
use fuzztruction_shared::dwarf::DwarfReg;
use fuzztruction_shared::mutation_cache_entry::MutationCacheEntry;
use fuzztruction_shared::types::VAddr;
use keystone::{Arch, Keystone, OptionType};
use llvm_stackmap::LocationType;
use proc_maps::MapRange;
use std::collections::HashSet;
use std::fmt::Debug;

use std::str::FromStr;
use std::sync::Mutex;

use libc;
use std::{collections::HashMap, slice};

use super::util;
use crate::agent::{update_proc_mappings, PROC_MAPPINGS};
use anyhow::{anyhow, Result};
use lazy_static::lazy_static;

macro_rules! MiB {
    ($val:literal) => {
        (1024 * 1024 * ($val))
    };
}

const DEFAULT_CODE_CACHE_SIZE: usize = MiB!(64);
const NOP_PATTERN: &[u8; 32] = b"\x66\x66\x66\x66\x66\x2e\x66\x0f\x1f\x84\x00\x00\x02\x00\x00\x66\x66\x66\x66\x66\x2e\x66\x0f\x1f\x84\x00\x00\x02\x00\x00\x66\x90";

#[derive(Debug, Clone, Copy)]
/// An argument that is passed to a function.
pub enum FunctionArg {
    Constant(u64),
    Register(DwarfReg),
}

#[derive(Debug)]
pub enum JitError {
    UnsupportedMutation(String),
}

#[derive(Debug)]
struct PatchableLocation {
    addr: *mut u8,
    size: usize,
    reset_value: [u8; PATCH_POINT_SIZE],
}

impl PatchableLocation {
    pub fn new(addr: VAddr, size: usize) -> PatchableLocation {
        debug_assert!(size == PATCH_POINT_SIZE);
        PatchableLocation {
            addr: addr.0 as *mut u8,
            size,
            reset_value: [0; PATCH_POINT_SIZE],
        }
    }

    pub fn reset(&mut self) {
        unsafe {
            std::ptr::copy_nonoverlapping(
                self.reset_value.as_ptr() as *mut u8,
                self.addr,
                self.size,
            );
        }
    }

    pub fn copy_default_from_addr(&mut self) -> Result<()> {
        unsafe {
            if !util::is_readable_mem_range(self.addr, self.size) {
                let msg = format!(
                    "Target memory range is not readable. vma=0x{:x}",
                    self.addr as u64
                );
                return Err(anyhow!(msg));
            }

            std::ptr::copy_nonoverlapping(
                self.addr,
                self.reset_value.as_ptr() as *mut u8,
                self.size,
            );
        }
        Ok(())
    }
}

/// Provides an allocator to allocate RWX memory slots that can be used to store
/// jitted code.
struct CodeCache<'a> {
    /// The memory allocation that is used to serve all allocation requests.
    buffer: *mut libc::c_void,
    /// The size of `buffer` in bytes.
    size: usize,
    /// The slice that contains all unallocated bytes of buffer.
    unallocated: &'a mut [u8],
}

impl<'a> CodeCache<'a> {
    pub fn new(size: usize) -> CodeCache<'a> {
        let buffer = unsafe {
            libc::mmap(
                0 as *mut libc::c_void,
                size,
                libc::PROT_EXEC | libc::PROT_READ,
                libc::MAP_ANONYMOUS | libc::MAP_SHARED,
                0,
                0,
            )
        };
        assert!(buffer != libc::MAP_FAILED);
        update_proc_mappings();

        let unallocated = unsafe { slice::from_raw_parts_mut::<u8>(buffer as *mut u8, size) };

        CodeCache {
            buffer,
            size: size,
            unallocated,
        }
    }

    /// Allocate a memory slot with length `len`. The returned slice is safe to use
    /// until self is dropped or `reset()` is called.
    pub fn allocate_slot<'b>(&'b mut self, len: usize) -> Option<&'b mut [u8]> {
        Jit::mark_enclosing_mapping_rwx(self.buffer as *const u8).unwrap();

        if self.unallocated.len() < len {
            return None;
        }

        let tmp = std::mem::replace(&mut self.unallocated, &mut []);
        let split: (&'b mut [u8], &'a mut [u8]) = tmp.split_at_mut(len);
        self.unallocated = split.1;

        Some(split.0)
    }

    pub fn make_rx(&mut self) {
        Jit::mark_enclosing_mapping_rx(self.buffer as *const u8).unwrap();
    }

    /// Reset the CodeCache by discarding all allocations made so far.
    /// Safety: This is unsafe, if there is any references alive that was
    /// handed out by allocate_slot().
    pub unsafe fn reset(&mut self) {
        Jit::mark_enclosing_mapping_rwx(self.buffer as *const u8).unwrap();
        self.unallocated = slice::from_raw_parts_mut::<u8>(self.buffer as *mut u8, self.size);
        self.unallocated.fill(0x00);
        Jit::mark_enclosing_mapping_rx(self.buffer as *const u8).unwrap();
    }
}

impl<'a> Drop for CodeCache<'a> {
    fn drop(&mut self) {
        let ret = unsafe { libc::munmap(self.buffer as *mut libc::c_void, self.size) };
        assert!(ret == 0, "Failed to unmap code cache");
    }
}

/// A object that can be called via call and will return via ret.
pub trait CallableFunction: Debug {
    fn args(&self) -> u64;

    fn vma(&self) -> VAddr;

    fn is_dead(&self) -> bool {
        return false;
    }
}

/// A native function that is part of the application.
#[derive(Debug, Clone, Copy)]
pub struct NativeFunction {
    pub vma: VAddr,
    pub nargs: u64,
}

impl NativeFunction {
    pub fn from_fn(function_addr: usize, nargs: u64) -> NativeFunction {
        NativeFunction {
            vma: VAddr(function_addr as u64),
            nargs,
        }
    }

    pub fn to_box(&self) -> Box<NativeFunction> {
        Box::new(*self)
    }
}

impl CallableFunction for NativeFunction {
    fn args(&self) -> u64 {
        self.nargs
    }

    fn vma(&self) -> VAddr {
        self.vma
    }
}

#[allow(unused)]
#[derive(Debug)]
pub struct FunctionInstance {
    asm: Vec<String>,
    /// Number of arguments this function expects.
    //arg_cnt: u8,
    /// The machinecode that was produced by assembling the FunctionTemplate.
    machine_code: Vec<u8>,
    vma: Option<VAddr>,
}

impl FunctionInstance {
    pub fn from_assembled_template(asm: Vec<String>, machine_code: Vec<u8>) -> FunctionInstance {
        FunctionInstance {
            asm,
            machine_code: machine_code,
            vma: None,
        }
    }

    pub fn len(&self) -> usize {
        return self.machine_code.len();
    }

    pub unsafe fn write_safe(&mut self, dst: &mut [u8]) {
        assert!(self.machine_code.len() > 0);
        self.vma = Some((dst.as_ptr() as u64).into());

        //eprintln!("write_safe: {:#?}", self);

        dst[0..self.machine_code.len()].copy_from_slice(&self.machine_code)
    }

    pub unsafe fn write(&mut self, dst_addr: VAddr) {
        assert!(
            self.machine_code.len() <= PATCH_POINT_SIZE,
            "len={}\nasm={:#?}",
            self.machine_code.len(),
            self
        );
        assert!(self.machine_code.len() > 0);

        let patchpoint_byte = slice::from_raw_parts(dst_addr.0 as *mut u8, 32);
        assert_eq!(NOP_PATTERN, patchpoint_byte);

        self.vma = Some(dst_addr);
        std::ptr::copy_nonoverlapping(
            [0x90; PATCH_POINT_SIZE].as_ptr(),
            dst_addr.0 as *mut u8,
            PATCH_POINT_SIZE,
        );
        std::ptr::copy_nonoverlapping(
            self.machine_code.as_ptr(),
            dst_addr.0 as *mut u8,
            self.machine_code.len(),
        );
    }
}

impl CallableFunction for FunctionInstance {
    fn args(&self) -> u64 {
        // No args support for now.
        0
    }

    fn vma(&self) -> VAddr {
        self.vma.unwrap()
    }
}

// Our CC:
// - If a function trashes a reg, it is responsible to back it up
// - At a call instruction, all regs. except R11 must have the same values
//   as when the caller was called.

#[derive(Debug)]
pub struct FunctionTemplate {
    /// The assembler code this function is made of.
    asm_body: Vec<String>,
    /// Does this function return or is it inlined?
    returns: bool,
}

//asm_body, is_callee
lazy_static! {
    static ref GEN_CALL_CACHE: Mutex<HashSet<Vec<String>>> = Mutex::new(HashSet::new());
}

impl FunctionTemplate {
    pub fn new(asm_body: Vec<String>, returns: bool) -> FunctionTemplate {
        FunctionTemplate {
            asm_body: asm_body,
            returns,
        }
    }

    fn assemble(self, ks: &Keystone) -> Option<(Vec<String>, Vec<u8>)> {
        let mut asm = self.asm_body;

        if self.returns {
            asm.push("ret".to_owned());
        }

        // Assemble
        let asm_str = asm.join("\n");
        //log::trace!("Assembling asm:\n{}", asm_str);

        //eprintln!("Assembling:\n-----\n{}\n-----", &asm_str);
        let res = ks.asm(asm_str, 0);
        if let Ok(bytes) = &res {
            let mut hex = String::from_str("asm_result:\n").unwrap();
            for byte in &bytes.bytes {
                hex.push_str(&format!("\\x{:x}", byte));
            }
            //log::trace!("{}", hex);
        }

        match res {
            Err(e) => {
                log::error!("Error while assembling {}", e);
                None
            }
            Ok(e) => {
                //eprintln!("{:#?}", e);
                Some((asm, e.bytes.clone()))
            }
        }
    }

    // Put into code cache or write to location (e.g., patch point)
}

pub struct Jit<'a> {
    code_cache: CodeCache<'a>,
    keystone_engine: Keystone,
    registered_patch_points: HashMap<VAddr, PatchableLocation>,
}

impl<'a> Jit<'a> {
    pub fn new() -> Jit<'a> {
        let keystone_engine = Keystone::new(Arch::X86, keystone::Mode::MODE_64).unwrap();

        keystone_engine
            .option(OptionType::SYNTAX, keystone::OptionValue::SYNTAX_NASM)
            .unwrap();

        let code_cache = CodeCache::new(DEFAULT_CODE_CACHE_SIZE);
        Jit {
            code_cache,
            keystone_engine,
            registered_patch_points: HashMap::new(),
        }
    }

    /// Must be called for each patch point before it gets modified the first time.
    /// This function make a copy of the patch point that is used during reset()
    /// to restore the original state of the binary.
    pub fn snapshot_patch_point(&mut self, mce: &MutationCacheEntry) {
        let addr = mce.vma().into();
        let value = self.registered_patch_points.get(&addr);
        if value.is_none() {
            let mut value = PatchableLocation::new(addr.clone(), PATCH_POINT_SIZE);
            if let Err(e) = value.copy_default_from_addr() {
                log::error!(
                    "Failed to snapshot patchpoint at address 0x{:x}. mce={:#?} err={}",
                    addr.0,
                    mce,
                    e
                );
                panic!("Failed to snapshot patchpoint!");
            }
            self.registered_patch_points.insert(addr, value);
        }
    }

    fn get_enclosing_mapping(addr: *const u8) -> Option<MapRange> {
        let mappings_guard = PROC_MAPPINGS.lock().unwrap();
        let mappings = mappings_guard.as_ref().unwrap();
        for m in mappings {
            let addr = addr as usize;
            let start = m.start();
            let end = m.start() + m.size();
            if addr >= start && addr < end {
                return Some(m.clone());
            }
        }
        None
    }

    /// Mark the mapping containing `addr` as RWX.
    pub fn mark_enclosing_mapping_rwx(addr: *const u8) -> Result<()> {
        let mapping = Jit::get_enclosing_mapping(addr);
        if mapping.is_none() {
            return Err(anyhow!("Failed to get mapping for addr {:?}", addr));
        }

        let mapping = mapping.unwrap();
        if !mapping.is_write() {
            let start = mapping.start();
            let size = mapping.size();
            MappedMemoryConfig::new(start as usize, size)
                .reset()
                .read(true)
                .write(true)
                .exec(true)
                .commit()
                .unwrap();
            update_proc_mappings();
        }

        Ok(())
    }

    /// Mark the mapping containing `addr` as RX.
    pub fn mark_enclosing_mapping_rx(addr: *const u8) -> Result<()> {
        let mapping = Jit::get_enclosing_mapping(addr);
        if mapping.is_none() {
            return Err(anyhow!("Failed to get mapping for addr {:?}", addr));
        }

        let mapping = mapping.unwrap();
        if mapping.is_write() {
            let start = mapping.start();
            let size = mapping.size();
            MappedMemoryConfig::new(start as usize, size)
                .reset()
                .read(true)
                .write(false)
                .exec(true)
                .commit()
                .unwrap();
            update_proc_mappings();
        }

        Ok(())
    }

    /// Mark all code generated by the JIT as RX.
    pub fn mark_mappings_rx(&mut self) {
        self.code_cache.make_rx();
    }

    /// Restore the state of the binary as if no modifications have been ever applied.
    pub fn reset(&mut self) {
        self.registered_patch_points.values_mut().for_each(|e| {
            Jit::mark_enclosing_mapping_rwx(e.addr as *const u8).unwrap();
            e.reset();
        });

        self.registered_patch_points.values().for_each(|e| {
            Jit::mark_enclosing_mapping_rx(e.addr as *const u8).unwrap();
        });

        self.registered_patch_points.clear();
        // Make sure we are not forking pages that we do not need!
        self.registered_patch_points.shrink_to(0);

        // Reset code cache allocations.
        // Safety: We resetted all patch points (x.reset()) above, thus there are
        // no dangeling pointers into the caches memory.
        unsafe {
            self.code_cache.reset();
        }
    }

    /// Assemble the passed `template` while leaving the task to the caller to
    /// place it in its final memory location via `write_*`.
    pub fn assemble(&self, template: FunctionTemplate) -> Option<FunctionInstance> {
        let machine_code = template.assemble(&self.keystone_engine);
        let machine_code = machine_code.unwrap();

        let ret = FunctionInstance::from_assembled_template(machine_code.0, machine_code.1);
        Some(ret)
    }

    /// Assembles the passed `template` into an allocated memory slot.
    pub fn allocate(&mut self, template: FunctionTemplate) -> Option<FunctionInstance> {
        let instance = self.assemble(template);
        if let Some(mut instance) = instance {
            let slot = self.code_cache.allocate_slot(instance.len()).unwrap();
            unsafe {
                instance.write_safe(slot);
            }
            return Some(instance);
        }
        log::error!("Allocator is OOM");
        None
    }

    /// Generate a stub that consecutively calls all functions listed in `target_fns`.
    /// If the called functions trash any registers, they are responsible of
    /// backing them up.
    pub fn gen_call_multiplexer(
        &self,
        target_fns: Vec<&impl CallableFunction>,
    ) -> FunctionTemplate {
        assert!(target_fns.len() > 0);
        let mut asm_body = Vec::new();

        for f in target_fns.iter() {
            asm_body.extend_from_slice(&[
                "push rax".to_owned(),
                format!("mov rax, 0x{:x}", f.vma().0),
                "push rax".to_owned(),
                "mov rax, [rsp+8]".to_owned(),
                "call [rsp]".to_owned(),
                "add rsp, 0x10".to_owned(),
            ]);
        }

        let template = FunctionTemplate::new(asm_body, true);
        template
    }

    /// Generates a stub that calls a function located at `to` and
    /// passing the `args` arguments according to the AMD64 ABI.
    pub fn gen_call(
        &self,
        to: &impl CallableFunction,
        args: Vec<FunctionArg>,
        returns: bool,
        trashed_regs: Option<Vec<DwarfReg>>,
    ) -> FunctionTemplate {
        let mut asm_body = Vec::new();
        let mut abi_args_order = abi::ARGUMENT_PASSING_ORDER.iter();

        let mut trashed_regs = trashed_regs.unwrap_or(Vec::new());

        // Parse args to the called function, if any.
        for arg in args {
            match arg {
                FunctionArg::Constant(c) => {
                    let reg = abi_args_order
                        .next()
                        .expect("Ran out of registers for passing arguments");
                    trashed_regs.push(*reg);
                    let reg = reg.name();
                    asm_body.push(format!("movabs {}, 0x{:x}", reg, c));
                }
                _ => todo!("Passing registers is currently not supported!"),
            }
        }

        for reg in trashed_regs.iter() {
            // Insert prologe at the start of this function (idx 0).
            asm_body.insert(0, format!("push {}", reg.name()));
        }

        asm_body.extend_from_slice(&[
            "nop".to_owned(),
            "nop".to_owned(),
            "nop".to_owned(),
            "nop".to_owned(),
            "push rax".to_owned(),
            format!("mov rax, 0x{:x}", to.vma().0),
            "push rax".to_owned(),
            "mov rax, [rsp+8]".to_owned(),
            "call [rsp]".to_owned(),
            "add rsp, 0x10".to_owned(),
        ]);

        // Restore the trashed registers after the call returns.
        for reg in trashed_regs.iter() {
            asm_body.push(format!("pop {}", reg.name()));
        }

        FunctionTemplate::new(asm_body, returns)
    }

    /// Generate a mutation stub for a `MutationCacheEntry` that
    /// mutates a stack slot.
    fn gen_mutation_reg_and_direct(
        &self,
        mce: &MutationCacheEntry,
    ) -> Result<FunctionTemplate, JitError> {
        let mut asm = Vec::<String>::new();
        let spill_reg: DwarfReg = mce.spill_slot().dwarf_regnum.try_into().unwrap();
        assert_ne!(
            spill_reg,
            DwarfReg::Rsp,
            "RSP is changed in our caller, so this is currently not supported"
        );

        // Number of bits read each time this mutation is executed.
        let chunk_size_bits = mce.chunk_size_bits();
        let mut chunk_size_bytes_ceiled = chunk_size_bits.div_ceil(8);

        if chunk_size_bits > (8 * 8) {
            return Err(JitError::UnsupportedMutation(format!(
                "Chunks with size > 8 byte are currently not supported {:#?}",
                mce
            )));
        }

        // if we read more than 1 bit and the amount is not byte aligned we are reading
        // one extra byte to account for chunks spanning two bytes.
        // If we have reached the end of the mask, this will probably over read,
        //  but the mask's trailing memory is guarded by our read overflow area.
        // (see fuzztruction_shared/src/mutation_cache_entry.rs:79)
        if chunk_size_bits != 1 && chunk_size_bits % 8 != 0 {
            chunk_size_bytes_ceiled += 1;
            assert!(chunk_size_bytes_ceiled.div_ceil(8) <= 8);
        }

        // Make it match register sizes
        let chunk_size_bytes_ceiled = chunk_size_bytes_ceiled.next_power_of_two();
        assert!(chunk_size_bytes_ceiled <= 8);

        // Pointer to the spilled value
        let spill_slot_ptr_reg = DwarfReg::try_from(mce.spill_slot().dwarf_regnum).unwrap();

        // Scratch registers
        asm.push(format!("push rax"));
        asm.push(format!("push rbx"));
        asm.push(format!("push rcx"));
        asm.push(format!("push rdx"));
        asm.push(format!("push r11"));

        // Make sure we backup the stack slot pointer, since this could also be one
        // of the registers above (that we are going to clobber).
        asm.push(format!("push {}", spill_slot_ptr_reg.name()));

        // rax = &MutationCacheEntry
        asm.push(format!(
            "mov rax, 0x{:x}",
            mce as *const MutationCacheEntry as u64
        ));

        // rbx = read_pos_bits
        asm.push(format!(
            "mov ebx, [rax + 0x{:x}]",
            MutationCacheEntry::read_pos_bits_offset()
        ));

        // rdx = read_pos_bits
        asm.push(format!("mov rdx, rbx"));

        // rdx = read_pos_bits // 8
        asm.push(format!("shr rdx, 3"));

        // rcx = read_pos_bits
        asm.push(format!("mov rcx, rbx"));

        // rcx = read_pos_bits % 8
        asm.push(format!("and rcx, 0x7"));

        // Load the mask value into stack slot
        let msk_value_reg = DwarfReg::R11;
        //asm.push(format!("mov {}, 0x0", msk_value_reg.name()));

        let msk_value_reg_str = msk_value_reg
            .name_with_size(chunk_size_bytes_ceiled as u8)
            .unwrap();

        // read chunk_size many bits
        // msk_value_reg = msk_value
        asm.push(format!(
            "mov {}, {} [rax + rdx + 0x{:x}]",
            msk_value_reg_str,
            DwarfReg::mem_ptr_prefix(chunk_size_bytes_ceiled as usize),
            MutationCacheEntry::msk_start_offset()
        ));

        // Shift out bits that were already read
        asm.push(format!("shr {}, cl", msk_value_reg.name()));

        // Load the reg of the spill slot
        asm.push(format!("mov rdx, [rsp]"));

        if mce.spill_slot().loc_type == LocationType::Direct {
            let offset = mce.spill_slot().offset_or_constant;
            if offset > 0 {
                asm.push(format!("add rdx, 0x{:x}", offset));
            } else if offset < 0 {
                asm.push(format!("sub rdx, 0x{:x}", offset * -1));
            }
        }

        match chunk_size_bits {
            v if v % 8 == 0 => {
                asm.push(format!("xor [rdx], {}", msk_value_reg_str));
            }
            v => {
                asm.push(format!(
                    "and {}, 0x{:x}",
                    msk_value_reg_str,
                    (1u32 << v) - 1
                ));
                asm.push(format!("xor [rdx], {}", msk_value_reg_str));
            }
        }

        // Current register content
        // rax = mce base,
        // ebx = read_pos
        // rcx = free
        // rdx = free

        // increment read_pos
        asm.push(format!("add ebx, 0x{:x}", chunk_size_bits));

        // rcx = msk_len
        asm.push(format!(
            "mov ecx, [rax + 0x{:x}]",
            MutationCacheEntry::offsetof_msk_len(),
        ));

        // rcx = msk_len * 8
        asm.push(format!("shl ecx, 3"));

        // cmp read_pos_bits, msk_len_bits
        asm.push(format!("cmp ebx, ecx"));

        // set read_pos = msk_len if (read_pos > msk_len)
        asm.push(format!("cmova ebx, ecx"));

        // Update the read_pos in the struct
        asm.push(format!(
            "mov dword [rax + 0x{:x}], ebx",
            MutationCacheEntry::read_pos_bits_offset()
        ));

        asm.push(format!("pop {}", spill_slot_ptr_reg.name()));
        asm.push(format!("pop r11"));
        asm.push(format!("pop rdx"));
        asm.push(format!("pop rcx"));
        asm.push(format!("pop rbx"));
        asm.push(format!("pop rax"));

        //log::trace!("Target: {:#?}\nASM:\n{}", mce, asm.join("\n"));
        Ok(FunctionTemplate::new(asm, true))
    }

    /// Generate an assembler template that implements everything necessary to apply the mutations to the values in the `mce`.`
    pub fn gen_mutation(&self, mce: &MutationCacheEntry) -> Result<FunctionTemplate, JitError> {
        assert!(mce.msk_len() > 0);
        match mce.spill_slot().loc_type {
            LocationType::Register | LocationType::Direct => {
                return self.gen_mutation_reg_and_direct(mce);
            }
            _ => Err(JitError::UnsupportedMutation(format!(
                "Unsupported location type: {:#?}",
                mce
            ))),
        }
    }
}
