#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

#include "llvm/IR/Instruction.h"
#include "llvm/IR/GlobalValue.h"

#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"

#include "llvm/IR/Intrinsics.h"

#include "llvm/Transforms/Utils.h"
#include <algorithm>
#include <assert.h>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constant.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/PassInstrumentation.h>
#include <llvm/IR/Use.h>
#include <llvm/IR/Value.h>
#include <llvm/IR/Attributes.h>

#include <llvm/Support/Casting.h>
#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/ValueMapper.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/IRReader/IRReader.h>

#include <llvm/IR/GlobalValue.h>

#include <cstdint>
#include <cstdlib>

#include <random>
#include <utility>
#include <vector>

#include "config.hpp"

//#include "fuzztruction-preprocessing-pass.hpp"

using namespace llvm;

namespace {

    class FuzztructionSourcePass : public PassInfoMixin<FuzztructionSourcePass> {
    private:
        std::set<Value *> instrumented_values;

    public:
        static bool allow_ptr_ty;
        static bool allow_vec_ty;

        enum InsTy {Random = 0, Load = 1, Store = 2, Add = 3, Sub = 4, Icmp = 5, Select = 6, Branch = 7, Switch = 8, Call = 9};
        static std::string insTyNames[10];

        bool initializeFuzzingStub(Module &M);
        bool injectPatchPoints(Module &M);
        std::vector<Value *> getPatchpointArgs(Module &M, uint32_t id);
        bool instrumentInsArg(Module &M, Function *stackmap_intr, Instruction *ins, uint8_t op_idx);
        bool instrumentCall(Module &M, Function *stackmap_intr, CallInst *ins);
        bool instrumentInsOutput(Module &M, Function *stackmap_intr, Instruction *ins);
        bool maybeDeleteFunctionCall(Module &M, CallInst *call_ins, std::set<std::string> &target_functions);
        bool filterInvalidPatchPoints(Module &M);
        bool replaceMemFunctions(Module &M);
        bool instrumentFunctionEntry(Function &F, Function *stackmap_intr);
        bool instrumentCustomPatchPoints(Module &M, Function *stackmap_intr);

        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
    };


}

/*
Specify instruction types, which we want to instrument with probability p
*/
struct InsHook {
    FuzztructionSourcePass::InsTy type;
    uint8_t probability;

    std::string to_string() {
        return "InsHook{ ins_ty=" + FuzztructionSourcePass::insTyNames[type] +
                ", probability=" + std::to_string(probability) + "% }";
    }
};

inline bool operator<(const InsHook& lhs, const InsHook& rhs)
{
  return lhs.type < rhs.type;
}


PreservedAnalyses FuzztructionSourcePass::run(Module &M, ModuleAnalysisManager &MAM) {

    bool module_modified = false;

    module_modified |= injectPatchPoints(M);
    module_modified |= filterInvalidPatchPoints(M);
    module_modified |= initializeFuzzingStub(M);

    if (module_modified) {
        return PreservedAnalyses::none();
    } else {
        return PreservedAnalyses::all();
    }
}


/*
Split a string containing multiple comma-separated keywords
and return the set of these keywords
*/
std::vector<std::string> split_string(std::string s, char delim) {
    size_t pos_start = 0, pos_end;
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find (delim, pos_start)) != std::string::npos) {
        token = s.substr (pos_start, pos_end - pos_start);
        pos_start = pos_end + 1;
        res.push_back(token);
    }

    res.push_back(s.substr (pos_start));
    return res;
}

/*
Check if an environment variable is set.
*/
bool env_var_set(const char* env_var) {
    const char* envp = std::getenv(env_var);
    if (envp)
        return true;
    return false;
}


/*
Convert environment variable content to a set.
Expects comma-separated list of values in the env var.
*/
std::vector<std::string> parse_env_var_list(const char* env_var) {
    const char* envp = std::getenv(env_var);
    if (!envp)
        return std::vector<std::string> ();
    return split_string(std::string(envp), /* delim = */ ',');
}


/*
Extract integer specified in environment variable.
*/
uint32_t parse_env_var_int(const char* env_var, uint32_t default_val) {
    const char* envp = std::getenv(env_var);
    if (!envp)
        return default_val;
    uint32_t val = (uint32_t)std::stol(envp);
    return val;
}


/*
Convert set of strings to known instruction types. Ignores unknown elements.
*/
FuzztructionSourcePass::InsTy to_InsTy(std::string input) {
    if (input == "random")
        return FuzztructionSourcePass::InsTy::Random;
    if (input == "load")
        return FuzztructionSourcePass::InsTy::Load;
    if (input == "store")
        return FuzztructionSourcePass::InsTy::Store;
    if (input == "add")
        return FuzztructionSourcePass::InsTy::Add;
    if (input == "sub")
        return FuzztructionSourcePass::InsTy::Sub;
    if (input == "icmp")
        return FuzztructionSourcePass::InsTy::Icmp;
    if (input == "select")
        return FuzztructionSourcePass::InsTy::Select;
    if (input == "branch")
        return FuzztructionSourcePass::InsTy::Branch;
    if (input == "switch")
        return FuzztructionSourcePass::InsTy::Switch;
    if (input == "call")
        return FuzztructionSourcePass::InsTy::Call;

    errs() << "Unsupported instruction string received: " << input << "\n";
    exit(1);
}


/*
Convert a string of format "name:probability" to InsHook struct.
*/
InsHook to_InsHook(std::string s) {
    int pos = s.find_first_of(':');
    if (pos == std::string::npos)
        return {to_InsTy(s), 100};
    std::string name = s.substr(0, pos);
    uint32_t prob = std::stol(s.substr(pos + 1));
    assert(prob <= 100 && "Probability must be in range [0, 100]");
    return {to_InsTy(name), (uint8_t)prob};
}


bool FuzztructionSourcePass::initializeFuzzingStub(Module &M) {
    /*
    Used to initialize our fuzzing stub. We can not use the llvm constructor attribute because
    our stub relies on keystone which has static constructors that are executed after functions
    marked by the constructor attribute. Hence, we can not use keystone at that point in time.
    */
    auto init_hook_fn = M.getOrInsertFunction("__ft_auto_init", FunctionType::getVoidTy(M.getContext()));

    auto main_fn = M.getFunction("main");
    if (main_fn) {
        IRBuilder<> ins_builder(main_fn->getEntryBlock().getFirstNonPHI());
        ins_builder.CreateCall(init_hook_fn);
    }

    // Insert a call to __ft_after_listen after the 'listen' function returns.
    auto listen_hook_fn = M.getOrInsertFunction("__ft_after_listen", FunctionType::getVoidTy(M.getContext()));
    auto listen_fn = M.getFunction("listen");
    if (listen_fn && listen_fn->arg_size() == 2) {
        // check if arg types match those of the type of listen function we are interested in.
        auto first_arg = listen_fn->getArg(0);
        auto second_arg = listen_fn->getArg(1);
        if (first_arg->getType()->isIntegerTy() && second_arg->getType()->isIntegerTy()) {
            for (const auto& user : listen_fn->users()) {
                if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
                    dbgs() << *call_ins << "\n";
                    IRBuilder<> ins_builder(call_ins->getNextNode());
                    ins_builder.CreateCall(listen_hook_fn);
                }
            }
        }
    }

    // Insert a call to __ft_after_bind after the 'bind' function returns.
    auto bind_hook_fn = M.getOrInsertFunction("__ft_after_bind", FunctionType::getVoidTy(M.getContext()));
    auto bind_fn = M.getFunction("bind");
    if (bind_fn && bind_fn->arg_size() == 3) {
        for (const auto& user : bind_fn->users()) {
            if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
                dbgs() << *call_ins << "\n";
                IRBuilder<> ins_builder(call_ins->getNextNode());
                ins_builder.CreateCall(bind_hook_fn);
            }
        }
    }

    auto connect_hook_fn = M.getOrInsertFunction("__ft_after_connect", FunctionType::getVoidTy(M.getContext()));
    auto connect_fn = M.getFunction("connect");
    if (connect_fn && connect_fn->arg_size() == 3) {
        for (const auto& user : connect_fn->users()) {
            if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
                dbgs() << "patching connect call: " << *call_ins << "\n";
                IRBuilder<> ins_builder(call_ins->getNextNode());
                ins_builder.CreateCall(connect_hook_fn);
            }
        }
    }

    return true;
}


/*
Delete call if one of the functions specified by name is called
*/
bool FuzztructionSourcePass::maybeDeleteFunctionCall(Module &M, CallInst *call_ins, std::set<std::string> &target_functions) {
    Function *callee = call_ins->getCalledFunction();
    // skip indirect calls
    if (!callee) {
        return false;
    }
    // if called function should be deleted, erase it from IR
    if (target_functions.count(callee->getName().str())) {
        // if the callee expects a ret value, we cannot simply replace the function
        // TODO: we could determine type and replace Inst with Value
        if (!call_ins->getCalledFunction()->getReturnType()->isVoidTy()) {
            errs() << "Cannot delete " << callee->getName() << " as it returns\n";
            return false;
        }
        dbgs() << "deleteFunctionCalls(): Deleting call to " << callee->getName() << "\n";
        call_ins->eraseFromParent();
        return true;
    }
    return false;
}


/*
Get vector of default patchpoint arguments we need for every patchpoint.
ID is set depending on which type of instruction is instrumented.
*/
std::vector<Value *> FuzztructionSourcePass::getPatchpointArgs(Module &M, uint32_t id) {
    IntegerType *i64_type = IntegerType::getInt64Ty(M.getContext());
    IntegerType *i32_type = IntegerType::getInt32Ty(M.getContext());
    IntegerType *i8_type = IntegerType::getInt8Ty(M.getContext());

    std::vector<Value *> patchpoint_args;

    /* The ID of this patch point */
    Constant *c = ConstantInt::get(i64_type, id);
    // Constant *id = ConstantInt::get(i64_type, 0xcafebabe);
    patchpoint_args.push_back(c);

    /* Set the shadown length in bytes */
    Constant *shadow_len = ConstantInt::get(i32_type, FT_PATCH_POINT_SIZE);
    patchpoint_args.push_back(shadow_len);

    /*The function we are calling */
    auto null_ptr = ConstantPointerNull::get(PointerType::get(i8_type, 0));
    //Constant *fnptr = ConstantInt::get(i32_type, 1);
    //auto null_ptr = ConstantExpr::getIntToPtr(fnptr, PointerType::get(i8_type, 0));
    patchpoint_args.push_back(null_ptr);

    /*
    The number of args that should be considered as function arguments.
    Reaming arguments are the live values for which the location will be
    recorded.
     */
    Constant *argcnt = ConstantInt::get(i32_type, 0);
    patchpoint_args.push_back(argcnt);

    return patchpoint_args;
}


uint64_t get_alloction_size_in_bits(AllocaInst *ins, Value *target) {
    if (target->getType()->isIntegerTy()) {
        return target->getType()->getIntegerBitWidth();
    } else {
        return *ins->getAllocationSizeInBits(ins->getModule()->getDataLayout());
    }
}


bool FuzztructionSourcePass::instrumentCustomPatchPoints(Module &M, Function *stackmap_intr) {
    auto custom_patch_points_enables = env_var_set("FT_CUSTOM_PATCH_POINTS");

    std::vector<User*> users;
    auto ft_get_byte_fn = M.getOrInsertFunction("__ft_get_byte", FunctionType::getInt8Ty(M.getContext()));
    for (auto user : ft_get_byte_fn.getCallee()->users()) {
        users.push_back(user);
    }

    for (auto user : users) {
        if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
            dbgs() << "User: " << *call_ins << "\n";
            if (custom_patch_points_enables) {
                dbgs() << "Injecting cutstom patch point\n";
                IRBuilder<> irb(&*call_ins);
                auto slot_type = IntegerType::getInt8Ty(M.getContext());

                auto *slot = irb.CreateAlloca(slot_type);
                irb.CreateStore(ConstantInt::get(slot_type, 0), slot);
                std::vector<Value *> patchpoint_args = getPatchpointArgs(M, 1338);
                patchpoint_args.push_back(slot);
                patchpoint_args.push_back(irb.getInt64(8));
                irb.CreateCall(stackmap_intr, patchpoint_args);
                auto mutated_ins = irb.CreateLoad(slot_type, slot);
                call_ins->replaceAllUsesWith(mutated_ins);
            } else {
                call_ins->replaceAllUsesWith(ConstantInt::get(IntegerType::getInt8Ty(M.getContext()), 0));
            }
            call_ins->eraseFromParent();
        }
    }

    return true;
}


bool FuzztructionSourcePass::instrumentFunctionEntry(Function &instrumented_function, Function *stackmap_intr) {
    auto call_injection_enabled = env_var_set("FT_CALL_INJECTION");
    if (!call_injection_enabled || instrumented_function.isVarArg()) {
        return false;
    }

    if (instrumented_function.empty())
        return false;

    if (instrumented_function.getName().starts_with("__ft")) {
        return false;
    }

    std::vector<Value *> instrumented_function_args;
    for (auto &arg: instrumented_function.args()) {
        instrumented_function_args.push_back(&arg);
    }

    std::vector<Constant *> potential_targets;
    auto module = instrumented_function.getParent();
    for (auto &f: module->functions()) {
        bool skip = false;
        if (&f == &instrumented_function) {
            continue;
        }

        if (f.getName().starts_with("__ft")) {
            continue;
        }

        if (f.arg_size() != instrumented_function.arg_size()) {
            continue;
        }

        if (f.getReturnType() != instrumented_function.getReturnType()) {
            continue;
        }

        if (f.isIntrinsic()) {
            continue;
        }

        for (int i = 0; i < f.arg_size(); i++) {
            if ( f.getArg(i)->getType() != instrumented_function.getArg(i)->getType()) {
                skip = true;
                break;
            }
        }
        if (skip) {
            continue;
        }

        potential_targets.push_back(&f);
    }

    if (potential_targets.empty()) {
        return false;
    }

    dbgs() << "Found: " << potential_targets.size() << " potential targets\n";

    // We can use 7 bits -> 128 values and need the 0 to encode the nop-action.
    // 128 -1 = 127 possible call targets.
    if (potential_targets.size() > 127) {
        potential_targets.resize(127);
    }

    // total number of bits needed to make a decision
    // +1 is the bit used to determine whether to skip execution of `instrumented_function`.
    auto potential_target_encoding_bits_needed = (int) std::ceil(std::log2(potential_targets.size())) + 1;
    assert(potential_target_encoding_bits_needed <= 8);

    auto potential_target_encoding_select_fn_msk = (1 << (potential_target_encoding_bits_needed - 1)) - 1;
    auto potential_target_encoding_skip_fn_msk = 1 << (potential_target_encoding_bits_needed - 1);

    auto array_type = llvm::ArrayType::get(instrumented_function.getType(), potential_targets.size());
    llvm::Constant* array = llvm::ConstantArray::get(array_type, potential_targets);

    // Create a unique name for the global constant
    std::string global_name = "call_injection_array_" + std::to_string(rand());

    // Create the global variable
    auto global_var = new llvm::GlobalVariable(*module, array_type, true, llvm::GlobalValue::PrivateLinkage, array, global_name);

    // Get byte from patch point
    std::vector<Value *> patchpoint_args = getPatchpointArgs(*module, 1337);

    auto insertion_point = instrumented_function.getEntryBlock().getFirstInsertionPt();
    IRBuilder<> irb(&*insertion_point);

    auto &context = module->getContext();
    auto slot_type = IntegerType::getInt8Ty(context);

    auto *slot = irb.CreateAlloca(slot_type);
    irb.CreateStore(ConstantInt::get(slot_type, 0), slot);

    patchpoint_args.push_back(slot);
    patchpoint_args.push_back(irb.getInt64(potential_target_encoding_bits_needed));
    irb.CreateCall(stackmap_intr, patchpoint_args);

    auto slot_value = irb.CreateLoad(slot_type, slot);
    auto slot_value_is_not_zero = irb.CreateICmpNE(slot_value, ConstantInt::get(slot_type, 0));

    auto *function_call_block = llvm::SplitBlockAndInsertIfThen(slot_value_is_not_zero, &*insertion_point, false);
    irb.SetInsertPoint(function_call_block);

    // mask out the high bit
    auto selected_index_masked = irb.CreateAnd(slot_value, ConstantInt::get(slot_type, potential_target_encoding_select_fn_msk));
    auto selected_index_unbound = irb.CreateSub(selected_index_masked, ConstantInt::get(slot_type, 1));
    auto selected_index = irb.CreateURem(selected_index_unbound, ConstantInt::get(slot_type, potential_targets.size()));

    auto target_fn_ptr_ptr = irb.CreateInBoundsGEP(instrumented_function.getType(), global_var, {selected_index});
    auto target_fn_ptr = irb.CreateLoad(instrumented_function.getType(), target_fn_ptr_ptr);

    // call the function that we injected
    auto injected_fn_ret = irb.CreateCall(instrumented_function.getFunctionType(), target_fn_ptr, instrumented_function_args);

    // get the highest bit of the byte retrived from the patch point.
    auto high_bit_set = irb.CreateAnd(slot_value, ConstantInt::get(slot_type, potential_target_encoding_skip_fn_msk));
    auto skip_instrumented_function = irb.CreateICmpNE(high_bit_set, ConstantInt::get(slot_type, 0));

    // called if the current function should be skipped
    auto *skip_function_block = llvm::SplitBlockAndInsertIfThen(skip_instrumented_function, &*function_call_block, true);
    irb.SetInsertPoint(skip_function_block);

    if (instrumented_function.getFunctionType()->getReturnType()->isVoidTy()) {
        irb.CreateRetVoid();
    } else {
        irb.CreateRet(injected_fn_ret);
    }

    // the unreachable
    skip_function_block->getParent()->getTerminator()->eraseFromParent();

    return true;
}


/*
Instrument the output value of the instruction. In other words, the value produced by the instruction
is the live value fed into the patchpoint.
*/
bool FuzztructionSourcePass::instrumentInsOutput(Module &M, Function *stackmap_intr, Instruction *ins) {
    auto parent_fn = ins->getParent()->getParent();
    auto insertion_point = parent_fn->getEntryBlock().getFirstInsertionPt();
    IRBuilder<> irb(&*insertion_point);
    auto *slot = irb.CreateAlloca(ins->getType());

    // dbgs() << "instrumentInsOutput called\n";
    Instruction *next_ins = ins;
    /* In case of a load the patchpoint is inserted after the load was executed */
    if (ins)
        next_ins = ins->getNextNode();
    if (!next_ins)
        return false;

    if (this->instrumented_values.count(ins) > 0) {
        return false;
    } else {
        this->instrumented_values.insert(ins);
    }

    irb.SetInsertPoint(next_ins);
    std::vector<Value *> patchpoint_args = getPatchpointArgs(M, ins->getOpcode());

    std::vector<User *> users;
    for (auto user: ins->users()) {
        users.push_back(user);
    }

    // Store on stack
    irb.CreateStore(ins, slot);

    patchpoint_args.push_back(slot);
    patchpoint_args.push_back(irb.getInt64(get_alloction_size_in_bits(slot, ins)));
    irb.CreateCall(stackmap_intr, patchpoint_args);

    auto mutated_ins = irb.CreateLoad(ins->getType(), slot);
    for (auto user : users) {
        // if (CallInst* call_ins = dyn_cast<CallInst>(user)){
        //     if (call_ins->getFunction() == stackmap_intr) {
        //         continue;
        //     }
        // }
        user->replaceUsesOfWith(ins, mutated_ins);
    }

    return true;
}


/*
Instrument (one of) the input value(s) to the instruction (as specified by operand index).
This input value is the live value connected to the patchpoint, where it can be modified before being
processed by the instruction.
*/
bool FuzztructionSourcePass::instrumentInsArg(Module &M, Function *stackmap_intr, Instruction *ins, uint8_t op_idx) {
    if (!ins)
        return false;

    auto op = ins->getOperand(op_idx);

    if (this->instrumented_values.count(op) > 0) {
        return false;
    } else {
        this->instrumented_values.insert(op);
    }

    auto parent_fn = ins->getParent()->getParent();
    auto insertion_point = parent_fn->getEntryBlock().getFirstInsertionPt();
    IRBuilder<> irb(&*insertion_point);
    auto *slot = irb.CreateAlloca(op->getType());

    irb.SetInsertPoint(ins);
    std::vector<Value *> patchpoint_args = getPatchpointArgs(M, ins->getOpcode());

    irb.CreateStore(op, slot);

    // record stack slot
    patchpoint_args.push_back(slot);
    patchpoint_args.push_back(irb.getInt64(get_alloction_size_in_bits(slot, op)));
    irb.CreateCall(stackmap_intr, patchpoint_args);

    // Load from stack
    auto mutated_op = irb.CreateLoad(op->getType(), slot);

    // Use the patched value instead of the original one.
    ins->setOperand(op_idx, mutated_op);

    return true;
}

bool FuzztructionSourcePass::instrumentCall(Module &M, Function *stackmap_intr, CallInst *call) {
    if (!call->user_empty())
        return false;

    if (this->instrumented_values.count(call) > 0) {
        return false;
    } else {
        this->instrumented_values.insert(call);
    }

    auto parent_fn = call->getParent()->getParent();
    auto insertion_point = parent_fn->getEntryBlock().getFirstInsertionPt();
    IRBuilder<> irb(&*insertion_point);
    auto *condition = irb.CreateAlloca(irb.getInt1Ty());

    std::vector<Value *> patchpoint_args = getPatchpointArgs(M, call->getOpcode());
    irb.SetInsertPoint(call);
    // by default always take the call ins
    irb.CreateStore(irb.getInt1(true), condition);

    // record stack slot
    patchpoint_args.push_back(condition);
    patchpoint_args.push_back(irb.getInt64(1));
    irb.CreateCall(stackmap_intr, patchpoint_args);

    // Load from stack
    auto mutated_condition = irb.CreateLoad(irb.getInt1Ty(), condition);

    auto *new_block = llvm::SplitBlockAndInsertIfThen(mutated_condition, call, false);
    call->moveBefore(new_block);

    return true;
}



bool isValidTy(Type* ty) {
    if (ty->isIntegerTy())
        return true;
    if (FuzztructionSourcePass::allow_ptr_ty && ty->isPointerTy())
        return true;
    if (FuzztructionSourcePass::allow_vec_ty && ty->isVectorTy())
        return true;
    return false;
}

/*
Check whether it is reasonable to instrument the given instruction.
Ensure that
1) at least one user exists (else the value will never be used)
2) we support the type (integer, vec, and ptr types currently)
3) we exclude "weird" instructions (e.g., debug instructions, phi nodes etc)
*/
bool canBeInstrumented(Instruction *ins) {
    // ignore instructions that are never used
    if (ins->users().begin() == ins->users().end())
        return false;
    // ignore non-integer type instructions
    if (!isValidTy(ins->getType()))
        return false;
    if (ins->isKnownSentinel())
        return false;
    if (ins->isCast())
        return false;
    // if (ins->isDebugOrPseudoInst())
    //     return false;
#if LLVM_VERSION_MAJOR <= 17
    if (ins->isExceptionalTerminator())
        return false;
#else
    if (ins->isSpecialTerminator())
        return false;
#endif
    if (ins->isLifetimeStartOrEnd())
        return false;
    if (ins->isEHPad())
        return false;
    if (ins->isFenceLike())
        return false;
    if (ins->isSwiftError())
        return false;
    if (ins->getOpcode() == Instruction::PHI)
        return false;
    return true;
}


/*
Instrument all instructions and delete function calls specified by the user via environment variables.

User can specify instruction types ("load", "store"), for which we want to insert a patchpoint
as well as function names ("abort"), for which we erase any call to (if possible).
Function names are specified in FT_NOP_FN=abort,_bfd_abort.

Instruction types are specified in FT_HOOK_INS=store:50,load,add
Format is 'instruction_name':'probability of selecting a specific instance'.
Instruction name must be one of the following: add, sub, store, load, random

The value random is special in the sense that each instruction we can instrument, is actually instrumented.
We recommend to set a probability, at least for random (to avoid instrumenting too many instructions).
*/
bool FuzztructionSourcePass::injectPatchPoints(Module &M) {
    bool modified = false;
    this->instrumented_values = {};

    /* Get the patchpoint intrinsic */
    Function* stackmap_intr = Intrinsic::getDeclaration(&M,
        Intrinsic::experimental_patchpoint_void
    );
    stackmap_intr->setCallingConv(CallingConv::AnyReg);

    std::vector<CallInst*> abort_fn_callees;
    auto abort_fn = M.getFunction("abort");
    if (abort_fn && abort_fn->arg_size() == 0) {
            for (auto user : abort_fn->users()) {
                if(CallInst* call_ins = dyn_cast<CallInst>(user)) {
                    abort_fn_callees.push_back(call_ins);
                }
            }
    }

    for (auto call_ins: abort_fn_callees) {
        dbgs() << "Deleting call to abort " << *call_ins << "\n";
        auto bb = call_ins->getParent();
        auto bb_terminator = bb->getTerminator();
        auto function = bb->getParent();

        auto ret_type = function->getReturnType();
        if (ret_type->isIntegerTy()) {
            auto ret_val = ConstantInt::get(ret_type, 0);
            IRBuilder<> irb(bb_terminator);
            irb.CreateRet(ret_val);
        } else if (ret_type->isVoidTy()) {
            IRBuilder<> irb(bb_terminator);
            irb.CreateRetVoid();
        } else {
            continue;
        }

        call_ins->eraseFromParent();
        bb_terminator->eraseFromParent();
    }

    auto allowlisted_functions = parse_env_var_list("FT_FUNCTION_ALLOWLIST");
    dbgs() << "allowlisted_functions: " << allowlisted_functions.size() << "\n";

    auto allowlisted_files = parse_env_var_list("FT_FILE_ALLOWLIST");
    dbgs() << "allowlisted_files: " << allowlisted_files.size() << "\n";

    auto blocklisted_files = parse_env_var_list("FT_FILE_BLOCKLIST");
    dbgs() << "blocklisted_files: " << blocklisted_files.size() << "\n";

    if (allowlisted_files.size() > 0) {
        if (std::find(allowlisted_files.begin(), allowlisted_files.end(), M.getSourceFileName()) != allowlisted_files.end()) {
            dbgs() << "FT: File is listed as allowed " << M.getSourceFileName() << "\n";
        } else {
            dbgs() << "FT: File is not on the allow list " << M.getSourceFileName() << "\n";
            return modified;
        }
    } else {
        if (std::find(blocklisted_files.begin(), blocklisted_files.end(), M.getSourceFileName()) != blocklisted_files.end()) {
            dbgs() << "FT: Skipping blockedlisted file " << M.getSourceFileName() << "\n";
            return modified;
        }
    }

    auto allowlisted_files = parse_env_var_list("FT_FILE_ALLOWLIST");
    dbgs() << "allowlisted_files: " << allowlisted_files.size() << "\n";

    auto blocklisted_files = parse_env_var_list("FT_FILE_BLOCKLIST");
    dbgs() << "blocklisted_files: " << blocklisted_files.size() << "\n";

    if (allowlisted_files.size() > 0) {
        if (std::find(allowlisted_files.begin(), allowlisted_files.end(), M.getSourceFileName()) != allowlisted_files.end()) {
            dbgs() << "FT: File is listed as allowed " << M.getSourceFileName() << "\n";
        } else {
            dbgs() << "FT: File is not on the allow list " << M.getSourceFileName() << "\n";
            return false;
        }
    } else {
        if (std::find(blocklisted_files.begin(), blocklisted_files.end(), M.getSourceFileName()) != blocklisted_files.end()) {
            dbgs() << "FT: Skipping blockedlisted file " << M.getSourceFileName() << "\n";
            return false;
        }
    }

    FuzztructionSourcePass::allow_ptr_ty = !env_var_set("FT_NO_PTR_TY");
    FuzztructionSourcePass::allow_vec_ty = !env_var_set("FT_NO_VEC_TY");

    // Get functions which should not be called (i.e., for which we delete calls to)
    auto fn_del_vec = parse_env_var_list("FT_NOP_FN");
    std::set<std::string> fn_del (fn_del_vec.begin(), fn_del_vec.end());
    dbgs() << "FT: Deleting function calls to " << fn_del.size() << " functions\n";

    // Get instruction types we want to instrument
    std::set<InsHook> hook_ins = {};
    for (std::string e : parse_env_var_list("FT_HOOK_INS")) {
        dbgs() << "FT DEBUG: parsed ins_hook: " << to_InsHook(e).to_string() << "\n";
        hook_ins.insert(to_InsHook(e));
    }
    dbgs() << "FT: Instrumenting " << hook_ins.size() << " types of instructions\n";
    if (!hook_ins.size()) {
        errs() << "FT: FT_HOOK_INS is not set\n";
    }

    // use random number from hardware to seed mersenne twister prng
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, 100); // inclusive [0, 100]

    modified |= instrumentCustomPatchPoints(M, stackmap_intr);

    // Track whether we modified the module
    uint64_t num_patchpoints = 0;
    for (auto &F : M) {
        if (allowlisted_functions.size() > 0) {
            if (std::find(allowlisted_functions.begin(), allowlisted_functions.end(), F.getName()) != allowlisted_functions.end()) {
                dbgs() << "FT: function is on the allowlist " << F.getName() << "\n";
            } else {
                dbgs() << "FT: function is not on the allowlist " << F.getName() << "\n";
                continue;
            }
        } else {
            if (std::find(blocklisted_functions.begin(), blocklisted_functions.end(), F.getName()) != blocklisted_functions.end()) {
                dbgs() << "FT: Skipping blockedlisted function " << F.getName() << "\n";
                continue;
            }
        }
        std::vector<Instruction*> instructions;
        for (auto &B : F) {
            for (BasicBlock::iterator DI = B.begin(); DI != B.end(); ) {
                Instruction& I = *DI++;
                instructions.push_back(&I);
            }
        }

        // function call mutation
        modified |= instrumentFunctionEntry(F, stackmap_intr);

        for (auto *I: instructions) {
                if (auto *call_ins = dyn_cast<CallInst>(I)) {
                    bool deleted = maybeDeleteFunctionCall(M, call_ins, fn_del);
                    modified |= deleted;
                    // No point to continue if we just deleted the instruction
                    if (deleted)
                        continue;
                }

                // Check if the current instruction is hooked.
                for (const auto& ins_hook : hook_ins) {
                    bool ins_modified = false;
                    switch (ins_hook.type) {
                        case FuzztructionSourcePass::InsTy::Load:
                            if (auto *load_op = dyn_cast<LoadInst>(I)) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsOutput(M, stackmap_intr, I);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Store:
                            if (auto *store_op = dyn_cast<StoreInst>(I)) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, I, 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Add:
                            if (I->getOpcode() == Instruction::Add) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, I, 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Sub:
                            if (I->getOpcode() == Instruction::Sub) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, I, 1);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Icmp:
                            if (I->getOpcode() == Instruction::ICmp) {
                                if (distr(gen) <= ins_hook.probability)
                                    ins_modified = instrumentInsOutput(M, stackmap_intr, I);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Select:
                            if (I->getOpcode() == Instruction::Select) {
                                if (distr(gen) <= ins_hook.probability)
                                    // Arg 0 is the selection mask (i1 or {<N x i1>})
                                    ins_modified = instrumentInsArg(M, stackmap_intr, I, 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Branch:
                            if (I->getOpcode() == Instruction::Br && distr(gen) <= ins_hook.probability) {
                                // Conditional jump receives multiple args.
                                if (I->getNumOperands() > 1) {
                                    // Arg 0 is the branch condition (i1)
                                    ins_modified = instrumentInsArg(M, stackmap_intr, I, 0);
                                }
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Switch:
                            if (I->getOpcode() == Instruction::Switch && distr(gen) <= ins_hook.probability) {
                                // Arg 0 is the switch condition (intty)
                                ins_modified = instrumentInsArg(M, stackmap_intr, I, 0);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Random:
                            if (!canBeInstrumented(I))
                                break;
                            if (distr(gen) <= ins_hook.probability) {
                                ins_modified = instrumentInsOutput(M, stackmap_intr, I);
                            }
                            break;
                        case FuzztructionSourcePass::InsTy::Call:
                            auto *call = dyn_cast<CallInst>(I);
                            if (call && distr(gen) <= ins_hook.probability) {
                                ins_modified = instrumentCall(M, stackmap_intr, call);
                            }
                            break;
                    }
                    if (ins_modified) {
                        modified = true;
                        num_patchpoints++;
                        // dbgs() << "Instrumented function " << I->getFunction()->getName() << "\n";
                        // dbgs() << "Linkage " << I->getFunction()->getLinkage() << "\n";
                        // dbgs() << "Visibility " << I->getFunction()->getVisibility() << "\n";
                        // instruction cannot have multiple types
                        // no point in trying other types if we just matched
                        break;
                    }
                }
        }
        //llvm::errs() << "function-dump-start\n";
        //F.dump();
    }
    dbgs() << "FT: Inserted " << num_patchpoints << " patchpoints\n";

    return modified;
}

void removeArgumentFromCallInst(CallInst *callInst, unsigned argIndexToRemove) {
    // Get the original arguments of the CallInst
    std::vector<Value*> originalArgs(callInst->arg_begin(), callInst->arg_end());

    // Remove the desired argument
    originalArgs.erase(originalArgs.begin() + argIndexToRemove);

    // Create a new CallInst with the modified arguments
    CallInst* newCallInst = CallInst::Create(callInst->getFunctionType(),
                                             callInst->getCalledOperand(),
                                             originalArgs,
                                             "",
                                             callInst);

    // Replace all uses of the original CallInst with the new CallInst
    callInst->replaceAllUsesWith(newCallInst);

    // Remove the original CallInst
    callInst->eraseFromParent();
}

/*
Filter & delete patchpoints if the live value is already recorded
by another patchpoint.
*/
bool FuzztructionSourcePass::filterInvalidPatchPoints(Module &M) {
    bool modified = false;
    Function* stackmap_intr = Intrinsic::getDeclaration(&M,
        Intrinsic::experimental_patchpoint_void
    );
    stackmap_intr->setCallingConv(CallingConv::AnyReg);

    int num_users = 0;
    dbgs() << "FT: Filtering invalid patch points\n";
    std::set<Value *> used_values = {};
    std::set<Instruction *> pending_deletions = {};
    for (auto &ins : pending_deletions) {
        //assert(ins->isSafeToRemove() && "Instruction is not safe to remove!");
        assert((ins->users().end() == ins->users().begin()) && "Cannot delete call instruction as it has uses");
        modified = true;
        ins->eraseFromParent();
    }
    dbgs() << "FT: Deleted " << pending_deletions.size() << "/" << num_users;
    dbgs() << " patchpoints as live values were already recorded\n";
    return modified;
}

bool FuzztructionSourcePass::allow_ptr_ty = false;
bool FuzztructionSourcePass::allow_vec_ty = false;
std::string FuzztructionSourcePass::insTyNames[] = {"random", "load", "store", "add", "sub", "icmp", "select", "branch", "switch", "call"};

extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "ft-generator-pass", "v0.1",
          [](PassBuilder &PB) {
#if LLVM_VERSION_MAJOR == 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
#endif
#if LLVM_VERSION_MAJOR >= 16
            PB.registerOptimizerLastEPCallback(
#else
            PB.registerOptimizerLastEPCallback(
#endif
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(FuzztructionSourcePass());
                });
          }};

}
