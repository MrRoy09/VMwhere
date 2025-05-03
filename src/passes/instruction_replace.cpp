// add-obfuscation.cpp
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace
{
    class AddObfuscationPass : public PassInfoMixin<AddObfuscationPass>
    {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &)
        {
            for (Function &F : M)
                obfuscateAdds(F);
            return PreservedAnalyses::none();
        }

    private:
        void obfuscateAdds(Function &F)
        {
            std::vector<Instruction *> toReplace;

            // Identify all integer addition instructions to replace
            for (auto &BB : F)
            {
                for (auto &I : BB)
                {
                    if (auto *addInst = dyn_cast<BinaryOperator>(&I))
                    {
                        if (addInst->getOpcode() == Instruction::Add &&
                            addInst->getType()->isIntegerTy(32))
                        {
                            toReplace.push_back(addInst);
                        }
                    }
                }
            }

            // Replace additions with equivalent but more complex operations: (a+b) = (a^b) + ((a&b)<<1)
            for (Instruction *I : toReplace)
            {
                IRBuilder<> builder(I);
                Value *A = I->getOperand(0);
                Value *B = I->getOperand(1);

                Value *XOR = builder.CreateXor(A, B, "obf_xor");
                Value *AND = builder.CreateAnd(A, B, "obf_and");
                Value *SHL = builder.CreateShl(AND, ConstantInt::get(A->getType(), 1), "obf_shl");
                Value *OBF_ADD = builder.CreateAdd(XOR, SHL, "obf_add");

                I->replaceAllUsesWith(OBF_ADD);
                I->eraseFromParent();
            }
        }
    };
}

// Register the pass plugin with LLVM
extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "AddObfuscationPass",
            LLVM_VERSION_STRING, [](PassBuilder &PB)
            {
                PB.registerOptimizerLastEPCallback(
                    [](ModulePassManager &MPM, OptimizationLevel)
                    {
                        MPM.addPass(AddObfuscationPass());
                    });
            }};
}
