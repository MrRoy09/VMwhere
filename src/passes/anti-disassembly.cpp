// anti-disassembly.cpp
#include "llvm/IR/PassManager.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Module.h"

#include <random>
#include <sstream>
#include <iomanip>

using namespace llvm;

namespace
{
    class ImpossibleBytePass : public PassInfoMixin<ImpossibleBytePass>
    {
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &)
        {
            for (Function &F : M)
                injectBytes(F);
            return PreservedAnalyses::none();
        }

    private:
        void injectBytes(Function &F)
        {
            LLVMContext &Ctx = F.getContext();
            static std::mt19937_64 rng(std::random_device{}());
            std::uniform_int_distribution<uint8_t> dist(0, 0xFF);

            auto makeIA = [&]() -> InlineAsm *
            {
                uint8_t r2 = dist(rng),
                        r3 = dist(rng),
                        r4 = dist(rng);

                std::ostringstream oss;
                oss << ".byte 0x48, 0xB8, "
                    << "0x" << std::hex << std::setw(2) << std::setfill('0') << int(r2) << ", "
                    << "0x" << std::hex << std::setw(2) << std::setfill('0') << int(r3) << ", "
                    << "0x" << std::hex << std::setw(2) << std::setfill('0') << int(r4) << ", "
                    << "0xEB, 0x08, 0xFF, 0xFF, 0x48, 0x31, 0xC0, 0xEB, 0xF7, 0xE8\n";
                std::string bytes1 = oss.str();

                FunctionType *FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
                return InlineAsm::get(
                    FTy,
                    bytes1,
                    "~{eax}",
                    true,
                    false,
                    InlineAsm::AD_Intel,
                    false);
            };

            for (BasicBlock &BB : F)
            {
                IRBuilder<> B(&BB);
                B.SetInsertPoint(&*BB.getFirstInsertionPt());

                InlineAsm *IA1 = makeIA();
                B.CreateCall(IA1);

                for (auto It = BB.begin(); It != BB.end(); ++It)
                {
                    if (isa<PHINode>(*It))
                        continue;

                    if (rand() % 2 == 0)
                    {
                        IRBuilder<> IB(&*It);
                        InlineAsm *IA2 = makeIA();
                        IB.CreateCall(IA2);
                    }
                }
            }
        }
    };

}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return {LLVM_PLUGIN_API_VERSION, "ImpossibleBytePass",
            LLVM_VERSION_STRING, [](PassBuilder &PB)
            {
                PB.registerOptimizerLastEPCallback(
                    [](ModulePassManager &MPM, OptimizationLevel)
                    {
                        MPM.addPass(ImpossibleBytePass());
                    });
            }};
}
