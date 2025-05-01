#include "llvm/IR/PassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/IR/Instructions.h>
#include "llvm/Pass.h"
#include <vector>

using namespace llvm;

namespace
{
  class ControlFlowFlatten : public PassInfoMixin<ControlFlowFlatten>
  {
  public:
    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
    {
      for (Function &F : M)
      {
        flattenFunction(F);
      }
      return PreservedAnalyses::none();
    }

    bool checkIsConditional(Instruction *i)
    {
      if (BranchInst *ir = dyn_cast<BranchInst>(i))
      {
        return ir->isConditional();
      }
      return 0;
    }

    bool flattenFunction(Function &F)
    {
      std::vector<BasicBlock *> target_conditionals;
      std::vector<BasicBlock *> BasicBlocks;
      for (auto &BB : F)
      {
        BasicBlocks.push_back(&BB);
      }

      if (BasicBlocks.size() < 2)
      {
        return 0;
      }

      BasicBlock &entry_block = F.getEntryBlock();

      for (auto *bb : BasicBlocks)
      {
        if (checkIsConditional(bb->getTerminator()))
        {
          target_conditionals.push_back(bb);
        }
      }

      if (target_conditionals.size() != 0)
      {
        for (auto i = target_conditionals.rbegin(); i != target_conditionals.rend(); i++)
        {
          flatten_conditional(*i, F);
        }
      }
      return 1;
    }

    bool flatten_conditional(BasicBlock *conditionalBlock, Function &F)
    {
      BasicBlock *temp = conditionalBlock->splitBasicBlockBefore(conditionalBlock->getTerminator());
      auto *branchInstruction = dyn_cast<BranchInst>(conditionalBlock->getTerminator());
      ICmpInst *condition = dyn_cast<ICmpInst>(branchInstruction->getCondition()); 
      Instruction *firstInst = conditionalBlock->getFirstNonPHI();

      AllocaInst *switchVar = NULL;
      LoadInst *load = NULL;
      switchVar = new AllocaInst(Type::getInt32Ty(F.getContext()), 0, "switchVar", firstInst);
      new StoreInst(ConstantInt::get(Type::getInt32Ty(F.getContext()), 1), switchVar, firstInst);
      load = new LoadInst(IntegerType::getInt32Ty(F.getContext()), switchVar, "switchVar", firstInst);

      Value *cmp = new ICmpInst(branchInstruction, ICmpInst::ICMP_EQ, load, ConstantInt::get(Type::getInt32Ty(F.getContext()), 0), "cmp");
      BasicBlock *trueBlock = branchInstruction->getSuccessor(0);
      BasicBlock *falseBlock = branchInstruction->getSuccessor(1);
      BranchInst::Create(falseBlock, trueBlock, cmp, branchInstruction);
      branchInstruction->removeFromParent();

      BasicBlock *switch_case_3 = trueBlock;
      new StoreInst(ConstantInt::get(Type::getInt32Ty(F.getContext()), 2), switchVar, trueBlock->getTerminator());
      BasicBlock *switch_block = BasicBlock::Create(F.getContext(), "switch_statement", &F);
      dyn_cast<BranchInst>(conditionalBlock->getTerminator())->setSuccessor(1, switch_block);
      SwitchInst *switchI = SwitchInst::Create(load, falseBlock, 2, switch_block);

      BasicBlock *newconditionalBlock = conditionalBlock->splitBasicBlockBefore(load);

      for (auto *pred : predecessors(newconditionalBlock))
      {
        if (pred != (*predecessors(newconditionalBlock).begin()))
        {
          Instruction *terminator = pred->getTerminator();
          for (unsigned i = 0; i < terminator->getNumSuccessors(); i++)
          {
            if (terminator->getSuccessor(i) == newconditionalBlock)
            {
              terminator->setSuccessor(i, conditionalBlock);
            }
          }
        }
      }

      BasicBlock *switch_case_1 = BasicBlock::Create(F.getContext(), "case_1", &F);
      new StoreInst(ConstantInt::get(F.getContext(), APInt(32, 2)), switchVar, switch_case_1);
      BranchInst::Create(conditionalBlock, switch_case_1);

      BasicBlock *switch_case_2 = BasicBlock::Create(F.getContext(), "case_2", &F);
      BasicBlock *thenBlock = BasicBlock::Create(F.getContext(), "case_2_then", &F);
      new StoreInst(ConstantInt::get(F.getContext(), APInt(32, 3)), switchVar, thenBlock);
      BranchInst::Create(conditionalBlock, thenBlock);
      BasicBlock *elseBlock = BasicBlock::Create(F.getContext(), "case_2_else", &F);
      new StoreInst(ConstantInt::get(F.getContext(), APInt(32, 0)), switchVar, elseBlock);
      BranchInst::Create(conditionalBlock, elseBlock);
      ICmpInst *condition_replicate = (ICmpInst *)condition->clone();
      IRBuilder<> Builder(switch_case_2);
      Builder.Insert(condition_replicate);
      BranchInst::Create(thenBlock, elseBlock, condition_replicate, switch_case_2);
      switchI->addCase(ConstantInt::get(F.getContext(), APInt(32, 1)), switch_case_1);
      switchI->addCase(ConstantInt::get(F.getContext(), APInt(32, 2)), switch_case_2);
      switchI->addCase(ConstantInt::get(F.getContext(), APInt(32, 3)), switch_case_3);
      return 1;
    }
  };
}

PassPluginLibraryInfo getPassPluginInfo()
{
  static std::atomic<bool> ONCE_FLAG(false);
  return {LLVM_PLUGIN_API_VERSION, "control-flow-flatten", "0.0.1",
          [](PassBuilder &PB)
          {
            try
            {
              PB.registerPipelineEarlySimplificationEPCallback(
                  [&](ModulePassManager &MPM, OptimizationLevel opt)
                  {
                    if (ONCE_FLAG)
                    {
                      return true;
                    }
                    MPM.addPass(ControlFlowFlatten());
                    ONCE_FLAG = true;
                    return true;
                  });
            }
            catch (const std::exception &e)
            {
              outs() << "Error: " << e.what() << "\n";
            }
          }};
};

extern "C" __attribute__((visibility("default"))) LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
  return getPassPluginInfo();
}
