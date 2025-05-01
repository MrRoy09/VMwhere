#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <random>
#include <vector>

using namespace llvm;

namespace
{

    const uint8_t DEFAULT_KEY = 0x42;

    class StringEncryptionPass : public PassInfoMixin<StringEncryptionPass>
    {
    private:
        uint8_t encryptionKey;

        uint8_t generateKey()
        {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(1, 255); 
            return static_cast<uint8_t>(distrib(gen));
        }

        std::vector<uint8_t> encryptString(StringRef str)
        {
            std::vector<uint8_t> encrypted;
            for (char c : str)
            {
                encrypted.push_back(static_cast<uint8_t>(c) ^ encryptionKey);
            }
            encrypted.push_back(0 ^ encryptionKey); 
            return encrypted;
        }

        Function *declareDecryptFunction(Module &M)
        {
            Type *int8Ty = Type::getInt8Ty(M.getContext());
            PointerType *charPtrTy = PointerType::get(int8Ty, 0);
            Type *sizeTy = Type::getInt64Ty(M.getContext());

            FunctionType *decryptFuncTy = FunctionType::get(
                charPtrTy,
                {charPtrTy, sizeTy, int8Ty},
                false);

            return Function::Create(
                decryptFuncTy,
                GlobalValue::LinkageTypes::ExternalLinkage,
                "decrypt_string",
                &M);
        }

        GlobalVariable *createKeyGlobal(Module &M)
        {
            Constant *keyConstant = ConstantInt::get(Type::getInt8Ty(M.getContext()), encryptionKey);

            return new GlobalVariable(
                M,
                Type::getInt8Ty(M.getContext()),
                true, // isConstant
                GlobalValue::LinkageTypes::InternalLinkage,
                keyConstant,
                "__encryption_key");
        }

    public:
        StringEncryptionPass() : encryptionKey(DEFAULT_KEY) {}

        PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM)
        {
            bool modified = false;
            encryptionKey = generateKey();
            GlobalVariable *keyGlobal = createKeyGlobal(M);
            Function *decryptFunc = declareDecryptFunction(M);
            std::vector<GlobalVariable *> toReplace;
            for (GlobalVariable &GV : M.globals())
            {
                if (!GV.isConstant() || !GV.hasInitializer())
                    continue;

                Constant *Init = GV.getInitializer();
                if (isa<ConstantDataArray>(Init))
                {
                    ConstantDataArray *CDA = cast<ConstantDataArray>(Init);
                    if (CDA->isCString())
                    {
                        toReplace.push_back(&GV);
                    }
                }
            }

            for (GlobalVariable *GV : toReplace)
            {
                ConstantDataArray *CDA = cast<ConstantDataArray>(GV->getInitializer());
                StringRef originalStr = CDA->getAsCString();

                if (originalStr.empty())
                    continue;

                std::vector<uint8_t> encryptedData = encryptString(originalStr);

                ArrayType *encryptedArrayType = ArrayType::get(
                    Type::getInt8Ty(M.getContext()),
                    encryptedData.size());

                std::vector<Constant *> encryptedBytes;
                for (uint8_t byte : encryptedData)
                {
                    encryptedBytes.push_back(ConstantInt::get(Type::getInt8Ty(M.getContext()), byte));
                }

                Constant *encryptedArray = ConstantArray::get(encryptedArrayType, encryptedBytes);
                GlobalVariable *encryptedGV = new GlobalVariable(
                    M,
                    encryptedArrayType,
                    true, 
                    GlobalValue::PrivateLinkage,
                    encryptedArray,
                    GV->getName() + ".encrypted");

                for (auto UI = GV->use_begin(), UE = GV->use_end(); UI != UE;)
                {
                    Use &U = *UI++;
                    User *user = U.getUser();

                    IRBuilder<> builder(M.getContext());
                    if (Instruction *I = dyn_cast<Instruction>(user))
                    {
                        builder.SetInsertPoint(I);
                    }
                    else
                    {
                        continue;
                    }

                    Type *int8Ty = Type::getInt8Ty(M.getContext());
                    Value *stringPtr = builder.CreateBitCast(
                        encryptedGV,
                        PointerType::get(int8Ty, 0));

                    Value *stringLen = builder.getInt64(originalStr.size());
                    Value *keyValue = builder.CreateLoad(Type::getInt8Ty(M.getContext()), keyGlobal);

                    Value *decryptedString = builder.CreateCall(
                        decryptFunc,
                        {stringPtr, stringLen, keyValue});

                    U.set(decryptedString);
                }

                if (GV->use_empty())
                {
                    GV->eraseFromParent();
                }

                modified = true;
            }

            return modified ? PreservedAnalyses::none() : PreservedAnalyses::all();
        }
    };

} 

PassPluginLibraryInfo getPassPluginInfo()
{
    static std::atomic<bool> ONCE_FLAG(false);
    return {LLVM_PLUGIN_API_VERSION, "StringEncryptionPass", "0.0.1",
            [](PassBuilder &PB)
            {
                PB.registerPipelineEarlySimplificationEPCallback(
                    [&](ModulePassManager &MPM, OptimizationLevel opt)
                    {
                        if (ONCE_FLAG)
                        {
                            return true;
                        }
                        MPM.addPass(StringEncryptionPass());
                        ONCE_FLAG = true;
                        return true;
                    });

            }};
};

extern "C" __attribute__((visibility("default"))) LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo()
{
    return getPassPluginInfo();
}