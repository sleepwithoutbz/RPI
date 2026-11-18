#ifndef DANGEROUSSINKCLASSIFIER_H
#define DANGEROUSSINKCLASSIFIER_H

#include "ModuleState.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include <vector>

using namespace llvm;

namespace DRCHECKER {

struct DangerousSinkClassifier {
    static bool isPageCarrier(Value *v);
    static bool isDangerousSink(GlobalState &state,
                                std::vector<Instruction *> *ctx,
                                Function &F,
                                Instruction &I);
};

}

#endif
