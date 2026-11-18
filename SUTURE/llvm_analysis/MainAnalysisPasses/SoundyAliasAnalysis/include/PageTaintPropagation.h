#ifndef PAGETAINTPROPAGATION_H
#define PAGETAINTPROPAGATION_H

#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"

using namespace llvm;

namespace DRCHECKER {

class TaintAnalysisVisitor;

struct PageTaintPropagation {
    static bool isPointerLike(Value *v);
    static bool isPageAddressFunction(const Function *F);
    static void handleExternalFunction(TaintAnalysisVisitor &visitor,
                                       CallInst &I,
                                       Function *currFunc);
    static void handleDefinedFunction(TaintAnalysisVisitor &visitor,
                                      CallInst &I,
                                      Function *currFunc);
};

}

#endif
