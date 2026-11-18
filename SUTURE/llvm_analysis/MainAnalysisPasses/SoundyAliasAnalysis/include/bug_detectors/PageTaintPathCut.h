#ifndef PAGETAINTPATHCUT_H
#define PAGETAINTPATHCUT_H

#include "ModuleState.h"
#include "CFGUtils.h"
#include "bug_detectors/PageTaintGraphBuilder.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include <set>
#include <vector>
#include <string>
#include <map>

using namespace llvm;

namespace DRCHECKER {

struct PageTaintPathCut {
    struct FunctionResult {
        Function *function = nullptr;
        unsigned sinkCount = 0;
        std::vector<Instruction*> sinks;
        std::vector<Instruction*> cutInstructions;
    };

    struct CheckPoint {
        Instruction *sink = nullptr;
        BasicBlock *bb = nullptr;
        Instruction *insertBefore = nullptr;
        std::string file;
        unsigned line = 0;
    };

    static std::vector<FunctionResult> compute(GlobalState &state);

    static void emitJson(raw_ostream &OS,
                         const std::vector<FunctionResult> &results);
};

}

#endif
