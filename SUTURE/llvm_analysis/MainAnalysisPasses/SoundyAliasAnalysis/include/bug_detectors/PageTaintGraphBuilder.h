#ifndef PAGETAINTGRAPHBUILDER_H
#define PAGETAINTGRAPHBUILDER_H

#include "ModuleState.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/raw_ostream.h"
#include <map>
#include <set>
#include <utility>
#include <vector>

using namespace llvm;

namespace DRCHECKER {

struct PageTaintGraphBuilder {
    struct InstructionInfo {
        std::string variable;
        std::string kinds;
    };

    struct EntryValueInfo {
        std::string ir;
        std::string variable;
        std::string kinds;
    };

    struct MergedTaintGraph {
        std::map<Function*, std::set<Instruction*>> dangerousSinksByFunc;
        std::set<Instruction*> sinkInstructions;
        std::set<Instruction*> pollutedInstructions;
        std::set<std::pair<Instruction*, Instruction*>> taintEdges;
        std::set<Instruction*> sourceInstructions;
        std::map<Instruction*, InstructionInfo> instructionInfos;
        std::map<Function*, std::vector<EntryValueInfo>> entryValueInfos;
    };

    static MergedTaintGraph build(GlobalState &state);
    static void emitText(raw_ostream &OS, GlobalState &state, const MergedTaintGraph &graph);
};

}

#endif
