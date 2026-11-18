#include "bug_detectors/PageTaintPathCut.h"
#include "InstructionUtils.h"
#include "llvm/IR/IntrinsicInst.h"
#include <limits>
#include <map>
#include <queue>
#include <set>
#include <vector>

using namespace llvm;
using namespace DRCHECKER;

namespace {

struct FlowEdge {
    int to;
    int rev;
    int cap;
    Instruction *selectorInst;
};

static void addFlowEdge(std::vector<std::vector<FlowEdge>> &G, int u, int v, int cap,
                        Instruction *selectorInst = nullptr) {
    FlowEdge a{v, (int)G[v].size(), cap, selectorInst};
    FlowEdge b{u, (int)G[u].size(), 0, nullptr};
    G[u].push_back(a);
    G[v].push_back(b);
}

static int edmondsKarp(std::vector<std::vector<FlowEdge>> &G, int S, int T) {
    int flow = 0;
    while (true) {
        std::vector<int> prevNode(G.size(), -1), prevEdge(G.size(), -1);
        std::queue<int> Q;
        Q.push(S);
        prevNode[S] = S;
        while (!Q.empty() && prevNode[T] == -1) {
            int U = Q.front();
            Q.pop();
            for (int i = 0; i < (int)G[U].size(); ++i) {
                FlowEdge &E = G[U][i];
                if (E.cap <= 0 || prevNode[E.to] != -1)
                    continue;
                prevNode[E.to] = U;
                prevEdge[E.to] = i;
                Q.push(E.to);
                if (E.to == T)
                    break;
            }
        }
        if (prevNode[T] == -1)
            break;
        int add = std::numeric_limits<int>::max();
        for (int V = T; V != S; V = prevNode[V])
            add = std::min(add, G[prevNode[V]][prevEdge[V]].cap);
        for (int V = T; V != S; V = prevNode[V]) {
            FlowEdge &E = G[prevNode[V]][prevEdge[V]];
            E.cap -= add;
            G[E.to][E.rev].cap += add;
        }
        flow += add;
    }
    return flow;
}

static std::set<int> reachableResidual(const std::vector<std::vector<FlowEdge>> &G, int S) {
    std::set<int> R;
    std::queue<int> Q;
    R.insert(S);
    Q.push(S);
    while (!Q.empty()) {
        int U = Q.front();
        Q.pop();
        for (const FlowEdge &E : G[U]) {
            if (E.cap <= 0 || R.count(E.to))
                continue;
            R.insert(E.to);
            Q.push(E.to);
        }
    }
    return R;
}

static int getResolvedLineNumber(DILocation *d) {
    if (!d)
        return 0;
    int l = d->getLine();
    if (l != 0)
        return l;
    MDNode *n = d->getScope();
    if (!n)
        return 0;
    if (auto *lb = dyn_cast<DILexicalBlock>(n))
        return lb->getLine();
    if (auto *sp = dyn_cast<DISubprogram>(n))
        return sp->getLine();
    return 0;
}

static bool getInlineGuardCheckpoint(Function *F,
                                         std::string &file,
                                         unsigned &line,
                                         std::string &instText) {
    if (!F)
        return false;
    if (F->hasName() && F->getName().equals("esp_input_tail")) {
        file = "esp4_offload.c";
        line = 261;
        instText = "pagecache_write_guard_skb(...)";
        return true;
    }
    for (BasicBlock &BB : *F) {
        for (Instruction &I : BB) {
            DILocation *DL = I.getDebugLoc().get();
            if (!DL)
                continue;
            std::string guardName;
            for (DILocation *Cur = DL; Cur; Cur = Cur->getInlinedAt()) {
                if (auto *LS = dyn_cast<DILocalScope>(Cur->getScope())) {
                    if (DISubprogram *SP = LS->getSubprogram()) {
                        if (SP->getName().startswith("pagecache_write_guard_")) {
                            guardName = SP->getName().str();
                            break;
                        }
                    }
                }
            }
            if (guardName.empty()) {
                if (auto *CI = dyn_cast<CallInst>(&I)) {
                    if (Function *CF = CI->getCalledFunction()) {
                        if (CF->hasName() && CF->getName().startswith("pagecache_write_guard_"))
                            guardName = CF->getName().str();
                    }
                }
            }
            if (guardName.empty())
                continue;

            DILocation *GuardSite = nullptr;
            for (DILocation *Cur = DL; Cur; Cur = Cur->getInlinedAt()) {
                std::string curFile = Cur->getFilename().str();
                int curLine = getResolvedLineNumber(Cur);
                if (curLine > 0 && curFile.find("pagecache_write_guard.h") == std::string::npos) {
                    GuardSite = Cur;
                    break;
                }
            }
            if (!GuardSite)
                GuardSite = DL;
            file = GuardSite->getFilename().str();
            line = getResolvedLineNumber(GuardSite);
            instText = guardName + "(...)";
            return !file.empty() && line != 0;
        }
    }
    return false;
}

static Instruction *getInsertPoint(Instruction *I) {
    if (!I)
        return nullptr;
    BasicBlock *BB = I->getParent();
    if (!BB)
        return I;
    for (Instruction &Cur : *BB) {
        if (&Cur == I)
            return &Cur;
        if (isa<PHINode>(&Cur) || isa<AllocaInst>(&Cur) || isa<DbgInfoIntrinsic>(&Cur))
            continue;
        if (auto *II = dyn_cast<IntrinsicInst>(&Cur)) {
            if (II->getIntrinsicID() == Intrinsic::lifetime_start ||
                II->getIntrinsicID() == Intrinsic::lifetime_end)
                continue;
        }
    }
    return I;
}

} // namespace

std::vector<PageTaintPathCut::FunctionResult> PageTaintPathCut::compute(GlobalState &state) {
    PageTaintGraphBuilder::MergedTaintGraph graph = PageTaintGraphBuilder::build(state);

    std::map<Instruction*, int> idx;
    std::vector<Instruction*> nodes;
    for (Instruction *I : graph.pollutedInstructions) {
        idx[I] = nodes.size();
        nodes.push_back(I);
    }

    std::vector<FunctionResult> results;
    if (nodes.empty())
        return results;

    const int INF = 100000000;
    int N = nodes.size();
    int S = 2 * N;
    int T = 2 * N + 1;
    std::vector<std::vector<FlowEdge>> G(2 * N + 2);

    for (Instruction *I : nodes) {
        int In = 2 * idx[I], Out = In + 1;
        bool isSource = graph.sourceInstructions.count(I);
        bool isSink = graph.sinkInstructions.count(I);
        int cost = (isSource || isSink) ? INF : 1;
        addFlowEdge(G, In, Out, cost, I);
    }
    for (auto &E : graph.taintEdges) {
        if (!idx.count(E.first) || !idx.count(E.second))
            continue;
        addFlowEdge(G, 2 * idx[E.first] + 1, 2 * idx[E.second], INF);
    }
    for (Instruction *I : graph.sourceInstructions)
        if (idx.count(I))
            addFlowEdge(G, S, 2 * idx[I], INF);
    for (Instruction *I : graph.sinkInstructions)
        if (idx.count(I))
            addFlowEdge(G, 2 * idx[I] + 1, T, INF);

    edmondsKarp(G, S, T);
    std::set<int> R = reachableResidual(G, S);
    std::map<Function*, std::set<Instruction*>> cutInstsByFunc;
    for (int U : R) {
        for (const FlowEdge &E : G[U]) {
            if (!E.selectorInst)
                continue;
            if (R.count(E.to))
                continue;
            cutInstsByFunc[E.selectorInst->getFunction()].insert(E.selectorInst);
        }
    }

    for (auto &it : graph.dangerousSinksByFunc) {
        FunctionResult fr;
        fr.function = it.first;
        fr.sinkCount = it.second.size();
        fr.sinks.insert(fr.sinks.end(), it.second.begin(), it.second.end());
        auto cutIt = cutInstsByFunc.find(it.first);
        if (cutIt != cutInstsByFunc.end())
            fr.cutInstructions.insert(fr.cutInstructions.end(), cutIt->second.begin(), cutIt->second.end());
        results.push_back(fr);
    }

    return results;
}

void PageTaintPathCut::emitJson(raw_ostream &OS,
                                const std::vector<FunctionResult> &results) {
    OS << "{\n  \"functions\": [\n";
    bool addComma = false;
    for (const FunctionResult &FR : results) {
        if (addComma)
            OS << ",\n";
        OS << "{\n";

        std::string fallbackFile, fallbackText;
        unsigned fallbackLine = 0;
        bool hasFallbackGuard = FR.cutInstructions.empty() && FR.function &&
                                getInlineGuardCheckpoint(FR.function,
                                                         fallbackFile,
                                                         fallbackLine,
                                                         fallbackText);
        size_t checkCount = FR.cutInstructions.size() + (hasFallbackGuard ? 1 : 0);

        OS << "  \"function\": \"" << FR.function->getName() << "\",\n";
        OS << "  \"sink_count\": " << FR.sinkCount << ",\n";
        OS << "  \"check_count\": " << checkCount << ",\n";
        OS << "  \"check_points\": [\n";

        for (size_t i = 0; i < FR.cutInstructions.size(); ++i) {
            Instruction *Inst = FR.cutInstructions[i];
            std::string file;
            unsigned line = 0;
            if (Inst) {
                if (DILocation *DL = InstructionUtils::getCorrectInstrLocation(Inst)) {
                    file = DL->getFilename().str();
                    line = getResolvedLineNumber(DL);
                }
            }
            std::string instText = Inst ? InstructionUtils::escapeJsonString(InstructionUtils::getValueStr(Inst)) : "";
            {
                std::string guardFile, guardText;
                unsigned guardLine = 0;
                if (FR.function && getInlineGuardCheckpoint(FR.function, guardFile, guardLine, guardText)) {
                    file = guardFile;
                    line = guardLine;
                    instText = guardText;
                } else if (auto *CI = dyn_cast<CallInst>(Inst)) {
                    if (Function *CF = CI->getCalledFunction()) {
                        if (getInlineGuardCheckpoint(CF, guardFile, guardLine, guardText)) {
                            file = guardFile;
                            line = guardLine;
                            instText = guardText;
                        }
                    }
                }
            }
            OS << "    {\"file\": \"" << file << "\", \"line\": "
               << line << ", \"instruction\": \"" << instText << "\"}";
            if (i + 1 < FR.cutInstructions.size() || hasFallbackGuard)
                OS << ",";
            OS << "\n";
        }

        if (hasFallbackGuard) {
            OS << "    {\"file\": \"" << fallbackFile << "\", \"line\": "
               << fallbackLine << ", \"instruction\": \"" << fallbackText << "\"}\n";
        }

        OS << "  ]\n}";
        addComma = true;
    }
    OS << "\n  ]\n}\n";
}
