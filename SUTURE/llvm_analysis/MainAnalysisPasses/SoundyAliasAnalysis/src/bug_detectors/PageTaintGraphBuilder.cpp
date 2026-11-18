#include "bug_detectors/PageTaintGraphBuilder.h"
#include "bug_detectors/DangerousSinkClassifier.h"
#include "InstructionUtils.h"
#include "PointsToUtils.h"
#include "TaintUtils.h"
#include <map>
#include <queue>
#include <set>
#include <sstream>
#include <string>

/*
 * PageTaintGraphBuilder 用来构建给 PageTaintPathCut 消费的“全局合并 taint 图”。
 *
 * 整体思路：
 * 1. 遍历 GlobalState 中已经分析过的所有 context。
 * 2. 在每个 context 可达的函数里找 dangerous sink 指令。
 * 3. 对每个 sink，恢复能够到达它的具体 page-taint chain。
 * 4. 把所有 context 下恢复出来的 chain 合并成一张全局过近似图。
 *
 * 合并策略是保守的：
 * - 只要某条指令在任一 context 下被污染，就把它放进合并图。
 * - 只要某条边在任一 taint chain 中出现，就把它放进合并图。
 *
 * 这样得到的是一张表达“可能存在污染流”的全局图，
 * 而不是很多张按 function / context 切开的局部图。
 */

using namespace llvm;
using namespace DRCHECKER;

namespace {
static bool shouldDebugPageSink(Instruction *I) {
    if (!I)
        return false;
    std::string S = InstructionUtils::getValueStr(I);
    return S.find("memcpy_sglist") != std::string::npos ||
           S.find("crypto_aead_encrypt") != std::string::npos ||
           S.find("crypto_aead_decrypt") != std::string::npos;
}

static std::set<TaintFlag*> filterByKind(const std::set<TaintFlag*> &src, TaintKind kind) {
    std::set<TaintFlag*> ret;
    for (TaintFlag *tf : src) {
        if (tf && tf->tag && tf->tag->kind == kind)
            ret.insert(tf);
    }
    return ret;
}

static std::string kindToString(TaintKind kind) {
    switch (kind) {
    case TAINT_KIND_GENERIC:
        return "GENERIC";
    case TAINT_KIND_PAGE:
        return "PAGE";
    case TAINT_KIND_PAGE_ADDR:
        return "PAGE_ADDR";
    default:
        return "UNKNOWN";
    }
}

static std::string collectKinds(std::set<TaintFlag*> *tfs) {
    if (!tfs || tfs->empty())
        return "none";
    std::set<std::string> kinds;
    for (TaintFlag *tf : *tfs) {
        if (!tf || !tf->tag)
            continue;
        if (tf->tag->kind == TAINT_KIND_GENERIC)
            continue;
        kinds.insert(kindToString(tf->tag->kind));
    }
    if (kinds.empty())
        return "none";
    std::ostringstream oss;
    bool first = true;
    for (const std::string &k : kinds) {
        if (!first)
            oss << ",";
        oss << k;
        first = false;
    }
    return oss.str();
}

static std::string valueNameOrNone(Value *V) {
    if (!V)
        return "none";
    if (V->hasName())
        return V->getName().str();
    std::string S;
    raw_string_ostream OS(S);
    V->printAsOperand(OS, false);
    OS.flush();
    return S;
}

static PageTaintGraphBuilder::InstructionInfo buildInstructionInfo(Instruction *I,
                                                                   std::set<TaintFlag*> *tfs) {
    PageTaintGraphBuilder::InstructionInfo info;
    info.variable = "none";
    info.kinds = collectKinds(tfs);

    for (Use &Op : I->operands()) {
        if (Op.get()->hasName()) {
            info.variable = valueNameOrNone(Op.get());
            break;
        }
    }
    return info;
}

static std::string functionSignature(Function *F) {
    if (!F)
        return "none";
    std::string S;
    raw_string_ostream OS(S);
    F->print(OS);
    OS.flush();
    size_t bodyPos = S.find(" {");
    if (bodyPos != std::string::npos)
        S.erase(bodyPos);
    return S;
}

static PageTaintGraphBuilder::EntryValueInfo buildEntryValueInfo(Value *V,
                                                                 std::set<TaintFlag*> *tfs) {
    PageTaintGraphBuilder::EntryValueInfo info;
    info.ir = valueNameOrNone(V);
    info.variable = valueNameOrNone(V);
    info.kinds = collectKinds(tfs);
    return info;
}

static std::string entryKindsText(const std::vector<PageTaintGraphBuilder::EntryValueInfo> &infos) {
    if (infos.empty())
        return "none";
    std::ostringstream oss;
    bool first = true;
    for (const auto &info : infos) {
        if (info.kinds == "none")
            continue;
        if (!first)
            oss << ";";
        oss << info.variable << "|" << info.kinds;
        first = false;
    }
    return first ? "none" : oss.str();
}

static std::string chooseSinkVariable(GlobalState &state,
                                      std::vector<Instruction*> *ctx,
                                      Instruction *I,
                                      TaintKind wantedKind) {
    auto *CI = dyn_cast<CallInst>(I);
    if (!CI)
        return "none";
    for (Use &Arg : CI->args()) {
        Value *V = Arg.get();
        std::set<TaintFlag*> *argTFs = TaintUtils::getTaintInfo(state, ctx, V);
        if (!argTFs)
            continue;
        std::set<TaintFlag*> matched = filterByKind(*argTFs, wantedKind);
        if (matched.empty())
            continue;
#ifdef DEBUG_PAGEGRAPH_EXPORT
        dbgs() << "chooseSinkVariable(): sink=" << InstructionUtils::getValueStr(I)
               << " operand=" << InstructionUtils::getValueStr(V)
               << " hasName=" << V->hasName()
               << " selected=" << valueNameOrNone(V)
               << " kind=" << kindToString(wantedKind) << "\n";
#endif
        return valueNameOrNone(V);
    }
    InstLoc loc(I, ctx);
    for (Use &Arg : CI->args()) {
        Value *V = Arg.get();
        std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
        if (!ptos)
            continue;
        for (auto *pto : *ptos) {
            if (!pto || !pto->targetObject)
                continue;
            std::set<TaintFlag*> fieldTFs;
            pto->targetObject->getFieldTaintInfo(pto->dstfieldId, fieldTFs, &loc);
            std::set<TaintFlag*> matched = filterByKind(fieldTFs, wantedKind);
            if (matched.empty())
                continue;
            return valueNameOrNone(V);
        }
    }
#ifdef DEBUG_PAGEGRAPH_EXPORT
    dbgs() << "chooseSinkVariable(): no matching operand for sink="
           << InstructionUtils::getValueStr(I)
           << " kind=" << kindToString(wantedKind) << "\n";
#endif
    return "none";
}

static void refineCallInstructionInfo(GlobalState &state,
                                      std::vector<Instruction*> *ctx,
                                      Instruction *I,
                                      PageTaintGraphBuilder::InstructionInfo &info) {
    if (!isa<CallInst>(I))
        return;
#ifdef DEBUG_PAGEGRAPH_EXPORT
    if (InstructionUtils::getValueStr(I).find("af_alg_get_rsgl") != std::string::npos) {
        dbgs() << "refineCallInstructionInfo(): before ";
        I->print(dbgs());
        dbgs() << " kinds=" << info.kinds << " var=" << info.variable << "\n";
    }
#endif
    if (info.kinds == "PAGE") {
        std::string var = chooseSinkVariable(state, ctx, I, TAINT_KIND_PAGE);
        if (var != "none")
            info.variable = var;
    } else if (info.kinds == "PAGE_ADDR") {
        std::string var = chooseSinkVariable(state, ctx, I, TAINT_KIND_PAGE_ADDR);
        if (var != "none")
            info.variable = var;
    }
#ifdef DEBUG_PAGEGRAPH_EXPORT
    if (InstructionUtils::getValueStr(I).find("af_alg_get_rsgl") != std::string::npos) {
        dbgs() << "refineCallInstructionInfo(): after ";
        I->print(dbgs());
        dbgs() << " kinds=" << info.kinds << " var=" << info.variable << "\n";
    }
#endif
}

static void mergeInstructionInfo(PageTaintGraphBuilder::InstructionInfo &dst,
                                 const PageTaintGraphBuilder::InstructionInfo &src) {
    if (dst.variable == "none" || dst.variable.empty())
        dst.variable = src.variable;
    if (dst.kinds == "none" || dst.kinds.empty()) {
        dst.kinds = src.kinds;
        return;
    }
    if (src.kinds == "none" || src.kinds.empty())
        return;
    std::set<std::string> kinds;
    auto addKinds = [&](const std::string &s) {
        std::stringstream ss(s);
        std::string item;
        while (std::getline(ss, item, ',')) {
            if (!item.empty())
                kinds.insert(item);
        }
    };
    addKinds(dst.kinds);
    addKinds(src.kinds);
    std::ostringstream oss;
    bool first = true;
    for (const std::string &k : kinds) {
        if (!first)
            oss << ",";
        oss << k;
        first = false;
    }
    dst.kinds = oss.str().empty() ? "none" : oss.str();
}

static bool sameOperandName(Value *V, const char *name) {
    if (!V)
        return false;
    return valueNameOrNone(V) == name;
}

static std::string bbLocation(BasicBlock *BB) {
    if (!BB)
        return "unknown";
    for (Instruction &I : *BB) {
        if (DILocation *DL = InstructionUtils::getCorrectInstrLocation(&I))
            return DL->getFilename().str() + ":" + std::to_string(DL->getLine());
    }
    return "unknown";
}

static std::set<BasicBlock*> collectGraphBBs(const PageTaintGraphBuilder::MergedTaintGraph &graph) {
    std::set<BasicBlock*> bbs;
    for (Instruction *I : graph.pollutedInstructions) {
        if (I && I->getParent())
            bbs.insert(I->getParent());
    }
    for (auto &E : graph.taintEdges) {
        if (E.first && E.first->getParent())
            bbs.insert(E.first->getParent());
        if (E.second && E.second->getParent())
            bbs.insert(E.second->getParent());
    }
    return bbs;
}

/*
 * 收集一个 sink 能关联到的所有 taint flag。
 *
 * 这里不能只依赖 sink 指令自身的 SSA taint。
 * 很多 sink 的危险性来自：
 * - tainted 参数
 * - tainted pointee object
 *
 * 即使 call 指令自己没有被直接打 taint，它依然可能是危险 sink。
 */
static std::set<TaintFlag*> collectSinkTaintFlags(GlobalState &state,
                                                  std::vector<Instruction*> *ctx,
                                                  Instruction *sink) {
    std::set<TaintFlag*> agg;
    if (!sink)
        return agg;

    std::set<TaintFlag*> *tfs = TaintUtils::getTaintInfo(state, ctx, sink);
    if (tfs)
        agg.insert(tfs->begin(), tfs->end());

    if (auto *SI = dyn_cast<StoreInst>(sink)) {
        Value *ptr = SI->getPointerOperand();
        std::set<TaintFlag*> *ptrTFs = TaintUtils::getTaintInfo(state, ctx, ptr);
        if (ptrTFs) {
            std::set<TaintFlag*> pageAddrOnly = filterByKind(*ptrTFs, TAINT_KIND_PAGE_ADDR);
            agg.insert(pageAddrOnly.begin(), pageAddrOnly.end());
        }
        return agg;
    }

    if (auto *CI = dyn_cast<CallInst>(sink)) {
        for (Use &Arg : CI->args()) {
            Value *V = Arg.get();
            std::set<TaintFlag*> *argTFs = TaintUtils::getTaintInfo(state, ctx, V);
            if (argTFs)
                agg.insert(argTFs->begin(), argTFs->end());

            InstLoc loc(sink, ctx);
            std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
            if (!ptos)
                continue;
            for (auto *pto : *ptos) {
                if (!pto || !pto->targetObject)
                    continue;
                std::set<TaintFlag*> fieldTFs;
                pto->targetObject->getFieldTaintInfo(pto->dstfieldId, fieldTFs, &loc);
                agg.insert(fieldTFs.begin(), fieldTFs.end());
            }
        }
    }
    return agg;
}

static bool infoHasKind(const std::string &kinds, const std::string &wanted) {
    std::stringstream ss(kinds);
    std::string item;
    while (std::getline(ss, item, ',')) {
        if (item == wanted)
            return true;
    }
    return false;
}

static bool entryInfosHaveKind(const std::vector<PageTaintGraphBuilder::EntryValueInfo> &infos,
                               const std::string &wanted) {
    for (const auto &info : infos) {
        if (infoHasKind(info.kinds, wanted))
            return true;
    }
    return false;
}

static Instruction *firstNonDebugInstruction(Function *F) {
    if (!F || F->empty())
        return nullptr;
    for (Instruction &I : F->getEntryBlock()) {
        if (!isa<DbgInfoIntrinsic>(&I))
            return &I;
    }
    return nullptr;
}

static void addDirectCallEntryEdges(PageTaintGraphBuilder::MergedTaintGraph &graph) {
    for (const auto &KV : graph.instructionInfos) {
        Instruction *I = KV.first;
        const PageTaintGraphBuilder::InstructionInfo &info = KV.second;
        if (!I || !infoHasKind(info.kinds, "PAGE"))
            continue;
        auto *CI = dyn_cast<CallInst>(I);
        if (!CI)
            continue;
        Function *Callee = CI->getCalledFunction();
        if (!Callee || Callee->isDeclaration())
            continue;
        auto entryIt = graph.entryValueInfos.find(Callee);
        if (entryIt == graph.entryValueInfos.end())
            continue;
        if (!entryInfosHaveKind(entryIt->second, "PAGE"))
            continue;
        Instruction *EntryInst = firstNonDebugInstruction(Callee);
        if (!EntryInst)
            continue;
        graph.pollutedInstructions.insert(I);
        graph.pollutedInstructions.insert(EntryInst);
        graph.taintEdges.insert({I, EntryInst});
    }
}
} // namespace

/*
 * 从 SUTURE 已经分析过的所有 context 构建一张“全局合并 taint 图”。
 *
 * 对每个 context：
 * - 枚举 dangerous sinks
 * - 恢复能到达这些 sink 的 taint chains
 * - 把 chain 投影成 instruction 节点和 instruction-to-instruction 边
 * - 最后把所有结果并成一张全局图
 */
PageTaintGraphBuilder::MergedTaintGraph PageTaintGraphBuilder::build(GlobalState &state) {
    MergedTaintGraph graph;

    for (AnalysisContext *ac : state.availableAnalysisContexts) {
        if (!ac || !ac->callSites || ac->callSites->empty())
            continue;

        /*
         * 一个 context 向量里会出现很多属于同一 function 的指令，
         * 所以同一个 function 在一个 context 下只需要分析一次。
         */
        std::set<Function*> visitedFuncs;
        for (Instruction *I : *(ac->callSites)) {
            if (!I || !I->getFunction())
                continue;
            Function *F = I->getFunction();
            if (!visitedFuncs.insert(F).second)
                continue;

            for (Argument &Arg : F->args()) {
                std::set<TaintFlag*> *argTFs =
                    TaintUtils::getTaintInfo(state, ac->callSites, &Arg);
                PageTaintGraphBuilder::EntryValueInfo argInfo =
                    buildEntryValueInfo(&Arg, argTFs);
                if (argInfo.kinds == "none")
                    continue;
                auto &entryInfos = graph.entryValueInfos[F];
                bool exists = false;
                for (const auto &existing : entryInfos) {
                    if (existing.variable == argInfo.variable &&
                        existing.kinds == argInfo.kinds) {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                    entryInfos.push_back(argInfo);
            }

            /*
             * 先把“当前值自己已经带的 taint kind”记下来。
             *
             * 这一步不能只依赖后面的 taint chain 恢复，因为某些值（例如 %62）
             * 当前在该 context 下已经带 PAGE 标签，但未必会出现在最终保留下来的
             * shortest taint chain 中。如果不在这里补记，导出时会错误显示成 none。
             */
            for (auto &BB : *F) {
                for (auto &Inst : BB) {
                    std::set<TaintFlag*> *instTFs =
                        TaintUtils::getTaintInfo(state, ac->callSites, &Inst);
                    std::set<TaintFlag*> callTFs;
                    std::set<TaintFlag*> *displayTFs = instTFs;
                    if ((!displayTFs || displayTFs->empty()) && isa<CallInst>(&Inst)) {
                        callTFs = collectSinkTaintFlags(state, ac->callSites, &Inst);
                        if (!callTFs.empty())
                            displayTFs = &callTFs;
                    }
                    if (!displayTFs || displayTFs->empty())
                        continue;
                    PageTaintGraphBuilder::InstructionInfo instInfo =
                        buildInstructionInfo(&Inst, displayTFs);
                    if (instInfo.kinds == "none")
                        continue;
                    refineCallInstructionInfo(state, ac->callSites, &Inst, instInfo);
                    if (graph.instructionInfos.find(&Inst) == graph.instructionInfos.end())
                        graph.instructionInfos[&Inst] = instInfo;
                    else
                        mergeInstructionInfo(graph.instructionInfos[&Inst], instInfo);
                }
            }

            std::vector<Instruction*> dangerousSinks;
            for (auto &BB : *F) {
                for (auto &Inst : BB) {
                    if (DangerousSinkClassifier::isDangerousSink(state, ac->callSites, *F, Inst))
                        dangerousSinks.push_back(&Inst);
                }
            }
            for (Instruction *sink : dangerousSinks) {
                std::set<TaintFlag*> cur = collectSinkTaintFlags(state, ac->callSites, sink);
                if (cur.empty())
                    continue;
#ifdef DEBUG_PAGEGRAPH_EXPORT
                if (shouldDebugPageSink(sink)) {
                    dbgs() << "PageGraphSinkDebug: sink=" << InstructionUtils::getValueStr(sink)
                           << " kinds=" << collectKinds(&cur) << "\n";
                }
#endif
                std::set<std::vector<InstLoc*>*> chains;
                state.getAllUserTaintChains(&cur, chains);
                if (chains.empty())
                    continue;

                graph.dangerousSinksByFunc[F].insert(sink);
                graph.sinkInstructions.insert(sink);
                for (auto *tr : chains) {
                    if (!tr || tr->empty())
                        continue;
                    Instruction *prevInst = nullptr;
                    /*
                     * 把每一条恢复出来的 taint chain 合并进全局图。
                     * 其中一条 chain 的第一条指令会被视为这张合并图里的
                     * source 节点。
                     */
                    for (InstLoc *loc : *tr) {
                        if (!loc || !loc->inst)
                            continue;
                        Instruction *curInst = dyn_cast<Instruction>(loc->inst);
                        if (!curInst)
                            continue;
                        graph.pollutedInstructions.insert(curInst);
                        /*
                         * 这里不能把 sink 的 taint 集 cur 直接抹到链上的每个
                         * instruction 上。链上每个点应该显示它“自己当前已有”的 taint，
                         * 而不是 sink 汇总出来的 taint。
                         *
                         * 当前 instruction 的展示信息已经在前面的“逐条 Inst 查
                         * TaintUtils::getTaintInfo(...)”阶段填过；这里仅补图节点和边，
                         * 不再覆盖 instructionInfos。
                         */
                        if (!prevInst)
                            graph.sourceInstructions.insert(curInst);
                        if (prevInst)
                            graph.taintEdges.insert({prevInst, curInst});
                        prevInst = curInst;
                    }
                    if (prevInst)
                        graph.taintEdges.insert({prevInst, sink});
                    graph.pollutedInstructions.insert(sink);
                    PageTaintGraphBuilder::InstructionInfo sinkInfo = buildInstructionInfo(sink, &cur);
                    refineCallInstructionInfo(state, ac->callSites, sink, sinkInfo);
                    if (graph.instructionInfos.find(sink) == graph.instructionInfos.end())
                        graph.instructionInfos[sink] = sinkInfo;
                    else
                        mergeInstructionInfo(graph.instructionInfos[sink], sinkInfo);
                }
            }
        }
    }

    addDirectCallEntryEdges(graph);
    return graph;
}

void PageTaintGraphBuilder::emitText(raw_ostream &OS,
                                     GlobalState &state,
                                     const MergedTaintGraph &graph) {
    std::set<BasicBlock*> graphBBs = collectGraphBBs(graph);
    std::map<BasicBlock*, std::set<BasicBlock*>> succs;
    std::set<BasicBlock*> sourceBBs;

    for (Instruction *I : graph.sourceInstructions)
        if (I && I->getParent())
            sourceBBs.insert(I->getParent());

    for (const auto &entryKV : graph.entryValueInfos) {
        Function *F = entryKV.first;
        if (!F || entryKV.second.empty())
            continue;
        sourceBBs.insert(&F->getEntryBlock());
    }

    for (auto &E : graph.taintEdges) {
        if (!E.first || !E.second || !E.first->getParent() || !E.second->getParent())
            continue;
        succs[E.first->getParent()].insert(E.second->getParent());
    }

    std::queue<BasicBlock*> Q;
    std::set<BasicBlock*> seen, enqueued;
    for (BasicBlock *BB : sourceBBs) {
        if (enqueued.insert(BB).second)
            Q.push(BB);
    }
    for (BasicBlock *BB : graphBBs) {
        if (enqueued.insert(BB).second)
            Q.push(BB);
    }

    std::vector<BasicBlock*> order;
    while (!Q.empty()) {
        BasicBlock *BB = Q.front();
        Q.pop();
        if (!seen.insert(BB).second)
            continue;
        order.push_back(BB);
        for (BasicBlock *Succ : succs[BB]) {
            if (enqueued.insert(Succ).second)
                Q.push(Succ);
        }
    }

    std::map<BasicBlock*, unsigned> bbIds;
    for (unsigned i = 0; i < order.size(); ++i)
        bbIds[order[i]] = i;

    OS << "=== TAINT GRAPH TRACE ===\n";
    for (BasicBlock *BB : order) {
        OS << "\n[BB " << bbIds[BB] << "]\n";
        OS << "function: " << BB->getParent()->getName() << "\n";
        OS << "location: " << bbLocation(BB) << "\n";
        OS << "succ: ";
        bool firstSucc = true;
        for (BasicBlock *Succ : succs[BB]) {
            if (!firstSucc)
                OS << ", ";
            OS << bbIds[Succ];
            firstSucc = false;
        }
        if (firstSucc)
            OS << "none";
        OS << "\n\n";

        if (BB == &BB->getParent()->getEntryBlock()) {
            auto fit = graph.entryValueInfos.find(BB->getParent());
            std::string entryText =
                (fit == graph.entryValueInfos.end()) ? "none" : entryKindsText(fit->second);
            OS << functionSignature(BB->getParent()) << "\t" << entryText << "\n";
        }

        for (Instruction &I : *BB) {
            auto it = graph.instructionInfos.find(&I);
            std::string kinds = "none";
            std::string var = valueNameOrNone(&I);
            bool isDangerousSink = graph.sinkInstructions.count(&I);
            if (it != graph.instructionInfos.end()) {
                var = it->second.variable;
                kinds = it->second.kinds;
            }

            OS << InstructionUtils::getValueStr(&I) << "\t";
            if (kinds == "none")
                OS << "none";
            else
                OS << var << "|" << kinds;
            if (isDangerousSink)
                OS << "\t<- dangerous sink";
            OS << "\n";
        }
    }
}
