#include "bug_detectors/DangerousSinkClassifier.h"
#include "PointsToUtils.h"
#include "TaintUtils.h"

using namespace llvm;
using namespace DRCHECKER;

namespace {
static bool hasAnyTaint(std::set<TaintFlag*> *tfs) {
    if (!tfs)
        return false;
    for (TaintFlag *tf : *tfs) {
        if (tf && tf->isTainted())
            return true;
    }
    return false;
}

static bool hasTaggedTaintKind(std::set<TaintFlag*> *tfs, TaintKind kind) {
    if (!tfs)
        return false;
    for (TaintFlag *tf : *tfs) {
        if (!tf || !tf->isTainted() || !tf->tag)
            continue;
        if (tf->tag->kind == kind)
            return true;
    }
    return false;
}

static const std::vector<std::string> pageCarrierTypePrefixes = {
    "struct.scatterlist",
    "struct.sg_table",
};

static bool isStructPage(Type *ty) {
    auto *st = dyn_cast<StructType>(ty);
    if (!st || !st->hasName())
        return false;
    StringRef name = st->getStructName();
    if (name == "struct.page")
        return true;
    if (!name.startswith("struct.page."))
        return false;
    StringRef suffix = name.drop_front(StringRef("struct.page.").size());
    return !suffix.empty() &&
           std::all_of(suffix.begin(), suffix.end(), [](char c) { return c >= '0' && c <= '9'; });
}

static bool isPageBearingType(Type *ty) {
    if (ty->isPointerTy())
        ty = ty->getPointerElementType();
    if (!ty->isStructTy())
        return false;
    StringRef name = ty->getStructName();
    if (isStructPage(ty))
        return true;
    return name.startswith("struct.scatterlist") ||
           name.startswith("struct.sg_table") ||
           name.startswith("struct.bio_vec") ||
           name.startswith("struct.bio") ||
           name.startswith("struct.iov_iter") ||
           name.startswith("struct.msghdr") ||
           name.startswith("struct.bvec_iter") ||
           name.startswith("struct.sk_buff") ||
           name.startswith("struct.skb_shared_info") ||
           name.startswith("struct.page_frag") ||
           name.startswith("struct.aead_request") ||
           name.startswith("struct.skcipher_request") ||
           name.startswith("struct.crypto_async_request") ||
           name.startswith("struct.netmem");
}

static bool hasStructPrefix(Type *ty, const std::vector<std::string> &prefixes) {
    if (!ty || !ty->isPointerTy())
        return false;
    Type *elem = ty->getPointerElementType();
    auto *st = dyn_cast<StructType>(elem);
    if (!st || !st->hasName())
        return false;
    StringRef name = st->getStructName();
    for (const std::string &prefix : prefixes) {
        if (name.startswith(prefix))
            return true;
    }
    return false;
}

static bool hasPageBearingArg(CallInst &CI) {
    for (Use &Arg : CI.args())
        if (isPageBearingType(Arg->getType()))
            return true;
    return false;
}

static bool hasScatterlistArg(CallInst &CI) {
    for (Use &Arg : CI.args())
        if (hasStructPrefix(Arg->getType(), pageCarrierTypePrefixes))
            return true;
    return false;
}

static bool hasTaintedPageContainerArg(GlobalState &state,
                                       std::vector<Instruction *> *ctx,
                                       CallInst &CI) {
    for (Use &Arg : CI.args()) {
        Value *V = Arg.get();
        if (!isPageBearingType(V->getType()))
            continue;
        std::set<TaintFlag*> *valTFs = TaintUtils::getTaintInfo(state, ctx, V);
        if (valTFs && !valTFs->empty())
            return true;
        std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
        if (!ptos)
            continue;
        InstLoc loc(&CI, ctx);
        for (auto *pto : *ptos) {
            if (!pto || !pto->targetObject)
                continue;
            std::set<TaintFlag*> cur;
            pto->targetObject->getFieldTaintInfo(pto->dstfieldId, cur, &loc);
            if (!cur.empty())
                return true;
        }
    }
    return false;
}

static bool hasPageCarrierObjectTaint(GlobalState &state,
                                      std::vector<Instruction *> *ctx,
                                      CallInst &CI,
                                      Value *V,
                                      TaintKind kind) {
    if (!V || !DangerousSinkClassifier::isPageCarrier(V))
        return false;
    std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
    if (!ptos)
        return false;
    InstLoc loc(&CI, ctx);
    for (auto *pto : *ptos) {
        if (!pto || !pto->targetObject)
            continue;
        std::set<TaintFlag*> cur;
        pto->targetObject->getFieldTaintInfo(pto->dstfieldId, cur, &loc);
        if (hasTaggedTaintKind(&cur, kind))
            return true;
    }
    return false;
}

static bool hasAnyObjectTaint(GlobalState &state,
                              std::vector<Instruction *> *ctx,
                              CallInst &CI,
                              Value *V) {
    if (!V || !V->getType()->isPointerTy())
        return false;
    std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
    if (!ptos)
        return false;
    InstLoc loc(&CI, ctx);
    for (auto *pto : *ptos) {
        if (!pto || !pto->targetObject)
            continue;
        std::set<TaintFlag*> cur;
        pto->targetObject->getFieldTaintInfo(pto->dstfieldId, cur, &loc);
        if (hasAnyTaint(&cur))
            return true;
    }
    return false;
}

static bool hasAnyTaintedArg(GlobalState &state,
                             std::vector<Instruction *> *ctx,
                             CallInst &CI) {
    for (Use &Arg : CI.args()) {
        Value *V = Arg.get();
        std::set<TaintFlag*> *valTFs = TaintUtils::getTaintInfo(state, ctx, V);
        if (hasAnyTaint(valTFs))
            return true;
        if (hasAnyObjectTaint(state, ctx, CI, V))
            return true;
    }
    return false;
}
} // namespace

bool DangerousSinkClassifier::isPageCarrier(Value *v) {
    if (!v)
        return false;
    Type *ty = v->getType();
    return hasStructPrefix(ty, pageCarrierTypePrefixes);
}

bool DangerousSinkClassifier::isDangerousSink(GlobalState &state,
                                              std::vector<Instruction *> *ctx,
                                              Function &F,
                                              Instruction &I) {
    (void)F;

    if (auto *SI = dyn_cast<StoreInst>(&I)) {
        Value *ptr = SI->getPointerOperand();
        if (!ptr)
            return false;
        std::set<TaintFlag*> *valTFs = TaintUtils::getTaintInfo(state, ctx, ptr);
        return hasTaggedTaintKind(valTFs, TAINT_KIND_PAGE_ADDR);
    }

    auto *CI = dyn_cast<CallInst>(&I);
    if (!CI)
        return false;

    Function *callee = CI->getCalledFunction();
    if (callee && callee->hasName()) {
        StringRef name = callee->getName();
        if (name.equals("sg_init_table") || name.equals("sg_mark_end") ||
            name.equals("sg_chain") || name.equals("sg_unmark_end"))
            return false;
        if (name.equals("esp_input_done2")) {
#ifdef DEBUG_PAGEGRAPH_EXPORT
            dbgs() << "DangerousSinkDebug: esp_input_done2 page_container=" << hasTaintedPageContainerArg(state, ctx, *CI) << "\n";
#endif
            return hasTaintedPageContainerArg(state, ctx, *CI);
        }
        if (name.equals("pagecache_write_guard_skb")) {
            for (Use &Arg : CI->args()) {
                Value *V = Arg.get();
                if (!isPageBearingType(V->getType()))
                    continue;
                std::set<TaintFlag*> *valTFs = TaintUtils::getTaintInfo(state, ctx, V);
                if (hasTaggedTaintKind(valTFs, TAINT_KIND_PAGE))
                    return true;
                std::set<PointerPointsTo*> *ptos = PointsToUtils::getPointsToObjects(state, ctx, V);
                if (!ptos)
                    continue;
                InstLoc loc(&I, ctx);
                for (auto *pto : *ptos) {
                    if (!pto || !pto->targetObject)
                        continue;
                    std::set<TaintFlag*> cur;
                    pto->targetObject->getFieldTaintInfo(pto->dstfieldId, cur, &loc);
                    if (hasTaggedTaintKind(&cur, TAINT_KIND_PAGE))
                        return true;
                }
            }
            return false;
        }
    }

    if (!callee || callee->isDeclaration()) {
        if (callee && callee->isIntrinsic())
            return false;
        return hasAnyTaintedArg(state, ctx, *CI);
    }

    /*
     * 情况（1）：
     *   tainted page-container + scatterlist
     * 不在这里单独保留。
     *
     * 原因是外部函数传播规则已经会把这种调用里的 scatterlist 参数直接打脏，
     * 所以后续这里再看“污染的 page carrier 参数”即可覆盖，不需要重复保留
     * 一个更早的分类条件。
     */
    for (Use &Arg : CI->args()) {
        Value *V = Arg.get();
        if (!DangerousSinkClassifier::isPageCarrier(V))
            continue;
        std::set<TaintFlag*> *valTFs = TaintUtils::getTaintInfo(state, ctx, V);
        if (hasTaggedTaintKind(valTFs, TAINT_KIND_PAGE) ||
            hasPageCarrierObjectTaint(state, ctx, *CI, V, TAINT_KIND_PAGE))
            return true;
    }


    return false;
}
