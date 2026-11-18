#include "PageTaintPropagation.h"
#include "TaintAnalysisVisitor.h"
#include "PointsToUtils.h"
#include "InstructionUtils.h"

using namespace llvm;
using namespace DRCHECKER;

namespace {
static std::set<TaintFlag*> filterByKind(const std::set<TaintFlag*> &src, TaintKind kind) {
    std::set<TaintFlag*> ret;
    for (TaintFlag *tf : src) {
        if (tf && tf->tag && tf->tag->kind == kind)
            ret.insert(tf);
    }
    return ret;
}

static bool isPageBearingPointer(Value *v) {
    if (!v)
        return false;
    Type *ty = v->getType();
    if (!ty || !ty->isPointerTy())
        return false;
    Type *elem = ty->getPointerElementType();
    StructType *st = dyn_cast<StructType>(elem);
    if (!st || !st->hasName())
        return false;
    StringRef name = st->getStructName();
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
           name.startswith("struct.af_alg_sgl") ||
           name.startswith("struct.af_alg_tsgl") ||
           name.startswith("struct.af_alg_async_req") ||
           name.startswith("struct.page") ||
           name.startswith("struct.netmem");
}

static bool isScatterlistPointerType(Type *ty) {
    if (!ty || !ty->isPointerTy())
        return false;
    Type *elem = ty->getPointerElementType();
    StructType *st = dyn_cast<StructType>(elem);
    return st && st->hasName() && st->getStructName().startswith("struct.scatterlist");
}

static bool isFirstRsglSglPtrGep(GetElementPtrInst *gep, Value *basePtr) {
    if (!gep || gep->getPointerOperand() != basePtr)
        return false;
    if (!isScatterlistPointerType(gep->getType()))
        return false;

    SmallVector<long, 8> idxs;
    for (auto it = gep->idx_begin(); it != gep->idx_end(); ++it) {
        auto *ci = dyn_cast<ConstantInt>(it->get());
        if (!ci)
            return false;
        idxs.push_back(ci->getSExtValue());
    }
    return idxs.size() == 5 &&
           idxs[0] == 0 &&
           idxs[1] == 2 &&
           idxs[2] == 0 &&
           idxs[3] == 0 &&
           idxs[4] == 0;
}

static void addPageTaintToPointerPointees(TaintAnalysisVisitor &visitor,
                                          Value *ptrVal,
                                          Instruction *site,
                                          const std::set<TaintFlag*> &pageOnly) {
    if (!ptrVal || !site || pageOnly.empty())
        return;

    std::set<PointerPointsTo*> *ptos =
        PointsToUtils::getPointsToObjects(visitor.currState, visitor.currFuncCallSites, ptrVal);
    if (!ptos || ptos->empty())
        return;

    std::set<TaintFlag*> *newTaintInfo =
        visitor.makeTaintInfoCopy(site, const_cast<std::set<TaintFlag*>*>(&pageOnly));
    if (!newTaintInfo || newTaintInfo->empty())
        return;

    std::set<TaintFlag*> addedTFs;
    bool multi_pto = (ptos->size() > 1);
    for (PointerPointsTo *pto : *ptos) {
        if (!pto || !pto->targetObject)
            continue;
        for (TaintFlag *tf : *newTaintInfo) {
            tf->is_weak |= multi_pto;
            if (pto->targetObject->addFieldTaintFlag(pto->dstfieldId, tf, true))
                addedTFs.insert(tf);
        }
    }
    if (addedTFs.size() < newTaintInfo->size()) {
        for (TaintFlag *tf : *newTaintInfo) {
            if (addedTFs.find(tf) == addedTFs.end())
                delete(tf);
        }
    }
    delete newTaintInfo;
}

}

bool PageTaintPropagation::isPageAddressFunction(const Function *F) {
    if (!F || !F->hasName())
        return false;
    StringRef n = F->getName();
    return n.equals("page_address") ||
           n.equals("kmap_local_page") ||
           n.equals("folio_address") ||
           n.equals("page_to_virt");
}

bool PageTaintPropagation::isPointerLike(Value *v) {
    if (!v)
        return false;
    Type *ty = v->getType();
    return ty && ty->isPointerTy();
}

void PageTaintPropagation::handleDefinedFunction(TaintAnalysisVisitor &visitor,
                                                 CallInst &I,
                                                 Function *currFunc) {
    if (!currFunc || !currFunc->hasName())
        return;

    if (currFunc->getName().equals("af_alg_get_rsgl") && I.arg_size() >= 4) {
        Value *msgArg = I.getArgOperand(1);
        Value *areqArg = I.getArgOperand(3);
        std::set<TaintFlag*> msgPtrObjectTaint;
        visitor.getPtrTaintInfo(msgArg, msgPtrObjectTaint, &I);
        std::set<TaintFlag*> pageOnly = filterByKind(msgPtrObjectTaint, TAINT_KIND_PAGE);
        if (pageOnly.empty())
            return;

        std::set<TaintFlag*> *newTaintInfo = visitor.makeTaintInfoCopy(&I, &pageOnly);
        std::set<PointerPointsTo*> *dstPointsTo =
            PointsToUtils::getPointsToObjects(visitor.currState,
                                              visitor.currFuncCallSites,
                                              areqArg);
        if (newTaintInfo && dstPointsTo) {
            for (PointerPointsTo *pto : *dstPointsTo) {
                if (!pto || !pto->targetObject)
                    continue;
                for (TaintFlag *tf : *newTaintInfo) {
                    pto->targetObject->addFieldTaintFlag(2, tf, true);
                    pto->targetObject->addFieldTaintFlag(3, tf, false);
                }
            }
        }

        Function *caller = I.getFunction();
        if (!caller)
            return;
        for (BasicBlock &BB : *caller) {
            for (Instruction &Inst : BB) {
                auto *LI = dyn_cast<LoadInst>(&Inst);
                if (!LI || !isScatterlistPointerType(LI->getType()))
                    continue;
                auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
                if (!isFirstRsglSglPtrGep(GEP, areqArg))
                    continue;
                std::set<TaintFlag*> *tmp = visitor.makeTaintInfoCopy(LI, &pageOnly);
                if (tmp && !tmp->empty()) {
                    visitor.updateTaintInfo(LI, tmp);
                }
                addPageTaintToPointerPointees(visitor, LI, LI, pageOnly);
            }
        }
        return;
    }

    if (currFunc->getName().equals("extract_iter_to_sg") && I.arg_size() >= 3) {
        Value *iterArg = I.getArgOperand(0);
        Value *sgtArg = I.getArgOperand(2);
        std::set<TaintFlag*> iterPtrObjectTaint;
        visitor.getPtrTaintInfo(iterArg, iterPtrObjectTaint, &I);
        std::set<TaintFlag*> pageOnly = filterByKind(iterPtrObjectTaint, TAINT_KIND_PAGE);
        if (pageOnly.empty())
            return;

        Function *caller = I.getFunction();
        if (!caller)
            return;

        SmallVector<Value *, 4> matchedPtrSlots;
        for (BasicBlock &BB : *caller) {
            for (Instruction &Inst : BB) {
                auto *LI = dyn_cast<LoadInst>(&Inst);
                if (!LI || !isScatterlistPointerType(LI->getType()))
                    continue;
                auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
                if (!GEP || GEP->getPointerOperand() != sgtArg)
                    continue;

                SmallVector<long, 8> idxs;
                bool ok = true;
                for (auto it = GEP->idx_begin(); it != GEP->idx_end(); ++it) {
                    auto *ci = dyn_cast<ConstantInt>(it->get());
                    if (!ci) {
                        ok = false;
                        break;
                    }
                    idxs.push_back(ci->getSExtValue());
                }
                if (!ok)
                    continue;
                if (idxs.size() != 2 || idxs[0] != 0 || idxs[1] != 0)
                    continue;
                matchedPtrSlots.push_back(LI->getPointerOperand());
                std::set<TaintFlag*> *newTaintInfo =
                    visitor.makeTaintInfoCopy(LI, &pageOnly);
                if (newTaintInfo && !newTaintInfo->empty())
                    visitor.updateTaintInfo(LI, newTaintInfo);
                addPageTaintToPointerPointees(visitor, LI, LI, pageOnly);
            }
        }

        for (BasicBlock &BB : *caller) {
            for (Instruction &Inst : BB) {
                auto *LI = dyn_cast<LoadInst>(&Inst);
                if (!LI || !isScatterlistPointerType(LI->getType()))
                    continue;
                if (std::find(matchedPtrSlots.begin(), matchedPtrSlots.end(), LI->getPointerOperand()) == matchedPtrSlots.end())
                    continue;
                std::set<TaintFlag*> *newTaintInfo =
                    visitor.makeTaintInfoCopy(LI, &pageOnly);
                if (newTaintInfo && !newTaintInfo->empty())
                    visitor.updateTaintInfo(LI, newTaintInfo);
                addPageTaintToPointerPointees(visitor, LI, LI, pageOnly);
            }
        }
    }
}

void PageTaintPropagation::handleExternalFunction(TaintAnalysisVisitor &visitor,
                                                  CallInst &I,
                                                  Function *currFunc) {
    if (!currFunc)
        return;

    if (PageTaintPropagation::isPageAddressFunction(currFunc) && I.arg_size() >= 1) {
        Value *srcArg = I.getArgOperand(0);
        std::set<TaintFlag*> srcPtrObjectTaint;
        visitor.getPtrTaintInfo(srcArg, srcPtrObjectTaint, &I);
        std::set<TaintFlag*> pageOnly = filterByKind(srcPtrObjectTaint, TAINT_KIND_PAGE);
        if (!pageOnly.empty()) {
            std::set<TaintFlag*> *newTaintInfo = visitor.makeTaintInfoCopy(&I, &pageOnly);
            if (newTaintInfo) {
                for (TaintFlag *tf : *newTaintInfo) {
                    if (!tf || !tf->tag)
                        continue;
                    tf->tag = new TaintTag(tf->tag);
                    tf->tag->kind = TAINT_KIND_PAGE_ADDR;
                }
                visitor.updateTaintInfo(&I, newTaintInfo);
            }
        }
        return;
    }

    /*
     * af_alg_get_rsgl():
     * msg 里的 output pages 会被抽成 RX scatterlist，落到
     * areq->first_rsgl / areq->last_rsgl 这条链上。
     *
     * 这里不再把 taint 粗暴打到整个 areq 对象，只点亮：
     * 1. areq->first_rsgl.sgl.sgt.sgl
     * 2. areq->last_rsgl
     *
     * 后续如果 caller 用 last_rsgl->sgl.sgt.sgl 做 sg_chain(...)，
     * 泛化的 scatterlist 参数传播会再把 PAGE 带到 areq->tsgl。
     */
    if (currFunc->hasName() && currFunc->getName().equals("skb_to_sgvec") && I.arg_size() >= 2) {
        Value *skbArg = I.getArgOperand(0);
        Value *sgArg = I.getArgOperand(1);
        std::set<TaintFlag*> skbPtrObjectTaint;
        visitor.getPtrTaintInfo(skbArg, skbPtrObjectTaint, &I);
        std::set<TaintFlag*> pageOnly = filterByKind(skbPtrObjectTaint, TAINT_KIND_PAGE);
        if (pageOnly.empty())
            return;

        std::set<TaintFlag*> *newTaintInfo = visitor.makeTaintInfoCopy(&I, &pageOnly);
        if (newTaintInfo && !newTaintInfo->empty())
            visitor.updateTaintInfo(sgArg, newTaintInfo);
        addPageTaintToPointerPointees(visitor, sgArg, &I, pageOnly);
        return;
    }

    if (currFunc->hasName() && currFunc->getName().equals("af_alg_get_rsgl")) {
        if (I.arg_size() >= 4) {
            Value *msgArg = I.getArgOperand(1);
            Value *areqArg = I.getArgOperand(3);
            std::set<TaintFlag*> msgPtrObjectTaint;
            visitor.getPtrTaintInfo(msgArg, msgPtrObjectTaint, &I);
            std::set<TaintFlag*> pageOnly = filterByKind(msgPtrObjectTaint, TAINT_KIND_PAGE);
            if (!pageOnly.empty()) {
                std::set<TaintFlag*> *newTaintInfo = visitor.makeTaintInfoCopy(&I, &pageOnly);
                std::set<PointerPointsTo*> *dstPointsTo =
                    PointsToUtils::getPointsToObjects(visitor.currState,
                                                      visitor.currFuncCallSites,
                                                      areqArg);
                if (newTaintInfo && dstPointsTo) {
                    for (PointerPointsTo *pto : *dstPointsTo) {
                        if (!pto || !pto->targetObject)
                            continue;
                        for (TaintFlag *tf : *newTaintInfo) {
                            pto->targetObject->addFieldTaintFlag(2, tf, true);
                            pto->targetObject->addFieldTaintFlag(3, tf, false);
                        }
                    }
                }

                Function *caller = I.getFunction();
                if (caller) {
                    for (BasicBlock &BB : *caller) {
                        for (Instruction &Inst : BB) {
                            auto *LI = dyn_cast<LoadInst>(&Inst);
                            if (!LI || !isScatterlistPointerType(LI->getType()))
                                continue;
                            auto *GEP = dyn_cast<GetElementPtrInst>(LI->getPointerOperand());
                            if (!isFirstRsglSglPtrGep(GEP, areqArg))
                                continue;
                            addPageTaintToPointerPointees(visitor, LI, LI, pageOnly);
                        }
                    }
                }
            }
        }
        return;
    }

    SmallVector<Value *, 8> pointerArgs;
    Value *taintedPointerArg = nullptr;

    for (unsigned int i = 0; i < I.arg_size(); ++i) {
        Value *arg = I.getArgOperand(i);
        if (!PageTaintPropagation::isPointerLike(arg))
            continue;
        if (!isPageBearingPointer(arg))
            continue;
        pointerArgs.push_back(arg);
        if (!taintedPointerArg) {
            std::set<TaintFlag*> ptrTaint;
            visitor.getPtrTaintInfo(arg, ptrTaint, &I);
            std::set<TaintFlag*> pageOnly = filterByKind(ptrTaint, TAINT_KIND_PAGE);
            if (!pageOnly.empty())
                taintedPointerArg = arg;
        }
    }

    if (!taintedPointerArg)
        return;

    for (Value *dstArg : pointerArgs) {
        if (dstArg == taintedPointerArg)
            continue;
        visitor.propagatePtrObjectTaintToPointer(taintedPointerArg, dstArg, &I);
    }

    /*
     * 泛化外部函数传播只负责“参数到参数”的污染扩散。
     * 不再把 call 返回值本身打成 PAGE。
     *
     * 否则像 sock_kmalloc()/af_alg_count_tsgl()/af_alg_get_rsgl() 这种
     * 返回新值/新内存的外部函数，会因为参数里带 PAGE 而把返回值错误污染，
     * 后面再沿着普通值传播把 PAGE 扩散到无关 SSA 值上。
     *
     * PAGE_ADDR 是特例，仍然只在 page_address/kmap_local_page/
     * folio_address/page_to_virt 这 4 个地址计算函数上生成。
     */
}
