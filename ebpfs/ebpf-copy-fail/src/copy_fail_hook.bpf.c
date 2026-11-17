#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "../../include/inode_ugo.bpf.h"
#include "sg_scan.bpf.h"

char LICENSE[] SEC("license") = "GPL";
extern int bpf_set_regs(struct pt_regs *regs, const void *src, u32 src__sz) __ksym;
extern int bpf_skip_call(struct pt_regs *regs, unsigned long retval,
                        u32 call_size) __ksym;

/* Tests compile the same hooks with a child-process filter. Production guards
 * apply to every task; there is no runtime switch that silently narrows scope. */
#ifndef CF_GUARD_ACTIVE
#define CF_GUARD_ACTIVE() 1
#endif

static __always_inline void copy_pt_regs(struct pt_regs *dst,
					 const struct pt_regs *src) {
	dst->r15 = BPF_CORE_READ(src, r15);
	dst->r14 = BPF_CORE_READ(src, r14);
	dst->r13 = BPF_CORE_READ(src, r13);
	dst->r12 = BPF_CORE_READ(src, r12);
	dst->bp = BPF_CORE_READ(src, bp);
	dst->bx = BPF_CORE_READ(src, bx);
	dst->r11 = BPF_CORE_READ(src, r11);
	dst->r10 = BPF_CORE_READ(src, r10);
	dst->r9 = BPF_CORE_READ(src, r9);
	dst->r8 = BPF_CORE_READ(src, r8);
	dst->ax = BPF_CORE_READ(src, ax);
	dst->cx = BPF_CORE_READ(src, cx);
	dst->dx = BPF_CORE_READ(src, dx);
	dst->si = BPF_CORE_READ(src, si);
	dst->di = BPF_CORE_READ(src, di);
	dst->orig_ax = BPF_CORE_READ(src, orig_ax);
	dst->ip = BPF_CORE_READ(src, ip);
	dst->cs = BPF_CORE_READ(src, cs);
	dst->flags = BPF_CORE_READ(src, flags);
	dst->sp = BPF_CORE_READ(src, sp);
	dst->ss = BPF_CORE_READ(src, ss);
}


/* Fixed sites for the documented algif_aead.ko build. The first guard
 * protects the RX writes made by both void memcpy_sglist() calls. It runs
 * before those calls and uses af_alg_get_rsgl's existing error cleanup. */
SEC("kprobe/aead_recvmsg+0x11d")
int hook_aead_recvmsg_11d(struct pt_regs *ctx)
{
    struct cf_scan scan = {};
    struct af_alg_async_req___cf *areq;
    struct af_alg_rsgl___cf *last;
    struct scatterlist *rx = NULL;
    int rc;

    if (!CF_GUARD_ACTIVE() || PT_REGS_RC(ctx)) return 0;
    areq = (void *)BPF_CORE_READ(ctx, r15);
    if (!areq) {
        scan.error = CF_BAD_STRUCTURE;
        goto deny;
    }
    /* No RX buffers is valid for authentication-only requests. */
    if (BPF_CORE_READ_INTO(&last, areq, last_rsgl)) {
        scan.error = CF_READ_ERROR;
        goto deny;
    }
    if (last && (BPF_CORE_READ_INTO(&rx, areq, first_rsgl.sgl.sgt.sgl) || !rx)) {
        scan.error = CF_READ_ERROR;
        goto deny;
    }
    /* TX is only a copy source here. Never require its write permission. */
    if (cf_scan_init(&scan, rx, NULL)) goto deny;
    if (!cf_scan_run(&scan, COPY_FAIL_SCAN_LIMIT)) return 0;
deny:
    {
        struct pt_regs regs = {};
        copy_pt_regs(&regs, ctx);
        regs.ax = (unsigned long)CF_DENY;
        rc = bpf_set_regs(ctx, &regs, sizeof(regs));
        bpf_printk("copy-fail RX denied reason=%u steps=%u pages=%u",
                   scan.error, scan.steps, scan.pages_checked);
        if (rc) bpf_printk("copy-fail register override failed: %d", rc);
    }
    return 1;
}

/* The destination SG is finalized after the first guard. In decryption the
 * kernel may append file-backed TX tag pages to it. Scan that final chain before
 * either sync or AIO crypto call; skipping it returns -EACCES through the normal
 * sock_put()/af_alg_free_resources() path. Scanning only the early RX list would
 * miss precisely the writable alias used by Copy Fail. */
static __always_inline int guard_crypto_call(struct pt_regs *ctx)
{
    struct cf_scan scan = {};
    struct aead_request *req = (void *)PT_REGS_PARM1(ctx);
    int rc;

    if (!CF_GUARD_ACTIVE()) return 0;
    if (!cf_scan_aead_dst(&scan, req, COPY_FAIL_SCAN_LIMIT)) return 0;
    rc = bpf_skip_call(ctx, (unsigned long)CF_DENY, 5);
    bpf_printk("copy-fail crypto denied reason=%u steps=%u pages=%u",
               scan.error, scan.steps, scan.pages_checked);
    if (rc) bpf_printk("copy-fail skip call failed: %d", rc);
    return 1;
}

/* Offsets point to the CALL itself, not to its return address. */
SEC("kprobe/aead_recvmsg+0x383")
int hook_aead_decrypt_aio(struct pt_regs *ctx) { return guard_crypto_call(ctx); }
SEC("kprobe/aead_recvmsg+0x3f6")
int hook_aead_encrypt_sync(struct pt_regs *ctx) { return guard_crypto_call(ctx); }
SEC("kprobe/aead_recvmsg+0x542")
int hook_aead_decrypt_sync(struct pt_regs *ctx) { return guard_crypto_call(ctx); }
SEC("kprobe/aead_recvmsg+0x577")
int hook_aead_encrypt_aio(struct pt_regs *ctx) { return guard_crypto_call(ctx); }
