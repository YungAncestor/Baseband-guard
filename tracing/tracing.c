#include "kernel_compat.h"
#include <linux/security.h>
#include <linux/errno.h>
#include <linux/cred.h>

int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
void bb_cred_transfer(struct cred *new, const struct cred *old);
int bb_bprm_set_creds(struct linux_binprm *bprm);

int __maybe_unused bbg_process_setpermissive(void);
int __maybe_unused bbg_test_domain_transition(u32 target_secid);

#ifdef BBG_USE_DEFINE_LSM
struct lsm_blob_sizes bbg_blob_sizes __ro_after_init = {
	.lbs_cred = sizeof(struct bbg_cred_security_struct),
};
#elif !defined(BBG_COMPAT_SELINUX_CRED)
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
	return cred->security;
}
#endif

int bb_cred_prepare(struct cred *new, const struct cred *old,
					gfp_t gfp)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
	return 0;
}
void bb_cred_transfer(struct cred *new, const struct cred *old)
{
	const struct bbg_cred_security_struct *old_tsec = bbg_cred(old);
	struct bbg_cred_security_struct *tsec = bbg_cred(new);

	*tsec = *old_tsec;
}

/*
 * Root-domain secid cache.  A domain such as "u:r:ksu:s0" only exists in the
 * policy after KernelSU's ksud injects it, which happens long after the first
 * execve() of boot; caching a failed security_secctx_to_secid() lookup forever
 * (as -EINVAL) made every root process look trusted, so the guard never
 * denied anything.  Only cache successful lookups and retry failures at a
 * low rate until the domain shows up in the policy.
 */
#define BBG_SID_RETRY_INTERVAL 256
static unsigned long bbg_exec_nr;

static void bbg_resolve_domain_sid(int *cached_sid, const char *ctx)
{
	u32 sid;

	if (likely(*cached_sid >= 0))
		return;
	if (*cached_sid != -EINVAL || !(bbg_exec_nr % BBG_SID_RETRY_INTERVAL))
		*cached_sid = security_secctx_to_secid(ctx, strlen(ctx), &sid)
			      ? -EINVAL : (int)sid;
}

int bb_bprm_set_creds(struct linux_binprm *bprm)
{
	static int su_sid = -1;
	static int magisk_sid = -1;
	static int ksu_sid = -1;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
	struct task_security_struct *new_selinux_tsec;
	const struct task_security_struct *old_selinux_tsec;
#else
	struct cred_security_struct *new_selinux_tsec;
	const struct cred_security_struct *old_selinux_tsec;
#endif
	const struct bbg_cred_security_struct *old_bbg_tsec;
	struct bbg_cred_security_struct *new_bbg_tsec;

	old_selinux_tsec = selinux_cred(current_cred());
	new_selinux_tsec = selinux_cred(bprm->cred);
	new_bbg_tsec = bbg_cred(bprm->cred);
	old_bbg_tsec = bbg_cred(current_cred());

	new_bbg_tsec->is_untrusted_process = old_bbg_tsec->is_untrusted_process;

	if (new_bbg_tsec->is_untrusted_process) {
		return 0; // already flag as untrusted_process, no need check current domain
	}

	if (unlikely(!selinux_initialized_compat())) return 0; // we keep this only for module scripts, i don't want hook execve

	bbg_exec_nr++;
	/* root impl compatible (su/magisk/ksu domains) */
	bbg_resolve_domain_sid(&su_sid, "u:r:su:s0");
	bbg_resolve_domain_sid(&magisk_sid, "u:r:magisk:s0");
	bbg_resolve_domain_sid(&ksu_sid, "u:r:ksu:s0");

	if (unlikely(
		old_selinux_tsec->sid == su_sid || old_selinux_tsec->osid == su_sid || // kernelsu old
		new_selinux_tsec->sid == su_sid || new_selinux_tsec->osid == su_sid ||

                old_selinux_tsec->sid == ksu_sid || old_selinux_tsec->osid == ksu_sid || // kernelsu new
                new_selinux_tsec->sid == ksu_sid || new_selinux_tsec->osid == ksu_sid ||

		old_selinux_tsec->sid == magisk_sid || old_selinux_tsec->osid == magisk_sid || // magisk/apatch
		new_selinux_tsec->sid == magisk_sid || new_selinux_tsec->osid == magisk_sid
	)) {
		new_bbg_tsec->is_untrusted_process = 1;
		pr_info("baseband_guard: pid %d has been marked as untrusted process due to its selinux domain\n",
			current->pid);
	}

	return 0;
}

int __maybe_unused bbg_process_setpermissive(void)
{
	return 0;
}

int __maybe_unused bbg_test_domain_transition(u32 target_secid)
{
	return 0;
}

#ifndef BBG_USE_DEFINE_LSM
struct bbg_cred_security_struct* bbg_cred(const struct cred *cred) {
	return &((struct task_security_struct *)cred->security)->bbg_cred;
}
#endif
