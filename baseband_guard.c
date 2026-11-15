#include <linux/module.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/blk_types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/hashtable.h>
#include <linux/major.h>
#include <linux/mman.h>
/* READING_MODULE/LOADING_MODULE enums: <linux/fs.h> on < 5.8,
 * <linux/kernel_read_file.h> on >= 5.8. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#include <linux/kernel_read_file.h>
#endif

#include "kernel_compat.h"
#include "baseband_guard.h"
#include "tracing/tracing.h"
#include "blkdev_helper.h"

struct device_hash_node { dev_t dev; struct hlist_node h; };
static DEFINE_HASHTABLE(allowed_devs, 7);
static DEFINE_SPINLOCK(allowed_devs_lock);

static bool allow_has(dev_t dev)
{
	struct device_hash_node *p;
	bool found = false;
	unsigned long flags;

	spin_lock_irqsave(&allowed_devs_lock, flags);
	hash_for_each_possible(allowed_devs, p, h, (u64)dev) {
		if (p->dev == dev) {
			found = true;
			break;
		}
	}
	spin_unlock_irqrestore(&allowed_devs_lock, flags);
	return found;
}

static void allow_add(dev_t dev)
{
	struct device_hash_node *n;
	struct device_hash_node *p_dup;
	bool dup = false;
	unsigned long flags;

	if (!dev) return;
	n = kmalloc(sizeof(*n), GFP_ATOMIC);
	if (!n) return;
	n->dev = dev;
	INIT_HLIST_NODE(&n->h);

	spin_lock_irqsave(&allowed_devs_lock, flags);
	hash_for_each_possible(allowed_devs, p_dup, h, (u64)dev) {
		if (p_dup->dev == dev) { dup = true; break; }
	}
	if (!dup)
		hash_add(allowed_devs, &n->h, (u64)dev);
	spin_unlock_irqrestore(&allowed_devs_lock, flags);

	if (dup) {
		kfree(n);
		return;
	}
	bb_pr("allow-cache dev %u:%u\n", MAJOR(dev), MINOR(dev));
}

/*
 * Raw SCSI passthrough devices (/dev/sgN): an untrusted process can issue
 * WRITE(10)/UNMAP/FORMAT UNIT against any LUN with a plain SG_IO ioctl or a
 * write(), which never touches a block device inode.  They are char devices,
 * so treat write access to them like a write to a protected partition.
 * (bsg char devices use a dynamic major and stay uncovered for now.)
 */
static bool bbg_is_raw_scsi_inode(struct inode *inode)
{
	return S_ISCHR(inode->i_mode) && imajor(inode) == SCSI_GENERIC_MAJOR;
}

static bool is_zram_device(dev_t dev)
{
	bool is_zram = bbg_is_named_device(dev, "zram");
	if (is_zram) {
		bb_pr("zram dev %u:%u identified, whitelisting\n",
				MAJOR(dev), MINOR(dev));
	}
	return is_zram;
}

static bool reverse_allow_match_and_cache(dev_t cur)
{
	if (!cur) return false;
	if (is_zram_device(cur)) {
		allow_add(cur);
		return true;
	}
	if (is_allowed_partition_dev_resolve(cur)) {
		allow_add(cur);
		return true;
	}
	return false;
}

static const char *bbg_file_path(struct file *file, char *buf, int buflen)
{
	char *p;
	if (!file || !buf || buflen <= 0) return NULL;
	buf[0] = '\0';
	p = d_path(&file->f_path, buf, buflen);
	return IS_ERR(p) ? NULL : p;
}

static int bbg_get_cmdline(char *buf, int buflen)
{
	int n, i;
	if (!buf || buflen <= 0) return 0;
	n = get_cmdline(current, buf, buflen);
	if (n <= 0) return 0;
	for (i = 0; i < n - 1; i++) if (buf[i] == '\0') buf[i] = ' ';
	if (n < buflen) buf[n] = '\0';
	else buf[buflen - 1] = '\0';
	return n;
}

static void bbg_log_deny_detail(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	const int PATH_BUFLEN = 256;
	const int CMD_BUFLEN  = 256;

	char *pathbuf = kmalloc(PATH_BUFLEN, GFP_ATOMIC);
	char *cmdbuf  = kmalloc(CMD_BUFLEN,  GFP_ATOMIC);

	const char *path = pathbuf ? bbg_file_path(file, pathbuf, PATH_BUFLEN) : NULL;
	dev_t dev = inode ? inode->i_rdev : 0;

	if (cmdbuf)
		bbg_get_cmdline(cmdbuf, CMD_BUFLEN);

	if (cmd_opt) {
		pr_info_ratelimited(
			"baseband_guard: deny %s cmd=0x%x dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, cmd_opt, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	} else {
		pr_info_ratelimited(
			"baseband_guard: deny %s dev=%u:%u path=%s pid=%d comm=%s argv=\"%s\"\n",
			why, MAJOR(dev), MINOR(dev),
			path ? path : "?", current->pid, current->comm,
			cmdbuf ? cmdbuf : "?");
	}

	kfree(cmdbuf);
	kfree(pathbuf);
}

static int deny(const char *why, struct file *file, struct inode *inode, unsigned int cmd_opt)
{
	bbg_log_deny_detail(why, file, inode, cmd_opt);
	bb_pr_rl("deny %s pid=%d comm=%s\n", why, current->pid, current->comm);
	if (!BB_ENFORCING) return 0;
	return -EPERM;
}

static int bb_file_permission(struct file *file, int mask)
{
	struct inode *inode;

	if (likely(current_process_trusted()))
		return 0;

	if (!(mask & MAY_WRITE)) return 0;
	if (!file) return 0;

	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode) && !bbg_is_raw_scsi_inode(inode)))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write to protected partition", file, inode, 0);
}

/*
 * Block write access at open() time as well.  file_permission() only fires on
 * read/write syscalls, so without this hook an untrusted process can open a
 * protected device O_RDWR (open() checks no BBG hook) and keep the fd around.
 * A read-only open stays allowed.
 */
#ifdef BBG_FILE_OPEN_HAS_CRED
static int bb_file_open(struct file *file, const struct cred *cred)
#else
static int bb_file_open(struct file *file)
#endif
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);

	if (likely(!S_ISBLK(inode->i_mode) && !bbg_is_raw_scsi_inode(inode)))
		return 0;

	if (likely(current_process_trusted()))
		return 0;

	if ((file->f_flags & O_ACCMODE) == O_RDONLY)
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("write-open on protected device", file, inode, 0);
}

/*
 * Writable mmap is a full bypass of the write path: block devices support
 * generic_file_mmap(), and a shared writable mapping writes sectors from the
 * fault path, which never calls security_file_permission().  Close it at
 * mmap() time.  MAP_PRIVATE|PROT_WRITE is copy-on-write and cannot reach the
 * device, but for a protected partition we fail closed on PROT_WRITE anyway.
 */
static int bb_file_mmap(struct file *file, unsigned long reqprot,
			unsigned long prot, unsigned long flags)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;
	if (likely(current_process_trusted())) return 0;

	if (!(prot & PROT_WRITE))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("writable mmap on protected partition", file, inode, 0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,9,0)
static int bb_inode_setattr(struct mnt_idmap *idmap, struct dentry *dentry, struct iattr *iattr)
#else
static int bb_inode_setattr(struct dentry *dentry, struct iattr *iattr) 
#endif
{
	struct inode *inode;

	if (current_process_trusted())
        return 0;
	
	inode = d_inode(dentry);

	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	return deny("setattr on protected partition", 0, inode, 0);
}

/*
 * Default-deny for untrusted processes on protected devices: allow only
 * read-only queries, deny every other ioctl, including the destructive ones
 * (BLKDISCARD, BLKZEROOUT, BLKRRPART, ...), raw SCSI passthrough (SG_IO --
 * WRITE(10)/UNMAP/FORMAT UNIT against any LBA), NVMe admin/io passthrough
 * (format/sanitize) and zoned-blk resets (BLKRESETZONE).  A blacklist can
 * never be complete; passthrough ioctls let an attacker invent new commands
 * faster than the list can follow.
 */
static inline bool is_query_ioctl(unsigned int cmd)
{
	switch (cmd) {
	case BLKROGET:
	case BLKGETSIZE:
	case BLKGETSIZE64:
	case BLKSSZGET:
	case BLKBSZGET:
	case BLKPBSZGET:
	case BLKALIGNOFF:
	case BLKIOMIN:
	case BLKIOOPT:
	case BLKSECTGET:
	case BLKROTATIONAL:
#ifdef BLKDISCARDZEROES
	case BLKDISCARDZEROES:
#endif
#ifdef BLKGETDISKSEQ
	case BLKGETDISKSEQ:
#endif
		return true;
	default:
		return false;
	}
}

static int bb_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct inode *inode;

	if (!file) return 0;
	inode = file_inode(file);
	if (likely(!S_ISBLK(inode->i_mode))) return 0;

	if (likely(current_process_trusted()))
		return 0;

	if (allow_has(inode->i_rdev) || reverse_allow_match_and_cache(inode->i_rdev))
		return 0;

	if (is_query_ioctl(cmd))
		return 0;

	return deny("ioctl on protected partition", file, inode, cmd);
}

#ifdef BB_HAS_IOCTL_COMPAT
static int bb_file_ioctl_compat(struct file *file, unsigned int cmd, unsigned long arg)
{
	return bb_file_ioctl(file, cmd, arg);
}
#endif

extern int bb_bprm_set_creds(struct linux_binprm *bprm);
extern void bb_cred_transfer(struct cred *new, const struct cred *old);
extern int bb_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

/*
 * Block module loading from untrusted processes.  A KPM is kernel code:
 * it can bypass every LSM hook in this file by writing sectors directly
 * through the bio layer, or patch BBG's own deny() out of the kernel.
 * Deny at the LSM boundary instead of trying to out-patch it.
 *
 * 4.14: only kernel_read_file exists; init_module() (memory blob) also calls
 *   security_kernel_read_file(NULL, READING_MODULE), so one hook covers both.
 * 5.1+: kernel_read_file gains a `contents` param and a separate
 *   kernel_load_data hook (init_module) is added.
 */
#ifdef BBG_HAS_KERNEL_LOAD_DATA
static int bb_kernel_load_data(enum kernel_load_data_id id, bool contents)
#else
static int bb_kernel_read_file(struct file *file, enum kernel_read_file_id id)
#endif
{
	if (likely(current_process_trusted()))
		return 0;

#ifdef BBG_HAS_KERNEL_LOAD_DATA
	if (id != LOADING_MODULE)
		return 0;
#else
	if (id != READING_MODULE)
		return 0;
#endif

	return deny("module load from untrusted process", NULL, NULL, 0);
}

#ifdef BBG_HAS_KERNEL_READ_FILE
static int bb_kernel_read_file(struct file *file,
				enum kernel_read_file_id id, bool contents)
{
	if (likely(current_process_trusted()))
		return 0;

	if (id != READING_MODULE)
		return 0;

	return deny("module load from untrusted process", NULL, NULL, 0);
}
#endif

static struct security_hook_list bb_hooks[] = {
	LSM_HOOK_INIT(file_permission,      bb_file_permission),
	LSM_HOOK_INIT(file_open,            bb_file_open),
	LSM_HOOK_INIT(mmap_file,            bb_file_mmap),
	LSM_HOOK_INIT(file_ioctl,           bb_file_ioctl),
	LSM_HOOK_INIT(inode_setattr, 		bb_inode_setattr),
#ifdef BBG_HAS_KERNEL_LOAD_DATA
	LSM_HOOK_INIT(kernel_load_data, 	bb_kernel_load_data),
#endif
	LSM_HOOK_INIT(kernel_read_file, 	bb_kernel_read_file),

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,8,0)
	LSM_HOOK_INIT(bprm_creds_for_exec,  bb_bprm_set_creds),
#else
	LSM_HOOK_INIT(bprm_set_creds, 		bb_bprm_set_creds),
#endif
	LSM_HOOK_INIT(cred_transfer, 		bb_cred_transfer),
	LSM_HOOK_INIT(cred_prepare, 	    bb_cred_prepare),

#ifdef BB_HAS_IOCTL_COMPAT
	LSM_HOOK_INIT(file_ioctl_compat,    bb_file_ioctl_compat),
#endif
};

static int __init bbg_init(void)
{
	security_add_hooks_compat(bb_hooks, ARRAY_SIZE(bb_hooks)); // init lsm hooks and print version notice
	pr_info("baseband_guard power by https://t.me/qdykernel\n");
	pr_info("baseband_guard repo: %s", __stringify(BBG_REPO));
	pr_info("baseband_guard version: %s", __stringify(BBG_VERSION));
	return 0;
}

extern struct lsm_blob_sizes bbg_blob_sizes;

#ifndef BBG_USE_DEFINE_LSM
security_initcall(bbg_init);
#else
DEFINE_LSM(baseband_guard) = {
	.name = "baseband_guard",
	.init = bbg_init,
	.blobs = &bbg_blob_sizes
};
#endif

MODULE_DESCRIPTION("protect All Block & Power by TG@qdykernel");
MODULE_AUTHOR("秋刀鱼 & https://t.me/qdykernel");
MODULE_LICENSE("GPL v2");


