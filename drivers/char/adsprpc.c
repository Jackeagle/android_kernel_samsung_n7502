/*
 * Copyright (c) 2012-2013, The Linux Foundation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include "adsprpc_shared.h"

#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/pagemap.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/msm_ion.h>
#include <mach/msm_smd.h>
#include <mach/ion.h>
#include <mach/iommu_domains.h>
#include <linux/scatterlist.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/of.h>
#include <linux/iommu.h>
#include <linux/kref.h>

#ifndef ION_ADSPRPC_HEAP_ID
#define ION_ADSPRPC_HEAP_ID ION_AUDIO_HEAP_ID
#endif /*ION_ADSPRPC_HEAP_ID*/

#define RPC_TIMEOUT	(5 * HZ)
#define RPC_HASH_BITS	5
#define RPC_HASH_SZ	(1 << RPC_HASH_BITS)
#define BALIGN		32
<<<<<<< HEAD
=======
#define NUM_CHANNELS	 1
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60

#define LOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				down_read(&current->mm->mmap_sem);\
		} while (0)

#define UNLOCK_MMAP(kernel)\
		do {\
			if (!kernel)\
				up_read(&current->mm->mmap_sem);\
		} while (0)


#define IS_CACHE_ALIGNED(x) (((x) & ((L1_CACHE_BYTES)-1)) == 0)

static inline uint32_t buf_page_start(void *buf)
{
	uint32_t start = (uint32_t) buf & PAGE_MASK;
	return start;
}

static inline uint32_t buf_page_offset(void *buf)
{
	uint32_t offset = (uint32_t) buf & (PAGE_SIZE - 1);
	return offset;
}

static inline int buf_num_pages(void *buf, int len)
{
	uint32_t start = buf_page_start(buf) >> PAGE_SHIFT;
	uint32_t end = (((uint32_t) buf + len - 1) & PAGE_MASK) >> PAGE_SHIFT;
	int nPages = end - start + 1;
	return nPages;
}

static inline uint32_t buf_page_size(uint32_t size)
{
	uint32_t sz = (size + (PAGE_SIZE - 1)) & PAGE_MASK;
	return sz > PAGE_SIZE ? sz : PAGE_SIZE;
}

static inline int buf_get_pages(void *addr, int sz, int nr_pages, int access,
				  struct smq_phy_page *pages, int nr_elems)
{
	struct vm_area_struct *vma, *vmaend;
	uint32_t start = buf_page_start(addr);
	uint32_t end = buf_page_start((void *)((uint32_t)addr + sz - 1));
	uint32_t len = nr_pages << PAGE_SHIFT;
	unsigned long pfn, pfnend;
	int n = -1, err = 0;

	VERIFY(err, 0 != access_ok(access ? VERIFY_WRITE : VERIFY_READ,
					(void __user *)start, len));
	if (err)
		goto bail;
	VERIFY(err, 0 != (vma = find_vma(current->mm, start)));
	if (err)
		goto bail;
	VERIFY(err, 0 != (vmaend = find_vma(current->mm, end)));
	if (err)
		goto bail;
	n = 0;
	VERIFY(err, 0 == follow_pfn(vma, start, &pfn));
	if (err)
		goto bail;
	VERIFY(err, 0 == follow_pfn(vmaend, end, &pfnend));
	if (err)
		goto bail;
	VERIFY(err, (pfn + nr_pages - 1) == pfnend);
	if (err)
		goto bail;
	VERIFY(err, nr_elems > 0);
	if (err)
		goto bail;
	pages->addr = __pfn_to_phys(pfn);
	pages->size = len;
	n++;
 bail:
	return n;
}

struct fastrpc_buf {
	struct ion_handle *handle;
	void *virt;
	ion_phys_addr_t phys;
	int size;
	int used;
};

struct smq_context_list;

struct smq_invoke_ctx {
	struct hlist_node hn;
	struct completion work;
	int retval;
<<<<<<< HEAD
=======
	int cid;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	int pid;
	remote_arg_t *pra;
	remote_arg_t *rpra;
	struct fastrpc_buf obuf;
	struct fastrpc_buf *abufs;
	struct fastrpc_device *dev;
<<<<<<< HEAD
	struct fastrpc_apps *apps;
	int *fds;
	struct ion_handle **handles;
=======
	struct fastrpc_apps *apps; 
	int* fds;
	struct ion_handle** handles;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	int nbufs;
	bool smmu;
	uint32_t sc;
};

struct smq_context_list {
	struct hlist_head pending;
	struct hlist_head interrupted;
	spinlock_t hlock;
};

struct fastrpc_smmu {
	struct iommu_group *group;
	struct iommu_domain *domain;
	int domain_id;
	bool enabled;
};

<<<<<<< HEAD
struct fastrpc_apps {
	smd_channel_t *chan;
	struct smq_context_list clst;
	struct completion work;
	struct ion_client *iclient;
	struct cdev cdev;
	struct class *class;
	struct device *dev;
	struct fastrpc_smmu smmu;
=======
struct fastrpc_channel_context {
	smd_channel_t *chan;
	struct device *dev;
	struct completion work;
	struct fastrpc_smmu smmu;
	struct kref kref;
};

struct fastrpc_apps {
	struct fastrpc_channel_context channel[NUM_CHANNELS];
	struct smq_context_list clst;
	struct ion_client *iclient;
	struct cdev cdev;
	struct class *class;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	struct mutex smd_mutex;
	dev_t dev_no;
	spinlock_t wrlock;
	spinlock_t hlock;
<<<<<<< HEAD
	struct kref kref;
=======
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	struct hlist_head htbl[RPC_HASH_SZ];
};

struct fastrpc_mmap {
	struct hlist_node hn;
	struct ion_handle *handle;
	void *virt;
	ion_phys_addr_t phys;
	uint32_t vaddrin;
	uint32_t vaddrout;
	int size;
};

struct file_data {
	spinlock_t hlock;
	struct hlist_head hlst;
	uint32_t mode;
<<<<<<< HEAD
=======
	int cid;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
};

struct fastrpc_device {
	uint32_t tgid;
	struct hlist_node hn;
	struct fastrpc_buf buf;
};

<<<<<<< HEAD
static struct fastrpc_apps gfa;

static void free_mem(struct fastrpc_buf *buf)
=======
struct fastrpc_channel_info {
	char *name;
	char *node;
	char *group;
	int channel;
};

static struct fastrpc_apps gfa;

static const struct fastrpc_channel_info gcinfo[NUM_CHANNELS] = {
	{
		.name = "adsprpc-smd",
		.node = "qcom,msm-audio-ion",
		.group = "lpass_audio",
		.channel = SMD_APPS_QDSP,
	}
};

static void free_mem(struct fastrpc_buf *buf, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_apps *me = &gfa;

	if (!IS_ERR_OR_NULL(buf->handle)) {
<<<<<<< HEAD
		if (me->smmu.enabled && buf->phys) {
			ion_unmap_iommu(me->iclient, buf->handle,
					me->smmu.domain_id, 0);
=======
		if (me->channel[cid].smmu.enabled && buf->phys) {
			ion_unmap_iommu(me->iclient, buf->handle,
					me->channel[cid].smmu.domain_id, 0);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			buf->phys = 0;
		}
		if (!IS_ERR_OR_NULL(buf->virt)) {
			ion_unmap_kernel(me->iclient, buf->handle);
			buf->virt = 0;
		}
		ion_free(me->iclient, buf->handle);
		buf->handle = 0;
	}
}

<<<<<<< HEAD
static void free_map(struct fastrpc_mmap *map)
{
	struct fastrpc_apps *me = &gfa;
	if (!IS_ERR_OR_NULL(map->handle)) {
		if (me->smmu.enabled && map->phys) {
			ion_unmap_iommu(me->iclient, map->handle,
					me->smmu.domain_id, 0);
=======
static void free_map(struct fastrpc_mmap *map, int cid)
{
	struct fastrpc_apps *me = &gfa;
	if (!IS_ERR_OR_NULL(map->handle)) {
		if (me->channel[cid].smmu.enabled && map->phys) {
			ion_unmap_iommu(me->iclient, map->handle,
					me->channel[cid].smmu.domain_id, 0);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			map->phys = 0;
		}
		if (!IS_ERR_OR_NULL(map->virt)) {
			ion_unmap_kernel(me->iclient, map->handle);
			map->virt = 0;
		}
		ion_free(me->iclient, map->handle);
	}
	map->handle = 0;
}

<<<<<<< HEAD
static int alloc_mem(struct fastrpc_buf *buf)
=======
static int alloc_mem(struct fastrpc_buf *buf, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_apps *me = &gfa;
	struct ion_client *clnt = gfa.iclient;
	struct sg_table *sg;
	int err = 0;
	unsigned int heap;
	unsigned long len;
	buf->handle = 0;
	buf->virt = 0;
	buf->phys = 0;
<<<<<<< HEAD
	heap = me->smmu.enabled ? ION_HEAP(ION_IOMMU_HEAP_ID) :
=======
	heap = me->channel[cid].smmu.enabled ? ION_HEAP(ION_IOMMU_HEAP_ID) :
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		ION_HEAP(ION_ADSP_HEAP_ID) | ION_HEAP(ION_AUDIO_HEAP_ID);
	buf->handle = ion_alloc(clnt, buf->size, SZ_4K, heap, ION_FLAG_CACHED);
	VERIFY(err, 0 == IS_ERR_OR_NULL(buf->handle));
	if (err)
		goto bail;
	buf->virt = ion_map_kernel(clnt, buf->handle);
	VERIFY(err, 0 == IS_ERR_OR_NULL(buf->virt));
	if (err)
		goto bail;
<<<<<<< HEAD
	if (me->smmu.enabled) {
		len = buf->size;
		VERIFY(err, 0 == ion_map_iommu(clnt, buf->handle,
					me->smmu.domain_id, 0, SZ_4K, 0,
					&buf->phys, &len, 0, 0));
=======
	if (me->channel[cid].smmu.enabled) {
		len = buf->size;
		VERIFY(err, 0 == ion_map_iommu(clnt, buf->handle,
					me->channel[cid].smmu.domain_id, 0,
					SZ_4K, 0, &buf->phys, &len, 0, 0));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
	} else {
		VERIFY(err, 0 != (sg = ion_sg_table(clnt, buf->handle)));
		if (err)
			goto bail;
		buf->phys = sg_dma_address(sg->sgl);
	}
 bail:
	if (err && !IS_ERR_OR_NULL(buf->handle))
<<<<<<< HEAD
		free_mem(buf);
	return err;
}

static int context_restore_interrupted(struct fastrpc_apps *me,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				struct smq_invoke_ctx **po)
=======
		free_mem(buf, cid);
	return err;
}

static void context_list_ctor(struct smq_context_list *me)
{
	INIT_HLIST_HEAD(&me->interrupted);
	INIT_HLIST_HEAD(&me->pending);
	spin_lock_init(&me->hlock);
}

static void context_free(struct smq_invoke_ctx *ctx, bool lock);

static void context_list_dtor(struct fastrpc_apps *me, struct smq_context_list *clst) {
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *pos, *n;
	spin_lock(&clst->hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &clst->interrupted, hn) {
		context_free(ictx, 0);
	}
	hlist_for_each_entry_safe(ictx, pos, n, &clst->pending, hn) {
		context_free(ictx, 0);
	}
	spin_unlock(&clst->hlock);
}

static int context_restore_interrupted(struct fastrpc_apps *me,
				struct fastrpc_ioctl_invoke_fd *invokefd,
				int cid, struct smq_invoke_ctx **po)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	int err = 0;
	struct smq_invoke_ctx *ctx = 0, *ictx = 0;
	struct hlist_node *pos, *n;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	spin_lock(&me->clst.hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &me->clst.interrupted, hn) {
<<<<<<< HEAD
		if (ictx->pid == current->pid) {
			if (invoke->sc != ictx->sc)
=======
		if(ictx->pid == current->pid) {
			if(invoke->sc != ictx->sc || ictx->cid != cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
				err = -1;
			else {
				ctx = ictx;
				hlist_del(&ctx->hn);
				hlist_add_head(&ctx->hn, &me->clst.pending);
			}
			break;
		}
	}
	spin_unlock(&me->clst.hlock);
<<<<<<< HEAD
	if (ctx)
		*po = ctx;
=======
	if(ctx) {
		*po = ctx;
	}
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	return err;
}

static int context_alloc(struct fastrpc_apps *me, uint32_t kernel,
				struct fastrpc_ioctl_invoke_fd *invokefd,
<<<<<<< HEAD
=======
				int cid,
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
				struct smq_invoke_ctx **po)
{
	int err = 0, bufs, size = 0;
	struct smq_invoke_ctx *ctx = 0;
	struct smq_context_list *clst = &me->clst;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;

	bufs = REMOTE_SCALARS_INBUFS(invoke->sc) +
			REMOTE_SCALARS_OUTBUFS(invoke->sc);
	if (bufs) {
		size = bufs * sizeof(*ctx->pra);
		if (invokefd->fds)
			size = size + bufs * sizeof(*ctx->fds) +
				bufs * sizeof(*ctx->handles);
	}

	VERIFY(err, 0 != (ctx = kzalloc(sizeof(*ctx) + size, GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&ctx->hn);
<<<<<<< HEAD
	ctx->pra = (remote_arg_t *)(&ctx[1]);
	ctx->fds = invokefd->fds == 0 ? 0 : (int *)(&ctx->pra[bufs]);
	ctx->handles = invokefd->fds == 0 ? 0 :
					(struct ion_handle **)(&ctx->fds[bufs]);
=======
	ctx->pra = (remote_arg_t*)(&ctx[1]);
	ctx->fds = invokefd->fds == 0 ? 0 : (int*)(&ctx->pra[bufs]);
	ctx->handles = invokefd->fds == 0 ? 0 : (struct ion_handle**)(&ctx->fds[bufs]);

>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (!kernel) {
		VERIFY(err, 0 == copy_from_user(ctx->pra, invoke->pra,
					bufs * sizeof(*ctx->pra)));
		if (err)
			goto bail;
	} else {
		memmove(ctx->pra, invoke->pra, bufs * sizeof(*ctx->pra));
	}

	if (invokefd->fds) {
		if (!kernel) {
			VERIFY(err, 0 == copy_from_user(ctx->fds, invokefd->fds,
						bufs * sizeof(*ctx->fds)));
			if (err)
				goto bail;
		} else {
			memmove(ctx->fds, invokefd->fds,
						bufs * sizeof(*ctx->fds));
		}
	}
	ctx->sc = invoke->sc;
	ctx->retval = -1;
<<<<<<< HEAD
=======
	ctx->cid = cid;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	ctx->pid = current->pid;
	ctx->apps = me;
	init_completion(&ctx->work);
	spin_lock(&clst->hlock);
	hlist_add_head(&ctx->hn, &clst->pending);
	spin_unlock(&clst->hlock);

	*po = ctx;
bail:
<<<<<<< HEAD
	if (ctx && err)
=======
	if(ctx && err)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		kfree(ctx);
	return err;
}

static void context_save_interrupted(struct smq_invoke_ctx *ctx)
{
	struct smq_context_list *clst = &ctx->apps->clst;
	spin_lock(&clst->hlock);
	hlist_del(&ctx->hn);
	hlist_add_head(&ctx->hn, &clst->interrupted);
	spin_unlock(&clst->hlock);
}

static void add_dev(struct fastrpc_apps *me, struct fastrpc_device *dev);

static void context_free(struct smq_invoke_ctx *ctx, bool lock)
{
	struct smq_context_list *clst = &ctx->apps->clst;
<<<<<<< HEAD
	struct fastrpc_apps *apps = ctx->apps;
	struct ion_client *clnt = apps->iclient;
	struct fastrpc_smmu *smmu = &apps->smmu;
	struct fastrpc_buf *b;
	int i, bufs;
	if (ctx->smmu) {
		bufs = REMOTE_SCALARS_INBUFS(ctx->sc) +
			REMOTE_SCALARS_OUTBUFS(ctx->sc);
		if (ctx->fds) {
			for (i = 0; i < bufs; i++)
				if (!IS_ERR_OR_NULL(ctx->handles[i])) {
					ion_unmap_iommu(clnt, ctx->handles[i],
						smmu->domain_id, 0);
					ion_free(clnt, ctx->handles[i]);
				}
		}
		iommu_detach_group(smmu->domain, smmu->group);
	}
	for (i = 0, b = ctx->abufs; i < ctx->nbufs; ++i, ++b)
		free_mem(b);

=======
	struct fastrpc_apps *apps = ctx->apps; 
	struct fastrpc_buf *b;
	int i, bufs;
	if (ctx->smmu) {
		bufs = REMOTE_SCALARS_INBUFS(ctx->sc) + REMOTE_SCALARS_OUTBUFS(ctx->sc);
		if (ctx->fds) {
			for (i = 0; i < bufs; i++)
				if (!IS_ERR_OR_NULL(ctx->handles[i])) {
					ion_unmap_iommu(apps->iclient, ctx->handles[i],
						apps->channel[ctx->cid].smmu.domain_id,
						0);
					ion_free(apps->iclient, ctx->handles[i]);
				}
		}
		iommu_detach_group(apps->channel[ctx->cid].smmu.domain,
					apps->channel[ctx->cid].smmu.group);
	}
	for (i = 0, b = ctx->abufs; i < ctx->nbufs; ++i, ++b)
		free_mem(b, ctx->cid);
	
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	kfree(ctx->abufs);
	if (ctx->dev) {
		add_dev(apps, ctx->dev);
		if (ctx->obuf.handle != ctx->dev->buf.handle)
<<<<<<< HEAD
			free_mem(&ctx->obuf);
	}
	if (lock)
		spin_lock(&clst->hlock);
	hlist_del(&ctx->hn);
	if (lock)
		spin_unlock(&clst->hlock);
	kfree(ctx);
}

static void context_notify_user(struct smq_invoke_ctx *ctx, int retval)
{
	ctx->retval = retval;
	complete(&ctx->work);
}

static void context_notify_all_users(struct smq_context_list *me)
=======
			free_mem(&ctx->obuf, ctx->cid);
	}
	if(lock) {
		spin_lock(&clst->hlock);
	}
	hlist_del(&ctx->hn);
	if(lock) {
		spin_unlock(&clst->hlock);
	}
	kfree(ctx);
}

static void context_notify_user(struct smq_invoke_ctx *me, int retval)
{
	me->retval = retval;
	complete(&me->work);
}

static void context_notify_all_users(struct smq_context_list *me, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *pos, *n;
	spin_lock(&me->hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &me->pending, hn) {
<<<<<<< HEAD
		complete(&ictx->work);
	}
	hlist_for_each_entry_safe(ictx, pos, n, &me->interrupted, hn) {
		complete(&ictx->work);
=======
			if(ictx->cid == cid) {
				complete(&ictx->work);
			}
	}
	hlist_for_each_entry_safe(ictx, pos, n, &me->interrupted, hn) {
			if(ictx->cid == cid) {
				complete(&ictx->work);
			}
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	}
	spin_unlock(&me->hlock);

}

<<<<<<< HEAD
static void context_list_ctor(struct smq_context_list *me)
{
	INIT_HLIST_HEAD(&me->interrupted);
	INIT_HLIST_HEAD(&me->pending);
	spin_lock_init(&me->hlock);
}

static void context_list_dtor(struct fastrpc_apps *me,
				struct smq_context_list *clst)
{
	struct smq_invoke_ctx *ictx = 0;
	struct hlist_node *pos, *n;
	spin_lock(&clst->hlock);
	hlist_for_each_entry_safe(ictx, pos, n, &clst->interrupted, hn) {
		context_free(ictx, 0);
	}
	hlist_for_each_entry_safe(ictx, pos, n, &clst->pending, hn) {
		context_free(ictx, 0);
	}
	spin_unlock(&clst->hlock);
}

static int get_page_list(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			struct fastrpc_buf *ibuf, struct fastrpc_buf *obuf)
=======
static int get_page_list(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
		struct fastrpc_buf *ibuf, struct fastrpc_buf *obuf, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct smq_phy_page *pgstart, *pages;
	struct smq_invoke_buf *list;
	int i, rlen, err = 0;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);

	LOCK_MMAP(kernel);
	*obuf = *ibuf;
 retry:
	list = smq_invoke_buf_start((remote_arg_t *)obuf->virt, sc);
	pgstart = smq_phy_page_start(sc, list);
	pages = pgstart + 1;
	rlen = obuf->size - ((uint32_t)pages - (uint32_t)obuf->virt);
	if (rlen < 0) {
		rlen = ((uint32_t)pages - (uint32_t)obuf->virt) - obuf->size;
		obuf->size += buf_page_size(rlen);
<<<<<<< HEAD
		VERIFY(err, 0 == alloc_mem(obuf));
=======
		VERIFY(err, 0 == alloc_mem(obuf, cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		goto retry;
	}
	pgstart->addr = obuf->phys;
	pgstart->size = obuf->size;
	for (i = 0; i < inbufs + outbufs; ++i) {
		void *buf;
		int len, num;

		list[i].num = 0;
		list[i].pgidx = 0;
		len = pra[i].buf.len;
		VERIFY(err, len >= 0);
		if (err)
			goto bail;
		if (!len)
			continue;
		buf = pra[i].buf.pv;
		num = buf_num_pages(buf, len);
		if (!kernel)
			list[i].num = buf_get_pages(buf, len, num,
				i >= inbufs, pages, rlen / sizeof(*pages));
		else
			list[i].num = 0;
		VERIFY(err, list[i].num >= 0);
		if (err)
			goto bail;
		if (list[i].num) {
			list[i].pgidx = pages - pgstart;
			pages = pages + list[i].num;
		} else if (rlen > sizeof(*pages)) {
			list[i].pgidx = pages - pgstart;
			pages = pages + 1;
		} else {
			if (obuf->handle != ibuf->handle)
<<<<<<< HEAD
				free_mem(obuf);
			obuf->size += buf_page_size(sizeof(*pages));
			VERIFY(err, 0 == alloc_mem(obuf));
=======
				free_mem(obuf, cid);
			obuf->size += buf_page_size(sizeof(*pages));
			VERIFY(err, 0 == alloc_mem(obuf, cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			if (err)
				goto bail;
			goto retry;
		}
		rlen = obuf->size - ((uint32_t) pages - (uint32_t) obuf->virt);
	}
	obuf->used = obuf->size - rlen;
 bail:
	if (err && (obuf->handle != ibuf->handle))
<<<<<<< HEAD
		free_mem(obuf);
=======
		free_mem(obuf, cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	UNLOCK_MMAP(kernel);
	return err;
}

static int get_args(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			remote_arg_t *rpra, remote_arg_t *upra,
			struct fastrpc_buf *ibuf, struct fastrpc_buf **abufs,
<<<<<<< HEAD
			int *nbufs, int *fds, struct ion_handle **handles)
=======
			int *nbufs, int *fds, struct ion_handle **handles, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_apps *me = &gfa;
	struct smq_invoke_buf *list;
	struct fastrpc_buf *pbuf = ibuf, *obufs = 0;
	struct smq_phy_page *pages;
	void *args;
	int i, rlen, size, used, inh, bufs = 0, err = 0;
	int inbufs = REMOTE_SCALARS_INBUFS(sc);
	int outbufs = REMOTE_SCALARS_OUTBUFS(sc);
<<<<<<< HEAD
	unsigned long iova, len;
=======
	unsigned long len;
	ion_phys_addr_t iova;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60

	list = smq_invoke_buf_start(rpra, sc);
	pages = smq_phy_page_start(sc, list);
	used = ALIGN(pbuf->used, BALIGN);
	args = (void *)((char *)pbuf->virt + used);
	rlen = pbuf->size - used;
	for (i = 0; i < inbufs + outbufs; ++i) {

		rpra[i].buf.len = pra[i].buf.len;
		if (!rpra[i].buf.len)
			continue;
		if (list[i].num) {
			rpra[i].buf.pv = pra[i].buf.pv;
			continue;
<<<<<<< HEAD
		} else if (me->smmu.enabled && fds && (fds[i] >= 0)) {
=======
		} else if (me->channel[cid].smmu.enabled &&
					fds && (fds[i] >= 0)) {
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			len = buf_page_size(pra[i].buf.len);
			handles[i] = ion_import_dma_buf(me->iclient, fds[i]);
			VERIFY(err, 0 == IS_ERR_OR_NULL(handles[i]));
			if (err)
				goto bail;
			VERIFY(err, 0 == ion_map_iommu(me->iclient, handles[i],
<<<<<<< HEAD
						me->smmu.domain_id, 0, SZ_4K, 0,
						&iova, &len, 0, 0));
=======
					me->channel[cid].smmu.domain_id,
					0, SZ_4K, 0, &iova, &len, 0, 0));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			if (err)
				goto bail;
			rpra[i].buf.pv = pra[i].buf.pv;
			list[i].num = 1;
			pages[list[i].pgidx].addr = iova;
			pages[list[i].pgidx].size = len;
			continue;
		}
		if (rlen < pra[i].buf.len) {
			struct fastrpc_buf *b;
			pbuf->used = pbuf->size - rlen;
			VERIFY(err, 0 != (b = krealloc(obufs,
				 (bufs + 1) * sizeof(*obufs), GFP_KERNEL)));
			if (err)
				goto bail;
			obufs = b;
			pbuf = obufs + bufs;
			pbuf->size = buf_num_pages(0, pra[i].buf.len) *
								PAGE_SIZE;
<<<<<<< HEAD
			VERIFY(err, 0 == alloc_mem(pbuf));
=======
			VERIFY(err, 0 == alloc_mem(pbuf, cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			if (err)
				goto bail;
			bufs++;
			args = pbuf->virt;
			rlen = pbuf->size;
		}
		list[i].num = 1;
		pages[list[i].pgidx].addr =
<<<<<<< HEAD
			buf_page_start((void *)(pbuf->phys +
=======
			buf_page_start((void *)((uint32_t)pbuf->phys +
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
						 (pbuf->size - rlen)));
		pages[list[i].pgidx].size =
			buf_page_size(pra[i].buf.len);
		if (i < inbufs) {
			if (!kernel) {
				VERIFY(err, 0 == copy_from_user(args,
						pra[i].buf.pv, pra[i].buf.len));
				if (err)
					goto bail;
			} else {
				memmove(args, pra[i].buf.pv, pra[i].buf.len);
			}
		}
		rpra[i].buf.pv = args;
		args = (void *)((char *)args + ALIGN(pra[i].buf.len, BALIGN));
		rlen -= ALIGN(pra[i].buf.len, BALIGN);
	}
	for (i = 0; i < inbufs; ++i) {
		if (rpra[i].buf.len)
			dmac_flush_range(rpra[i].buf.pv,
				  (char *)rpra[i].buf.pv + rpra[i].buf.len);
	}
	pbuf->used = pbuf->size - rlen;
	size = sizeof(*rpra) * REMOTE_SCALARS_INHANDLES(sc);
	if (size) {
		inh = inbufs + outbufs;
		if (!kernel) {
			VERIFY(err, 0 == copy_from_user(&rpra[inh], &upra[inh],
							size));
			if (err)
				goto bail;
		} else {
			memmove(&rpra[inh], &upra[inh], size);
		}
	}
	dmac_flush_range(rpra, (char *)rpra + used);
 bail:
	*abufs = obufs;
	*nbufs = bufs;
	return err;
}

static int put_args(uint32_t kernel, uint32_t sc, remote_arg_t *pra,
			remote_arg_t *rpra, remote_arg_t *upra)
{
	int i, inbufs, outbufs, outh, size;
	int err = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (rpra[i].buf.pv != pra[i].buf.pv) {
			if (!kernel) {
				VERIFY(err, 0 == copy_to_user(pra[i].buf.pv,
					rpra[i].buf.pv, rpra[i].buf.len));
				if (err)
					goto bail;
			} else {
				memmove(pra[i].buf.pv, rpra[i].buf.pv,
							rpra[i].buf.len);
			}
		}
	}
	size = sizeof(*rpra) * REMOTE_SCALARS_OUTHANDLES(sc);
	if (size) {
		outh = inbufs + outbufs + REMOTE_SCALARS_INHANDLES(sc);
		if (!kernel) {
			VERIFY(err, 0 == copy_to_user(&upra[outh], &rpra[outh],
						size));
			if (err)
				goto bail;
		} else {
			memmove(&upra[outh], &rpra[outh], size);
		}
	}
 bail:
	return err;
}

static void inv_args_pre(uint32_t sc, remote_arg_t *rpra)
{
	int i, inbufs, outbufs;
	uint32_t end;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (!rpra[i].buf.len)
			continue;
		if (buf_page_start(rpra) == buf_page_start(rpra[i].buf.pv))
			continue;
		if (!IS_CACHE_ALIGNED((uint32_t)rpra[i].buf.pv))
			dmac_flush_range(rpra[i].buf.pv,
				(char *)rpra[i].buf.pv + 1);
		end = (uint32_t)rpra[i].buf.pv + rpra[i].buf.len;
		if (!IS_CACHE_ALIGNED(end))
			dmac_flush_range((char *)end,
				(char *)end + 1);
	}
}

static void inv_args(uint32_t sc, remote_arg_t *rpra, int used)
{
	int i, inbufs, outbufs;
	int inv = 0;

	inbufs = REMOTE_SCALARS_INBUFS(sc);
	outbufs = REMOTE_SCALARS_OUTBUFS(sc);
	for (i = inbufs; i < inbufs + outbufs; ++i) {
		if (buf_page_start(rpra) == buf_page_start(rpra[i].buf.pv))
			inv = 1;
		else if (rpra[i].buf.len)
			dmac_inv_range(rpra[i].buf.pv,
				(char *)rpra[i].buf.pv + rpra[i].buf.len);
	}

	if (inv || REMOTE_SCALARS_OUTHANDLES(sc))
		dmac_inv_range(rpra, (char *)rpra + used);
}

static int fastrpc_invoke_send(struct fastrpc_apps *me,
				 uint32_t kernel, uint32_t handle,
				 uint32_t sc, struct smq_invoke_ctx *ctx,
				 struct fastrpc_buf *buf)
{
	struct smq_msg msg;
	int err = 0, len;
	msg.pid = current->tgid;
	msg.tid = current->pid;
	if (kernel)
		msg.pid = 0;
	msg.invoke.header.ctx = ctx;
	msg.invoke.header.handle = handle;
	msg.invoke.header.sc = sc;
	msg.invoke.page.addr = buf->phys;
	msg.invoke.page.size = buf_page_size(buf->used);
	spin_lock(&me->wrlock);
<<<<<<< HEAD
	len = smd_write(me->chan, &msg, sizeof(msg));
=======
	len = smd_write(me->channel[ctx->cid].chan, &msg, sizeof(msg));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	spin_unlock(&me->wrlock);
	VERIFY(err, len == sizeof(msg));
	return err;
}

static void fastrpc_deinit(void)
{
	struct fastrpc_apps *me = &gfa;
<<<<<<< HEAD

	smd_close(me->chan);
	ion_client_destroy(me->iclient);
	me->iclient = 0;
	me->chan = 0;
}

static void fastrpc_read_handler(void)
=======
	int i;

	for (i = 0; i < NUM_CHANNELS; i++) {
		if (me->channel[i].chan) {
			(void)smd_close(me->channel[i].chan);
			me->channel[i].chan = 0;
		}
	}
	ion_client_destroy(me->iclient);
	me->iclient = 0;
}

static void fastrpc_read_handler(int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_apps *me = &gfa;
	struct smq_invoke_rsp rsp;
	int err = 0;

	do {
<<<<<<< HEAD
		VERIFY(err, sizeof(rsp) ==
				 smd_read_from_cb(me->chan, &rsp, sizeof(rsp)));
=======
		VERIFY(err, sizeof(rsp) == smd_read_from_cb(
							me->channel[cid].chan,
							&rsp, sizeof(rsp)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		context_notify_user(rsp.ctx, rsp.retval);
	} while (!err);
 bail:
	return;
}

static void smd_event_handler(void *priv, unsigned event)
{
<<<<<<< HEAD
	struct fastrpc_apps *me = (struct fastrpc_apps *)priv;

	switch (event) {
	case SMD_EVENT_OPEN:
		complete(&(me->work));
		break;
	case SMD_EVENT_CLOSE:
		context_notify_all_users(&me->clst);
		break;
	case SMD_EVENT_DATA:
		fastrpc_read_handler();
=======
	struct fastrpc_apps *me = &gfa;
	int cid = (int)priv;

	switch (event) {
	case SMD_EVENT_OPEN:
		complete(&me->channel[cid].work);
		break;
	case SMD_EVENT_CLOSE:
		context_notify_all_users(&me->clst, cid);
		break;
	case SMD_EVENT_DATA:
		fastrpc_read_handler(cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		break;
	}
}

static int fastrpc_init(void)
{
<<<<<<< HEAD
	int err = 0;
	struct fastrpc_apps *me = &gfa;
	struct device_node *node;
	bool enabled = 0;

	if (me->chan == 0) {
		int i;
		spin_lock_init(&me->hlock);
		spin_lock_init(&me->wrlock);
		init_completion(&me->work);
		mutex_init(&me->smd_mutex);
		context_list_ctor(&me->clst);
		for (i = 0; i < RPC_HASH_SZ; ++i)
			INIT_HLIST_HEAD(&me->htbl[i]);
		me->iclient = msm_ion_client_create(ION_HEAP_CARVEOUT_MASK,
							DEVICE_NAME);
		VERIFY(err, 0 == IS_ERR_OR_NULL(me->iclient));
		if (err)
			goto bail;
		node = of_find_compatible_node(NULL, NULL,
						"qcom,msm-audio-ion");
=======
	int i, err = 0;
	struct fastrpc_apps *me = &gfa;
	struct device_node *node;
	struct fastrpc_smmu *smmu;
	bool enabled = 0;

	spin_lock_init(&me->hlock);
	spin_lock_init(&me->wrlock);
	mutex_init(&me->smd_mutex);
	context_list_ctor(&me->clst);
	for (i = 0; i < RPC_HASH_SZ; ++i)
		INIT_HLIST_HEAD(&me->htbl[i]);
	me->iclient = msm_ion_client_create(ION_HEAP_CARVEOUT_MASK,
						DEVICE_NAME);
	VERIFY(err, 0 == IS_ERR_OR_NULL(me->iclient));
	if (err)
		goto bail;
	for (i = 0; i < NUM_CHANNELS; i++) {
		init_completion(&me->channel[i].work);
		if (!gcinfo[i].node)
			continue;
		smmu = &me->channel[i].smmu;
		node = of_find_compatible_node(NULL, NULL, gcinfo[i].node);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (node)
			enabled = of_property_read_bool(node,
						"qcom,smmu-enabled");
		if (enabled)
<<<<<<< HEAD
			me->smmu.group = iommu_group_find("lpass_audio");
		if (me->smmu.group)
			me->smmu.domain = iommu_group_get_iommudata(
							me->smmu.group);
		if (!IS_ERR_OR_NULL(me->smmu.domain)) {
			me->smmu.domain_id = msm_find_domain_no(
							me->smmu.domain);
			if (me->smmu.domain_id >= 0)
				me->smmu.enabled = enabled;
		}
	}

=======
			smmu->group = iommu_group_find(gcinfo[i].group);
		if (smmu->group)
			smmu->domain = iommu_group_get_iommudata(smmu->group);
		if (!IS_ERR_OR_NULL(smmu->domain)) {
			smmu->domain_id = msm_find_domain_no(smmu->domain);
			if (smmu->domain_id >= 0)
				smmu->enabled = enabled;
		}
	}
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	return 0;

bail:
	return err;
}

<<<<<<< HEAD
static void free_dev(struct fastrpc_device *dev)
{
	if (dev) {
		free_mem(&dev->buf);
=======
static void free_dev(struct fastrpc_device *dev, int cid)
{
	if (dev) {
		free_mem(&dev->buf, cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		kfree(dev);
		module_put(THIS_MODULE);
	}
}

<<<<<<< HEAD
static int alloc_dev(struct fastrpc_device **dev)
=======
static int alloc_dev(struct fastrpc_device **dev, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	int err = 0;
	struct fastrpc_device *fd = 0;

	VERIFY(err, 0 != try_module_get(THIS_MODULE));
	if (err)
		goto bail;
	VERIFY(err, 0 != (fd = kzalloc(sizeof(*fd), GFP_KERNEL)));
	if (err)
		goto bail;

	INIT_HLIST_NODE(&fd->hn);

	fd->buf.size = PAGE_SIZE;
<<<<<<< HEAD
	VERIFY(err, 0 == alloc_mem(&fd->buf));
=======
	VERIFY(err, 0 == alloc_mem(&fd->buf, cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto bail;
	fd->tgid = current->tgid;

	*dev = fd;
 bail:
	if (err)
<<<<<<< HEAD
		free_dev(fd);
	return err;
}

static int get_dev(struct fastrpc_apps *me, struct fastrpc_device **rdev)
=======
		free_dev(fd, cid);
	return err;
}

static int get_dev(struct fastrpc_apps *me, int cid,
			struct fastrpc_device **rdev)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct hlist_head *head;
	struct fastrpc_device *dev = 0, *devfree = 0;
	struct hlist_node *pos, *n;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	int err = 0;

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, pos, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	VERIFY(err, devfree != 0);
	if (err)
		goto bail;
	*rdev = devfree;
 bail:
	if (err) {
<<<<<<< HEAD
		free_dev(devfree);
		err = alloc_dev(rdev);
=======
		free_dev(devfree, cid);
		err = alloc_dev(rdev, cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	}
	return err;
}

static void add_dev(struct fastrpc_apps *me, struct fastrpc_device *dev)
{
	struct hlist_head *head;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);

	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_add_head(&dev->hn, head);
	spin_unlock(&me->hlock);
	return;
}

<<<<<<< HEAD
static int fastrpc_release_current_dsp_process(void);

static int fastrpc_internal_invoke(struct fastrpc_apps *me, uint32_t mode,
			uint32_t kernel,
			struct fastrpc_ioctl_invoke_fd *invokefd)
=======
static int fastrpc_release_current_dsp_process(int cid);

static int fastrpc_internal_invoke(struct fastrpc_apps *me, uint32_t mode,
			uint32_t kernel, struct fastrpc_ioctl_invoke_fd *invokefd,
			int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct smq_invoke_ctx *ctx = 0;
	struct fastrpc_ioctl_invoke *invoke = &invokefd->inv;
	int interrupted = 0;
	int err = 0;

<<<<<<< HEAD
	if (!kernel) {
		VERIFY(err, 0 == context_restore_interrupted(me, invokefd,
								&ctx));
		if (err)
			goto bail;
		if (ctx)
			goto wait;
	}

	VERIFY(err, 0 == context_alloc(me, kernel, invokefd, &ctx));
	if (err)
		goto bail;

	if (me->smmu.enabled) {
		VERIFY(err, 0 == iommu_attach_group(me->smmu.domain,
							me->smmu.group));
=======
	if(!kernel) {
		VERIFY(err, 0 == context_restore_interrupted(me, invokefd, cid, &ctx));
		if (err)
			goto bail;
		if(ctx) 
			goto wait;
	}

	VERIFY(err, 0 == context_alloc(me, kernel, invokefd, cid, &ctx));
	if (err)
		goto bail;

	if (me->channel[cid].smmu.enabled) {
		VERIFY(err, 0 == iommu_attach_group(
						me->channel[cid].smmu.domain,
						me->channel[cid].smmu.group));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		ctx->smmu = 1;
	}
	if (REMOTE_SCALARS_LENGTH(ctx->sc)) {
<<<<<<< HEAD
		VERIFY(err, 0 == get_dev(me, &ctx->dev));
		if (err)
			goto bail;
		VERIFY(err, 0 == get_page_list(kernel, ctx->sc, ctx->pra,
					&ctx->dev->buf, &ctx->obuf));
		if (err)
			goto bail;
		ctx->rpra = (remote_arg_t *)ctx->obuf.virt;
		VERIFY(err, 0 == get_args(kernel, ctx->sc, ctx->pra, ctx->rpra,
				invoke->pra, &ctx->obuf, &ctx->abufs,
				&ctx->nbufs, ctx->fds, ctx->handles));
=======
		VERIFY(err, 0 == get_dev(me, cid, &ctx->dev));
		if (err)
			goto bail;
		VERIFY(err, 0 == get_page_list(kernel, ctx->sc, ctx->pra, &ctx->dev->buf,
						&ctx->obuf, cid));
		if (err)
			goto bail;
		ctx->rpra = (remote_arg_t *)ctx->obuf.virt;
		VERIFY(err, 0 == get_args(kernel, ctx->sc, ctx->pra, ctx->rpra, invoke->pra,
					&ctx->obuf, &ctx->abufs, &ctx->nbufs, ctx->fds, ctx->handles, cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
	}

	inv_args_pre(ctx->sc, ctx->rpra);
	if (FASTRPC_MODE_SERIAL == mode)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
<<<<<<< HEAD
	VERIFY(err, 0 == fastrpc_invoke_send(me, kernel, invoke->handle,
						ctx->sc, ctx, &ctx->obuf));
=======
	VERIFY(err, 0 == fastrpc_invoke_send(me, kernel, invoke->handle, ctx->sc,
						ctx, &ctx->obuf));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto bail;
	if (FASTRPC_MODE_PARALLEL == mode)
		inv_args(ctx->sc, ctx->rpra, ctx->obuf.used);
<<<<<<< HEAD
 wait:
	if (kernel)
		wait_for_completion(&ctx->work);
=======
wait:
	if(kernel)
			wait_for_completion(&ctx->work);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	else {
		interrupted = wait_for_completion_interruptible(&ctx->work);
		VERIFY(err, 0 == (err = interrupted));
		if (err)
			goto bail;
	}
	VERIFY(err, 0 == (err = ctx->retval));
	if (err)
		goto bail;
<<<<<<< HEAD
	VERIFY(err, 0 == put_args(kernel, ctx->sc, ctx->pra, ctx->rpra,
					invoke->pra));
	if (err)
		goto bail;
 bail:
	if (ctx && interrupted == -ERESTARTSYS)
		context_save_interrupted(ctx);
	else if (ctx)
		context_free(ctx, 1);
	return err;
}

static int fastrpc_create_current_dsp_process(void)
=======
	VERIFY(err, 0 == put_args(kernel, ctx->sc, ctx->pra, ctx->rpra, invoke->pra));
	if (err)
		goto bail;
 bail:
	if (ctx && interrupted == -ERESTARTSYS) {
		context_save_interrupted(ctx);
		err = -ERESTARTSYS;
	} else if(ctx) {
		context_free(ctx, 1);
	}
	return err;
}

static int fastrpc_create_current_dsp_process(int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	int err = 0;
	struct fastrpc_ioctl_invoke_fd ioctl;
	struct fastrpc_apps *me = &gfa;
	remote_arg_t ra[1];
	int tgid = 0;

	tgid = current->tgid;
	ra[0].buf.pv = &tgid;
	ra[0].buf.len = sizeof(tgid);
	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(0, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
<<<<<<< HEAD
		FASTRPC_MODE_PARALLEL, 1, &ioctl)));
	return err;
}

static int fastrpc_release_current_dsp_process(void)
=======
		FASTRPC_MODE_PARALLEL, 1, &ioctl, cid)));
	return err;
}

static int fastrpc_release_current_dsp_process(int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	int err = 0;
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int tgid = 0;

	tgid = current->tgid;
	ra[0].buf.pv = &tgid;
	ra[0].buf.len = sizeof(tgid);
	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(1, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
<<<<<<< HEAD
		FASTRPC_MODE_PARALLEL, 1, &ioctl)));
=======
		FASTRPC_MODE_PARALLEL, 1, &ioctl, cid)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	return err;
}

static int fastrpc_mmap_on_dsp(struct fastrpc_apps *me,
					 struct fastrpc_ioctl_mmap *mmap,
					 struct smq_phy_page *pages,
<<<<<<< HEAD
					 int num)
=======
					 int cid, int num)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[3];
	int err = 0;
	struct {
		int pid;
		uint32_t flags;
		uint32_t vaddrin;
		int num;
	} inargs;

	struct {
		uint32_t vaddrout;
	} routargs;
	inargs.pid = current->tgid;
	inargs.vaddrin = mmap->vaddrin;
	inargs.flags = mmap->flags;
	inargs.num = num;
	ra[0].buf.pv = &inargs;
	ra[0].buf.len = sizeof(inargs);

	ra[1].buf.pv = pages;
	ra[1].buf.len = num * sizeof(*pages);

	ra[2].buf.pv = &routargs;
	ra[2].buf.len = sizeof(routargs);

	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(2, 2, 1);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
<<<<<<< HEAD
		FASTRPC_MODE_PARALLEL, 1, &ioctl)));
=======
		FASTRPC_MODE_PARALLEL, 1, &ioctl, cid)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	mmap->vaddrout = routargs.vaddrout;
	if (err)
		goto bail;
bail:
	return err;
}

static int fastrpc_munmap_on_dsp(struct fastrpc_apps *me,
<<<<<<< HEAD
				 struct fastrpc_ioctl_munmap *munmap)
=======
				 struct fastrpc_ioctl_munmap *munmap, int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_ioctl_invoke_fd ioctl;
	remote_arg_t ra[1];
	int err = 0;
	struct {
		int pid;
		uint32_t vaddrout;
		int size;
	} inargs;

	inargs.pid = current->tgid;
	inargs.size = munmap->size;
	inargs.vaddrout = munmap->vaddrout;
	ra[0].buf.pv = &inargs;
	ra[0].buf.len = sizeof(inargs);

	ioctl.inv.handle = 1;
	ioctl.inv.sc = REMOTE_SCALARS_MAKE(3, 1, 0);
	ioctl.inv.pra = ra;
	ioctl.fds = 0;
	VERIFY(err, 0 == (err = fastrpc_internal_invoke(me,
<<<<<<< HEAD
		FASTRPC_MODE_PARALLEL, 1, &ioctl)));
=======
		FASTRPC_MODE_PARALLEL, 1, &ioctl, cid)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	return err;
}

static int fastrpc_internal_munmap(struct fastrpc_apps *me,
				   struct file_data *fdata,
				   struct fastrpc_ioctl_munmap *munmap)
{
	int err = 0;
	struct fastrpc_mmap *map = 0, *mapfree = 0;
	struct hlist_node *pos, *n;
<<<<<<< HEAD
	VERIFY(err, 0 == (err = fastrpc_munmap_on_dsp(me, munmap)));
=======
	VERIFY(err, 0 == (err = fastrpc_munmap_on_dsp(me, munmap, fdata->cid)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto bail;
	spin_lock(&fdata->hlock);
	hlist_for_each_entry_safe(map, pos, n, &fdata->hlst, hn) {
		if (map->vaddrout == munmap->vaddrout &&
<<<<<<< HEAD
		    map->size == munmap->size) {
=======
			 map->size == munmap->size) {
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
			hlist_del(&map->hn);
			mapfree = map;
			map = 0;
			break;
		}
	}
	spin_unlock(&fdata->hlock);
bail:
	if (mapfree) {
<<<<<<< HEAD
		free_map(mapfree);
=======
		free_map(mapfree, fdata->cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		kfree(mapfree);
	}
	return err;
}


static int fastrpc_internal_mmap(struct fastrpc_apps *me,
				 struct file_data *fdata,
				 struct fastrpc_ioctl_mmap *mmap)
{
	struct ion_client *clnt = gfa.iclient;
	struct fastrpc_mmap *map = 0;
	struct smq_phy_page *pages = 0;
<<<<<<< HEAD
=======
	struct ion_handle *handles;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	void *buf;
	unsigned long len;
	int num;
	int err = 0;

	VERIFY(err, 0 != (map = kzalloc(sizeof(*map), GFP_KERNEL)));
	if (err)
		goto bail;
	map->handle = ion_import_dma_buf(clnt, mmap->fd);
	VERIFY(err, 0 == IS_ERR_OR_NULL(map->handle));
	if (err)
		goto bail;
	map->virt = ion_map_kernel(clnt, map->handle);
	VERIFY(err, 0 == IS_ERR_OR_NULL(map->virt));
	if (err)
		goto bail;
	buf = (void *)mmap->vaddrin;
	len =  mmap->size;
	num = buf_num_pages(buf, len);
	VERIFY(err, 0 != (pages = kzalloc(num * sizeof(*pages), GFP_KERNEL)));
	if (err)
		goto bail;

<<<<<<< HEAD
	if (me->smmu.enabled) {
		VERIFY(err, 0 == ion_map_iommu(clnt, map->handle,
				me->smmu.domain_id, 0,
=======
	if (me->channel[fdata->cid].smmu.enabled) {
		handles = ion_import_dma_buf(clnt, mmap->fd);
		VERIFY(err, 0 == IS_ERR_OR_NULL(handles));
		if (err)
			goto bail;
		VERIFY(err, 0 == ion_map_iommu(clnt, handles,
				me->channel[fdata->cid].smmu.domain_id, 0,
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
				SZ_4K, 0, &map->phys, &len, 0, 0));
		if (err)
			goto bail;
		pages->addr = map->phys;
		pages->size = len;
		num = 1;
	} else {
		VERIFY(err, 0 < (num = buf_get_pages(buf, len, num, 1,
							pages, num)));
		if (err)
			goto bail;
	}

<<<<<<< HEAD
	VERIFY(err, 0 == fastrpc_mmap_on_dsp(me, mmap, pages, num));
=======
	VERIFY(err, 0 == fastrpc_mmap_on_dsp(me, mmap, pages, fdata->cid, num));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto bail;
	map->vaddrin = mmap->vaddrin;
	map->vaddrout = mmap->vaddrout;
	map->size = mmap->size;
	INIT_HLIST_NODE(&map->hn);
	spin_lock(&fdata->hlock);
	hlist_add_head(&map->hn, &fdata->hlst);
	spin_unlock(&fdata->hlock);
 bail:
	if (err && map) {
<<<<<<< HEAD
		free_map(map);
=======
		free_map(map, fdata->cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		kfree(map);
	}
	kfree(pages);
	return err;
}

<<<<<<< HEAD
static void cleanup_current_dev(void)
=======
static void cleanup_current_dev(int cid)
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
{
	struct fastrpc_apps *me = &gfa;
	uint32_t h = hash_32(current->tgid, RPC_HASH_BITS);
	struct hlist_head *head;
	struct hlist_node *pos, *n;
	struct fastrpc_device *dev, *devfree;

 rnext:
	devfree = dev = 0;
	spin_lock(&me->hlock);
	head = &me->htbl[h];
	hlist_for_each_entry_safe(dev, pos, n, head, hn) {
		if (dev->tgid == current->tgid) {
			hlist_del(&dev->hn);
			devfree = dev;
			break;
		}
	}
	spin_unlock(&me->hlock);
	if (devfree) {
<<<<<<< HEAD
		free_dev(devfree);
=======
		free_dev(devfree, cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		goto rnext;
	}
	return;
}

static void fastrpc_channel_close(struct kref *kref)
{
	struct fastrpc_apps *me = &gfa;
<<<<<<< HEAD

	smd_close(me->chan);
	me->chan = 0;
	mutex_unlock(&me->smd_mutex);
	pr_info("'closed /dev/%s c %d 0'\n", DEVICE_NAME,
						MAJOR(me->dev_no));
=======
	struct fastrpc_channel_context *ctx;
	int cid;

	ctx = container_of(kref, struct fastrpc_channel_context, kref);
	smd_close(ctx->chan);
	ctx->chan = 0;
	mutex_unlock(&me->smd_mutex);
	cid = ctx - &me->channel[0];
	pr_info("'closed /dev/%s c %d %d'\n", gcinfo[cid].name,
						MAJOR(me->dev_no), cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
}

static int fastrpc_device_release(struct inode *inode, struct file *file)
{
	struct file_data *fdata = (struct file_data *)file->private_data;
	struct fastrpc_apps *me = &gfa;
<<<<<<< HEAD

	(void)fastrpc_release_current_dsp_process();
	cleanup_current_dev();
	if (fdata) {
		struct fastrpc_mmap *map = 0;
		struct hlist_node *n, *pos;
		file->private_data = 0;
		hlist_for_each_entry_safe(map, pos, n, &fdata->hlst, hn) {
			hlist_del(&map->hn);
			free_map(map);
			kfree(map);
		}
		kfree(fdata);
		kref_put_mutex(&me->kref, fastrpc_channel_close,
=======
	int cid = MINOR(inode->i_rdev);

	(void)fastrpc_release_current_dsp_process(cid);
	cleanup_current_dev(cid);
	if (fdata) {
		struct fastrpc_mmap *map = 0;
		struct hlist_node *pos, *n;
		file->private_data = 0;
		hlist_for_each_entry_safe(map, pos, n, &fdata->hlst, hn) {
			hlist_del(&map->hn);
			free_map(map, cid);
			kfree(map);
		}
		kfree(fdata);
		kref_put_mutex(&me->channel[cid].kref, fastrpc_channel_close,
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
				&me->smd_mutex);
	}
	return 0;
}

static int fastrpc_device_open(struct inode *inode, struct file *filp)
{
<<<<<<< HEAD
=======
	int cid = MINOR(inode->i_rdev);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	int err = 0;
	struct fastrpc_apps *me = &gfa;

	mutex_lock(&me->smd_mutex);
<<<<<<< HEAD
	if (kref_get_unless_zero(&me->kref) == 0) {
		VERIFY(err, 0 == smd_named_open_on_edge(FASTRPC_SMD_GUID,
						SMD_APPS_QDSP, &me->chan,
						me, smd_event_handler));
		if (err)
			goto smd_bail;
		VERIFY(err, 0 != wait_for_completion_timeout(&me->work,
							RPC_TIMEOUT));
		if (err)
			goto completion_bail;
		kref_init(&me->kref);
		pr_info("'opened /dev/%s c %d 0'\n", DEVICE_NAME,
						MAJOR(me->dev_no));
=======
	if (kref_get_unless_zero(&me->channel[cid].kref) == 0) {
		VERIFY(err, 0 == smd_named_open_on_edge(
					FASTRPC_SMD_GUID,
					gcinfo[cid].channel,
					&me->channel[cid].chan, (void*)cid,
					smd_event_handler));
		if (err)
			goto smd_bail;
		VERIFY(err, 0 != wait_for_completion_timeout(
							&me->channel[cid].work,
							RPC_TIMEOUT));
		if (err)
			goto completion_bail;
		kref_init(&me->channel[cid].kref);
		pr_info("'opened /dev/%s c %d %d'\n", gcinfo[cid].name,
						MAJOR(me->dev_no), cid);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	}
	mutex_unlock(&me->smd_mutex);

	filp->private_data = 0;
	if (0 != try_module_get(THIS_MODULE)) {
		struct file_data *fdata = 0;
		/* This call will cause a dev to be created
		 * which will addref this module
		 */
		VERIFY(err, 0 != (fdata = kzalloc(sizeof(*fdata), GFP_KERNEL)));
		if (err)
			goto bail;

		spin_lock_init(&fdata->hlock);
		INIT_HLIST_HEAD(&fdata->hlst);
<<<<<<< HEAD

		VERIFY(err, 0 == fastrpc_create_current_dsp_process());
=======
		fdata->cid = cid;

		VERIFY(err, 0 == fastrpc_create_current_dsp_process(cid));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		filp->private_data = fdata;
bail:
		if (err) {
<<<<<<< HEAD
			cleanup_current_dev();
			kfree(fdata);
			kref_put_mutex(&me->kref, fastrpc_channel_close,
					&me->smd_mutex);
=======
			cleanup_current_dev(cid);
			kfree(fdata);
			kref_put_mutex(&me->channel[cid].kref,
					fastrpc_channel_close, &me->smd_mutex);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		}
		module_put(THIS_MODULE);
	}
	return err;

completion_bail:
<<<<<<< HEAD
	smd_close(me->chan);
	me->chan = 0;
=======
	smd_close(me->channel[cid].chan);
	me->channel[cid].chan = 0;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
smd_bail:
	mutex_unlock(&me->smd_mutex);
	return err;
}


static long fastrpc_device_ioctl(struct file *file, unsigned int ioctl_num,
				 unsigned long ioctl_param)
{
	struct fastrpc_apps *me = &gfa;
	struct fastrpc_ioctl_invoke_fd invokefd;
<<<<<<< HEAD
=======
	struct fastrpc_ioctl_invoke *invoke = &invokefd.inv;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	struct fastrpc_ioctl_mmap mmap;
	struct fastrpc_ioctl_munmap munmap;
	void *param = (char *)ioctl_param;
	struct file_data *fdata = (struct file_data *)file->private_data;
	int size = 0, err = 0;

	switch (ioctl_num) {
	case FASTRPC_IOCTL_INVOKE_FD:
	case FASTRPC_IOCTL_INVOKE:
		invokefd.fds = 0;
		size = (ioctl_num == FASTRPC_IOCTL_INVOKE) ?
<<<<<<< HEAD
				sizeof(invokefd.inv) : sizeof(invokefd);
=======
				sizeof(*invoke) : sizeof(invokefd);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		VERIFY(err, 0 == copy_from_user(&invokefd, param, size));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_invoke(me, fdata->mode,
<<<<<<< HEAD
						0, &invokefd)));
=======
							0, &invokefd, fdata->cid)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MMAP:
		VERIFY(err, 0 == copy_from_user(&mmap, param,
						sizeof(mmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_mmap(me, fdata,
<<<<<<< HEAD
							      &mmap)));
=======
									&mmap)));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
		if (err)
			goto bail;
		VERIFY(err, 0 == copy_to_user(param, &mmap, sizeof(mmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_MUNMAP:
		VERIFY(err, 0 == copy_from_user(&munmap, param,
						sizeof(munmap)));
		if (err)
			goto bail;
		VERIFY(err, 0 == (err = fastrpc_internal_munmap(me, fdata,
								&munmap)));
		if (err)
			goto bail;
		break;
	case FASTRPC_IOCTL_SETMODE:
		switch ((uint32_t)ioctl_param) {
		case FASTRPC_MODE_PARALLEL:
		case FASTRPC_MODE_SERIAL:
			fdata->mode = (uint32_t)ioctl_param;
			break;
		default:
			err = -ENOTTY;
			break;
		}
		break;
	default:
		err = -ENOTTY;
		break;
	}
 bail:
	return err;
}

static const struct file_operations fops = {
	.open = fastrpc_device_open,
	.release = fastrpc_device_release,
	.unlocked_ioctl = fastrpc_device_ioctl,
};

static int __init fastrpc_device_init(void)
{
	struct fastrpc_apps *me = &gfa;
<<<<<<< HEAD
	int err = 0;
=======
	int i, err = 0;
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60

	memset(me, 0, sizeof(*me));
	VERIFY(err, 0 == fastrpc_init());
	if (err)
		goto fastrpc_bail;
<<<<<<< HEAD
	VERIFY(err, 0 == alloc_chrdev_region(&me->dev_no, 0, 1, DEVICE_NAME));
=======
	VERIFY(err, 0 == alloc_chrdev_region(&me->dev_no, 0, NUM_CHANNELS,
					DEVICE_NAME));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto alloc_chrdev_bail;
	cdev_init(&me->cdev, &fops);
	me->cdev.owner = THIS_MODULE;
<<<<<<< HEAD
	VERIFY(err, 0 == cdev_add(&me->cdev, MKDEV(MAJOR(me->dev_no), 0), 1));
=======
	VERIFY(err, 0 == cdev_add(&me->cdev, MKDEV(MAJOR(me->dev_no), 0),
				NUM_CHANNELS));
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
	if (err)
		goto cdev_init_bail;
	me->class = class_create(THIS_MODULE, "fastrpc");
	VERIFY(err, !IS_ERR(me->class));
	if (err)
		goto class_create_bail;
<<<<<<< HEAD
	me->dev = device_create(me->class, NULL, MKDEV(MAJOR(me->dev_no), 0),
				NULL, DEVICE_NAME);
	VERIFY(err, !IS_ERR(me->dev));
	if (err)
		goto device_create_bail;
=======
	for (i = 0; i < NUM_CHANNELS; i++) {
		me->channel[i].dev = device_create(me->class, NULL,
					MKDEV(MAJOR(me->dev_no), i),
					NULL, gcinfo[i].name);
		VERIFY(err, !IS_ERR(me->channel[i].dev));
		if (err)
			goto device_create_bail;
	}
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60

	return 0;

device_create_bail:
	class_destroy(me->class);
class_create_bail:
	cdev_del(&me->cdev);
cdev_init_bail:
<<<<<<< HEAD
	unregister_chrdev_region(me->dev_no, 1);
=======
	unregister_chrdev_region(me->dev_no, NUM_CHANNELS);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
alloc_chrdev_bail:
	fastrpc_deinit();
fastrpc_bail:
	return err;
}

static void __exit fastrpc_device_exit(void)
{
	struct fastrpc_apps *me = &gfa;
<<<<<<< HEAD

	context_list_dtor(me, &me->clst);
	fastrpc_deinit();
	cleanup_current_dev();
	device_destroy(me->class, MKDEV(MAJOR(me->dev_no), 0));
	class_destroy(me->class);
	cdev_del(&me->cdev);
	unregister_chrdev_region(me->dev_no, 1);
=======
	int i;

	context_list_dtor(me, &me->clst);
	fastrpc_deinit();
	for (i = 0; i < NUM_CHANNELS; i++) {
		cleanup_current_dev(i);
		device_destroy(me->class, MKDEV(MAJOR(me->dev_no), i));
	}
	class_destroy(me->class);
	cdev_del(&me->cdev);
	unregister_chrdev_region(me->dev_no, NUM_CHANNELS);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
}

module_init(fastrpc_device_init);
module_exit(fastrpc_device_exit);

MODULE_LICENSE("GPL v2");
