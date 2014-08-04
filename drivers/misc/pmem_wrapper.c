/* drivers/android/pmem_wrapper.c
 *
 * Copyright (C) 2007 Google, Inc.
 * Copyright (c) 2009-2012, The Linux Foundation. All rights reserved.
 * Copyright (C) 2014  Rudolf Tammekivi <rtammekivi@gmail.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/android_pmem.h>
#include <linux/file.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/module.h>
#include <linux/msm_ion.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define PMEM_MAX_DEVICES (10)

struct pmem_data {
	struct ion_client *client;
	struct miscdevice dev;
};

struct allocation_data {
	struct ion_client *client;
	struct ion_handle *handle;
	struct vm_area_struct *vma; /* NULL for indirect allocations. */
};

static struct pmem_data pmem[PMEM_MAX_DEVICES];

static int get_id(struct file *file)
{
	return MINOR(file->f_dentry->d_inode->i_rdev);
}

/* Detect whether the file is opened from a PMEM driver. */
static int is_pmem_file(struct file *file)
{
	int id;

	if (unlikely(!file || !file->f_dentry || !file->f_dentry->d_inode))
		return 0;

	id = get_id(file);
	return (unlikely(id >= PMEM_MAX_DEVICES ||
		file->f_dentry->d_inode->i_rdev !=
		     MKDEV(MISC_MAJOR, pmem[id].dev.minor))) ? 0 : 1;
}

int get_pmem_file(unsigned int fd, unsigned long *start, unsigned long *vstart,
		  unsigned long *len, struct file **filep)
{
	int ret;
	struct file *file = fget(fd);
	struct allocation_data *adata = NULL;
	bool pmem_file = is_pmem_file(file);

	if (pmem_file) {
		/* Get file private data, which is stored in pmem_open. */
		adata = file->private_data;
	} else {
		/* Close the file, not using it anymore. */
		fput(file);

		file = kzalloc(sizeof(*file), GFP_KERNEL);
		/* Not PMEM fd. Assume the fd is directly from ION. */
		adata = kzalloc(sizeof(*adata), GFP_KERNEL);
		/* Get PMEM client 0 ION client. */
		adata->client = pmem[0].client;
		adata->handle = ion_import_dma_buf(adata->client, fd);
		adata->vma = NULL;

		file->private_data = adata;
	}

	if (IS_ERR_OR_NULL(adata->handle)) {
		ret = PTR_ERR(adata->handle);
		adata->handle = NULL;
		pr_err("%s: Invalid handle ret=%d\n", __func__, ret);
		goto err;
	}

	ret = ion_phys(adata->client, adata->handle, start, (size_t *)len);
	if (ret) {
		pr_err("%s: Failed to ion_phys ret=%d\n", __func__, ret);
		goto err_free;
	}

	*vstart = (unsigned long)ion_map_kernel(adata->client, adata->handle);
	if (IS_ERR_OR_NULL((void *)*vstart)) {
		ret = PTR_ERR((void *)*vstart);
		pr_err("%s: Failed to ion_map_kernel ret=%d\n", __func__, ret);
		goto err_free;
	}

	*filep = file;

	return 0;
err_free:
	if (!pmem_file) {
		ion_free(adata->client, adata->handle);
		adata->handle = NULL;
		kfree(file);
	}
err:
	if (pmem_file)
		fput(file);
	return ret;
}
EXPORT_SYMBOL(get_pmem_file);

int get_pmem_fd(int fd, unsigned long *start, unsigned long *len)
{
	unsigned long vstart;
	return get_pmem_file(fd, start, &vstart, len, NULL);
}
EXPORT_SYMBOL(get_pmem_fd);

int get_pmem_user_addr(struct file *file, unsigned long *start,
		       unsigned long *len)
{
	int ret = -EINVAL;

	if (is_pmem_file(file)) {
		struct allocation_data *adata = file->private_data;
		if (adata->handle && adata->vma) {
			*start = adata->vma->vm_start;
			*len = adata->vma->vm_end - adata->vma->vm_start;
			ret = 0;
		}
	}
	return ret;
}
EXPORT_SYMBOL(get_pmem_user_addr);

void put_pmem_file(struct file *file)
{
	struct allocation_data *adata = file->private_data;
	bool pmem_file = is_pmem_file(file);

	if (adata->client && adata->handle) {
		ion_unmap_kernel(adata->client, adata->handle);
		if (!pmem_file) {
			ion_free(adata->client, adata->handle);
			adata->handle = NULL;
			kfree(adata);
		}
	}

	if (pmem_file)
		fput(file);
	else
		kfree(file);
}
EXPORT_SYMBOL(put_pmem_file);

void put_pmem_fd(int fd)
{
	int put_needed;
	struct file *file = fget_light(fd, &put_needed);

	if (file) {
		put_pmem_file(file);
		fput_light(file, put_needed);
	}
}
EXPORT_SYMBOL(put_pmem_fd);

void flush_pmem_fd(int fd, unsigned long start, unsigned long len)
{
	pr_err("%s\n", __func__);
	/* TODO */
}
EXPORT_SYMBOL(flush_pmem_fd);

void flush_pmem_file(struct file *file, unsigned long start, unsigned long len)
{
	pr_err("%s\n", __func__);
	/* TODO */
}
EXPORT_SYMBOL(flush_pmem_file);

int pmem_cache_maint(struct file *file, unsigned int cmd,
		struct pmem_addr *pmem_addr)
{
	int ret = -EINVAL;
	struct allocation_data *adata = file->private_data;

	if (!adata->handle)
		return -EINVAL;

	switch (cmd) {
	case PMEM_CLEAN_INV_CACHES:
		ret = msm_ion_do_cache_op(adata->client, adata->handle,
			&pmem_addr->vaddr, pmem_addr->length,
			ION_IOC_CLEAN_INV_CACHES);
		break;
	case PMEM_CLEAN_CACHES:
		ret = msm_ion_do_cache_op(adata->client, adata->handle,
			&pmem_addr->vaddr, pmem_addr->length,
			ION_IOC_CLEAN_CACHES);
		break;
	case PMEM_INV_CACHES:
		ret = msm_ion_do_cache_op(adata->client, adata->handle,
			&pmem_addr->vaddr, pmem_addr->length,
			ION_IOC_INV_CACHES);
		break;
	default:
		pr_err("%s: invalid cmd %d\n", __func__, cmd);
		break;
	};
	return ret;
}
EXPORT_SYMBOL(pmem_cache_maint);

static long pmem_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = -EINVAL;
	struct allocation_data *adata = file->private_data;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case PMEM_GET_SIZE:
	case PMEM_GET_PHYS: {
		struct pmem_region region;
		unsigned long start = 0;
		size_t len = 0;
		if (!adata->handle)
			return -ENOMEM;

		ret = ion_phys(adata->client, adata->handle, &start, &len);
		if (ret) {
			pr_err("%s: Failed to ion_phys ret=%d\n",
				__func__, ret);
			return ret;
		}
		region.offset = start;
		region.len = len;

		if (copy_to_user(argp, &region, sizeof(region)))
			return -EFAULT;
		break;
	}
	case PMEM_MAP:
		pr_err("%s: Unsupported ioctl PMEM_MAP\n", __func__);
		break;
	case PMEM_UNMAP:
		pr_err("%s: Unsupported ioctl PMEM_UNMAP\n", __func__);
		break;
	case PMEM_ALLOCATE: {
		if (adata->handle)
			return -EINVAL;
		adata->handle = ion_alloc(adata->client, arg, SZ_4K,
			ION_HEAP(ION_CP_MM_HEAP_ID), 0);
		if (IS_ERR_OR_NULL(adata->handle)) {
			ret = PTR_ERR(adata->handle);
			adata->handle = NULL;
			pr_err("%s: Failed to ion_alloc ret=%d\n",
				__func__, ret);
			return ret;
		}
		ret = 0;
		break;
	}
	case PMEM_CONNECT:
		pr_err("%s: Unsupported ioctl PMEM_CONNECT\n", __func__);
		break;
	case PMEM_GET_TOTAL_SIZE:
		pr_err("%s: Unsupported ioctl PMEM_GET_TOTAL_SIZE\n", __func__);
		break;
	case PMEM_CLEAN_INV_CACHES:
	case PMEM_CLEAN_CACHES:
	case PMEM_INV_CACHES: {
		struct pmem_addr pmem_addr;
		if (copy_from_user(&pmem_addr, argp, sizeof(struct pmem_addr)))
			return -EFAULT;
		ret = pmem_cache_maint(file, cmd, &pmem_addr);
		break;
	}
	case PMEM_GET_FREE_SPACE:
		pr_err("%s: Unsupported ioctl PMEM_GET_FREE_SPACE\n", __func__);
		break;
	case PMEM_ALLOCATE_ALIGNED: {
		struct pmem_allocation alloc;
		if (copy_from_user(&alloc, argp,
			sizeof(struct pmem_allocation)))
			return -EFAULT;
		if (adata->handle)
			return -EINVAL;
		adata->handle = ion_alloc(adata->client, alloc.size,
			alloc.align, ION_HEAP(ION_CP_MM_HEAP_ID), 0);
		if (IS_ERR_OR_NULL(adata->handle)) {
			ret = PTR_ERR(adata->handle);
			adata->handle = NULL;
			pr_err("%s: Failed to ion_alloc ret=%d\n",
				__func__, ret);
		} else {
			ret = 0;
		}
		break;
	}
	default:
		pr_err("%s: Unsupported ioctl %d\n", __func__, cmd);
		break;
	};

	return ret;
}

static int pmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	struct allocation_data *adata = file->private_data;
	unsigned long vma_size = vma->vm_end - vma->vm_start;

	unsigned long start = 0;
	size_t len = 0;

	adata->handle = ion_alloc(adata->client, vma_size, SZ_4K,
		ION_HEAP(ION_CP_MM_HEAP_ID), 0);
	if (IS_ERR_OR_NULL(adata->handle)) {
		ret = PTR_ERR(adata->handle);
		adata->handle = NULL;
		pr_err("%s: Failed to ion_alloc ret=%d\n", __func__, ret);
		goto err;
	}

	ret = ion_phys(adata->client, adata->handle, &start, &len);
	if (ret) {
		pr_err("%s: Failed to ion_phys ret=%d\n", __func__, ret);
		goto err_free;
	}

	/* Set physical address link with VMA. */
	vma->vm_pgoff = start >> PAGE_SHIFT;

	/* MAP physical address to userspace. */
	ret = remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, vma_size,
		vma->vm_page_prot);
	if (ret) {
		pr_err("%s: Failed to remap_pfn_range ret=%d\n", __func__, ret);
		goto err_free;
	}

	/* Set vma for future mappings. */
	adata->vma = vma;

	pr_debug("%s: Allocated & mmapped p:0x%lx v:0x%lx\n",
		__func__, start, vma->vm_start);

	return 0;
err_free:
	ion_free(adata->client, adata->handle);
	adata->handle = NULL;
err:
	return ret;
}

static int pmem_open(struct inode *inode, struct file *file)
{
	int id = get_id(file);
	struct allocation_data *adata;

	adata = kzalloc(sizeof(*adata), GFP_KERNEL);
	if (!adata)
		return -ENOMEM;

	adata->client = pmem[id].client;

	file->private_data = adata;

	return 0;
}

static int pmem_release(struct inode *inode, struct file *file)
{
	struct allocation_data *adata = file->private_data;

	if (adata->client && adata->handle) {
		ion_free(adata->client, adata->handle);
		adata->handle = NULL;
	}

	file->private_data = NULL;
	kfree(adata);

	return 0;
}

static const struct file_operations pmem_fops = {
	.unlocked_ioctl	= pmem_ioctl,
	.mmap		= pmem_mmap,
	.open		= pmem_open,
	.release	= pmem_release,
};

int pmem_setup(struct android_pmem_platform_data *pdata,
	long (*ioctl)(struct file *, unsigned int, unsigned long),
	int (*release)(struct inode *, struct file *))
{
	int ret;

	static int id = 0;
	pmem[id].client = msm_ion_client_create(-1, pdata->ion_client);
	if (IS_ERR_OR_NULL(pmem[id].client)) {
		ret = PTR_ERR(pmem[id].client);
		pmem[id].client = NULL;
		pr_err("Failed to msm_ion_client_create ret=%d\n", ret);
		goto err;
	}

	/* Dynamic devfs node. */
	pmem[id].dev.name = pdata->name;
	pmem[id].dev.minor = id;
	pmem[id].dev.fops = &pmem_fops;

	ret = misc_register(&pmem[id].dev);
	if (ret) {
		pr_err("Failed to misc_register ret=%d\n", ret);
		goto err_destroy_client;
	}

	id++;

	return 0;
err_destroy_client:
	ion_client_destroy(pmem[id].client);
	pmem[id].client = NULL;
err:
	return ret;
}
EXPORT_SYMBOL(pmem_setup);

static int pmem_probe(struct platform_device *pdev)
{
	struct android_pmem_platform_data *pdata;

	if (!pdev || !pdev->dev.platform_data) {
		pr_err("No pdev/platform_data\n");
		return -EINVAL;
	}
	pdata = pdev->dev.platform_data;

	return pmem_setup(pdata, NULL, NULL);
}

static int pmem_remove(struct platform_device *pdev)
{
	int id = pdev->id;

	misc_deregister(&pmem[id].dev);

	ion_client_destroy(pmem[id].client);
	pmem[id].client = NULL;
	return 0;
}

static struct platform_driver pmem_driver = {
	.probe	= pmem_probe,
	.remove	= pmem_remove,
	.driver	= {
		.name = "android_pmem",
	}
};


static int __init pmem_init(void)
{
	return platform_driver_register(&pmem_driver);
}

static void __exit pmem_exit(void)
{
	platform_driver_unregister(&pmem_driver);
}

module_init(pmem_init);
module_exit(pmem_exit);
