<<<<<<< HEAD
/* Copyright (c) 2010-2014, The Linux Foundation. All rights reserved.
=======
/* Copyright (c) 2010-2013, The Linux Foundation. All rights reserved.
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
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

#include <linux/export.h>
#include <linux/kernel.h>

<<<<<<< HEAD
#include "kgsl.h"
#include "kgsl_pwrscale.h"
#include "kgsl_device.h"
#include "kgsl_trace.h"

#define FAST_BUS 1
#define SLOW_BUS -1

static void do_devfreq_suspend(struct work_struct *work);
static void do_devfreq_resume(struct work_struct *work);
static void do_devfreq_notify(struct work_struct *work);

/*
 * kgsl_pwrscale_sleep - notify governor that device is going off
 * @device: The device
 *
 * Called shortly after all pending work is completed.
 */
void kgsl_pwrscale_sleep(struct kgsl_device *device)
{
	BUG_ON(!mutex_is_locked(&device->mutex));
	if (!device->pwrscale.enabled)
		return;
	device->pwrscale.time = device->pwrscale.on_time = 0;

	/* to call devfreq_suspend_device() from a kernel thread */
	queue_work(device->pwrscale.devfreq_wq,
		&device->pwrscale.devfreq_suspend_ws);
}
EXPORT_SYMBOL(kgsl_pwrscale_sleep);

/*
 * kgsl_pwrscale_wake - notify governor that device is going on
 * @device: The device
 *
 * Called when the device is returning to an active state.
 */
void kgsl_pwrscale_wake(struct kgsl_device *device)
{
	struct kgsl_power_stats stats;
	BUG_ON(!mutex_is_locked(&device->mutex));

	if (!device->pwrscale.enabled)
		return;
	/* clear old stats before waking */
	memset(&device->pwrscale.accum_stats, 0,
		sizeof(device->pwrscale.accum_stats));

	/* and any hw activity from waking up*/
	device->ftbl->power_stats(device, &stats);

	device->pwrscale.time = ktime_to_us(ktime_get());

	device->pwrscale.next_governor_call = 0;

	/* to call devfreq_resume_device() from a kernel thread */
	queue_work(device->pwrscale.devfreq_wq,
		&device->pwrscale.devfreq_resume_ws);
}
EXPORT_SYMBOL(kgsl_pwrscale_wake);

/*
 * kgsl_pwrscale_busy - update pwrscale state for new work
 * @device: The device
 *
 * Called when new work is submitted to the device.
 * This function must be called with the device mutex locked.
 */
void kgsl_pwrscale_busy(struct kgsl_device *device)
{
	BUG_ON(!mutex_is_locked(&device->mutex));
	if (!device->pwrscale.enabled)
		return;
	if (device->pwrscale.on_time == 0)
		device->pwrscale.on_time = ktime_to_us(ktime_get());
}
EXPORT_SYMBOL(kgsl_pwrscale_busy);

/*
 * kgsl_pwrscale_update - update device busy statistics
 * @device: The device
 *
 * Read hardware busy counters when the device is likely to be
 * on and accumulate the results between devfreq get_dev_status
 * calls. This is limits the need to turn on clocks to read these
 * values for governors that run independently of hardware
 * activity (for example, by time based polling).
 */
void kgsl_pwrscale_update(struct kgsl_device *device)
{
	struct kgsl_power_stats stats;
	BUG_ON(!mutex_is_locked(&device->mutex));

	if (!device->pwrscale.enabled)
		return;

	if (device->pwrscale.next_governor_call == 0)
		device->pwrscale.next_governor_call = jiffies;

	if (time_before(jiffies, device->pwrscale.next_governor_call))
		return;

	device->pwrscale.next_governor_call = jiffies
			+ msecs_to_jiffies(KGSL_GOVERNOR_CALL_INTERVAL);

	if (device->state == KGSL_STATE_ACTIVE) {
		device->ftbl->power_stats(device, &stats);
		device->pwrscale.accum_stats.busy_time += stats.busy_time;
		device->pwrscale.accum_stats.ram_time += stats.ram_time;
		device->pwrscale.accum_stats.ram_wait += stats.ram_wait;
	}

	/* to call srcu_notifier_call_chain() from a kernel thread */
	if (device->requested_state != KGSL_STATE_SLUMBER)
		queue_work(device->pwrscale.devfreq_wq,
			&device->pwrscale.devfreq_notify_ws);
}
EXPORT_SYMBOL(kgsl_pwrscale_update);

/*
 * kgsl_pwrscale_disable - temporarily disable the governor
 * @device: The device
 *
 * Temporarily disable the governor, to prevent interference
 * with profiling tools that expect a fixed clock frequency.
 * This function must be called with the device mutex locked.
 */
void kgsl_pwrscale_disable(struct kgsl_device *device)
{
	BUG_ON(!mutex_is_locked(&device->mutex));

	if (device->pwrscale.enabled) {
		queue_work(device->pwrscale.devfreq_wq,
			&device->pwrscale.devfreq_suspend_ws);
		device->pwrscale.enabled = false;
		kgsl_pwrctrl_pwrlevel_change(device, KGSL_PWRLEVEL_TURBO);
	}
}
EXPORT_SYMBOL(kgsl_pwrscale_disable);

/*
 * kgsl_pwrscale_enable - re-enable the governor
 * @device: The device
 *
 * Reenable the governor after a kgsl_pwrscale_disable() call.
 * This function must be called with the device mutex locked.
 */
void kgsl_pwrscale_enable(struct kgsl_device *device)
{
	BUG_ON(!mutex_is_locked(&device->mutex));

	if (!device->pwrscale.enabled) {
		device->pwrscale.enabled = true;
		queue_work(device->pwrscale.devfreq_wq,
			&device->pwrscale.devfreq_resume_ws);
	}
}
EXPORT_SYMBOL(kgsl_pwrscale_enable);

/*
 * kgsl_devfreq_target - devfreq_dev_profile.target callback
 * @dev: see devfreq.h
 * @freq: see devfreq.h
 * @flags: see devfreq.h
 *
 * This function expects the device mutex to be unlocked.
 */
int kgsl_devfreq_target(struct device *dev, unsigned long *freq, u32 flags)
{
	struct kgsl_device *device = dev_get_drvdata(dev);
	struct kgsl_pwrctrl *pwr;
	int level, i, b;
	unsigned long cur_freq;

	if (device == NULL)
		return -ENODEV;
	if (freq == NULL)
		return -EINVAL;
	if (!device->pwrscale.enabled)
		return 0;

	pwr = &device->pwrctrl;

	mutex_lock(&device->mutex);
	cur_freq = kgsl_pwrctrl_active_freq(pwr);
	level = pwr->active_pwrlevel;

	if (*freq != cur_freq) {
		level = pwr->max_pwrlevel;
		for (i = pwr->min_pwrlevel; i >= pwr->max_pwrlevel; i--)
			if (*freq <= pwr->pwrlevels[i].gpu_freq) {
				level = i;
				break;
			}
	} else if (flags && pwr->bus_control) {
		/*
		 * Signal for faster or slower bus.  If KGSL isn't already
		 * running at the desired speed for the given level, modify
		 * its vote.
		 */
		b = pwr->bus_mod;
		if ((flags & DEVFREQ_FLAG_FAST_HINT) &&
			(pwr->bus_mod != FAST_BUS))
			pwr->bus_mod = (pwr->bus_mod == SLOW_BUS) ?
					0 : FAST_BUS;
		else if ((flags & DEVFREQ_FLAG_SLOW_HINT) &&
			(pwr->bus_mod != SLOW_BUS))
			pwr->bus_mod = (pwr->bus_mod == FAST_BUS) ?
					0 : SLOW_BUS;
		if (pwr->bus_mod != b)
			kgsl_pwrctrl_buslevel_update(device, true);
	}

	kgsl_pwrctrl_pwrlevel_change(device, level);

	/*Invalidate the constraint set */
	pwr->constraint.type = KGSL_CONSTRAINT_NONE;

	*freq = kgsl_pwrctrl_active_freq(pwr);

	mutex_unlock(&device->mutex);
	return 0;
}
EXPORT_SYMBOL(kgsl_devfreq_target);

/*
 * kgsl_devfreq_get_dev_status - devfreq_dev_profile.get_dev_status callback
 * @dev: see devfreq.h
 * @freq: see devfreq.h
 * @flags: see devfreq.h
 *
 * This function expects the device mutex to be unlocked.
 */
int kgsl_devfreq_get_dev_status(struct device *dev,
				struct devfreq_dev_status *stat)
{
	struct kgsl_device *device = dev_get_drvdata(dev);
	struct kgsl_pwrscale *pwrscale;
	s64 tmp;

	if (device == NULL)
		return -ENODEV;
	if (stat == NULL)
		return -EINVAL;

	pwrscale = &device->pwrscale;

	mutex_lock(&device->mutex);
	/* make sure we don't turn on clocks just to read stats */
	if (device->state == KGSL_STATE_ACTIVE) {
		struct kgsl_power_stats extra;
		device->ftbl->power_stats(device, &extra);
		device->pwrscale.accum_stats.busy_time += extra.busy_time;
		device->pwrscale.accum_stats.ram_time += extra.ram_time;
		device->pwrscale.accum_stats.ram_wait += extra.ram_wait;
	}

	tmp = ktime_to_us(ktime_get());
	stat->total_time = tmp - pwrscale->time;
	pwrscale->time = tmp;

	stat->busy_time = pwrscale->accum_stats.busy_time;

	stat->current_frequency = kgsl_pwrctrl_active_freq(&device->pwrctrl);

	if (stat->private_data) {
		struct xstats *b = (struct xstats *)stat->private_data;
		b->ram_time = device->pwrscale.accum_stats.ram_time;
		b->ram_wait = device->pwrscale.accum_stats.ram_wait;
		b->mod = device->pwrctrl.bus_mod;
	}

	trace_kgsl_pwrstats(device, stat->total_time, &pwrscale->accum_stats);
	memset(&pwrscale->accum_stats, 0, sizeof(pwrscale->accum_stats));

	mutex_unlock(&device->mutex);

	return 0;
}
EXPORT_SYMBOL(kgsl_devfreq_get_dev_status);

/*
 * kgsl_devfreq_get_cur_freq - devfreq_dev_profile.get_cur_freq callback
 * @dev: see devfreq.h
 * @freq: see devfreq.h
 * @flags: see devfreq.h
 *
 * This function expects the device mutex to be unlocked.
 */
int kgsl_devfreq_get_cur_freq(struct device *dev, unsigned long *freq)
{
	struct kgsl_device *device = dev_get_drvdata(dev);

	if (device == NULL)
		return -ENODEV;
	if (freq == NULL)
		return -EINVAL;

	mutex_lock(&device->mutex);
	*freq = kgsl_pwrctrl_active_freq(&device->pwrctrl);
	mutex_unlock(&device->mutex);

	return 0;
}
EXPORT_SYMBOL(kgsl_devfreq_get_cur_freq);

/*
 * kgsl_devfreq_add_notifier - add a fine grained notifier.
 * @dev: The device
 * @nb: Notifier block that will recieve updates.
 *
 * Add a notifier to recieve ADRENO_DEVFREQ_NOTIFY_* events
 * from the device.
 */
int kgsl_devfreq_add_notifier(struct device *dev, struct notifier_block *nb)
{
	struct kgsl_device *device = dev_get_drvdata(dev);

	if (device == NULL)
		return -ENODEV;

	if (nb == NULL)
		return -EINVAL;

	return srcu_notifier_chain_register(&device->pwrscale.nh, nb);
}

void kgsl_pwrscale_idle(struct kgsl_device *device)
{
	BUG_ON(!mutex_is_locked(&device->mutex));
	queue_work(device->pwrscale.devfreq_wq,
		&device->pwrscale.devfreq_notify_ws);
}
EXPORT_SYMBOL(kgsl_pwrscale_idle);

/*
 * kgsl_devfreq_del_notifier - remove a fine grained notifier.
 * @dev: The device
 * @nb: The notifier block.
 *
 * Remove a notifier registered with kgsl_devfreq_add_notifier().
 */
int kgsl_devfreq_del_notifier(struct device *dev, struct notifier_block *nb)
{
	struct kgsl_device *device = dev_get_drvdata(dev);

	if (device == NULL)
		return -ENODEV;

	if (nb == NULL)
		return -EINVAL;

	return srcu_notifier_chain_unregister(&device->pwrscale.nh, nb);
}
EXPORT_SYMBOL(kgsl_devfreq_del_notifier);

/*
 * kgsl_pwrscale_init - Initialize pwrscale.
 * @dev: The device
 * @governor: The initial governor to use.
 *
 * Initialize devfreq and any non-constant profile data.
 */
int kgsl_pwrscale_init(struct device *dev, const char *governor)
{
	struct kgsl_device *device;
	struct kgsl_pwrscale *pwrscale;
	struct kgsl_pwrctrl *pwr;
	struct devfreq *devfreq;
	struct devfreq_dev_profile *profile;
	struct devfreq_msm_adreno_tz_data *data;
	int i, out = 0;
	int ret;

	device = dev_get_drvdata(dev);
	if (device == NULL)
		return -ENODEV;

	pwrscale = &device->pwrscale;
	pwr = &device->pwrctrl;
	profile = &pwrscale->profile;

	srcu_init_notifier_head(&pwrscale->nh);

	profile->initial_freq =
		pwr->pwrlevels[pwr->default_pwrlevel].gpu_freq;
	/* Let's start with 10 ms and tune in later */
	profile->polling_ms = 10;

	/* do not include the 'off' level or duplicate freq. levels */
	for (i = 0; i < (pwr->num_pwrlevels - 1); i++)
		pwrscale->freq_table[out++] = pwr->pwrlevels[i].gpu_freq;

	profile->max_state = out;
	/* link storage array to the devfreq profile pointer */
	profile->freq_table = pwrscale->freq_table;

	/* if there is only 1 freq, no point in running a governor */
	if (profile->max_state == 1)
		governor = "performance";

	/* initialize any governor specific data here */
	for (i = 0; i < profile->num_governor_data; i++) {
		if (strncmp("msm-adreno-tz",
				profile->governor_data[i].name,
				DEVFREQ_NAME_LEN) == 0) {
			data = (struct devfreq_msm_adreno_tz_data *)
				profile->governor_data[i].data;
			/*
			 * If there is a separate GX power rail, allow
			 * independent modification to its voltage through
			 * the bus bandwidth vote.
			 */
			if (pwr->bus_control) {
				out = 0;
				while (pwr->bus_ib[out]) {
					pwr->bus_ib[out] =
						pwr->bus_ib[out] >> 20;
					out++;
				}
				data->bus.num = out;
				data->bus.ib = &pwr->bus_ib[0];
				data->bus.index = &pwr->bus_index[0];
				printk("kgsl: num bus is %d\n", out);
			} else {
				data->bus.num = 0;
			}
		}
	}

	devfreq = devfreq_add_device(dev, &pwrscale->profile, governor, NULL);
	if (IS_ERR(devfreq))
		return PTR_ERR(devfreq);

	pwrscale->devfreq = devfreq;

	ret = sysfs_create_link(&device->dev->kobj,
			&devfreq->dev.kobj, "devfreq");

	pwrscale->devfreq_wq = create_freezable_workqueue("kgsl_devfreq_wq");
	INIT_WORK(&pwrscale->devfreq_suspend_ws, do_devfreq_suspend);
	INIT_WORK(&pwrscale->devfreq_resume_ws, do_devfreq_resume);
	INIT_WORK(&pwrscale->devfreq_notify_ws, do_devfreq_notify);

	pwrscale->next_governor_call = 0;

	return 0;
}
EXPORT_SYMBOL(kgsl_pwrscale_init);

/*
 * kgsl_pwrscale_close - clean up pwrscale
 * @device: the device
 *
 * This function should be called with the device mutex locked.
 */
void kgsl_pwrscale_close(struct kgsl_device *device)
{
	struct kgsl_pwrscale *pwrscale;

	BUG_ON(!mutex_is_locked(&device->mutex));

	pwrscale = &device->pwrscale;
	flush_workqueue(pwrscale->devfreq_wq);
	destroy_workqueue(pwrscale->devfreq_wq);
	devfreq_remove_device(device->pwrscale.devfreq);
	device->pwrscale.devfreq = NULL;
	srcu_cleanup_notifier_head(&device->pwrscale.nh);
}
EXPORT_SYMBOL(kgsl_pwrscale_close);

static void do_devfreq_suspend(struct work_struct *work)
{
	struct kgsl_pwrscale *pwrscale = container_of(work,
			struct kgsl_pwrscale, devfreq_suspend_ws);
	struct devfreq *devfreq = pwrscale->devfreq;

	devfreq_suspend_device(devfreq);
}

static void do_devfreq_resume(struct work_struct *work)
{
	struct kgsl_pwrscale *pwrscale = container_of(work,
			struct kgsl_pwrscale, devfreq_resume_ws);
	struct devfreq *devfreq = pwrscale->devfreq;

	devfreq_resume_device(devfreq);
}

static void do_devfreq_notify(struct work_struct *work)
{
	struct kgsl_pwrscale *pwrscale = container_of(work,
			struct kgsl_pwrscale, devfreq_notify_ws);
	struct devfreq *devfreq = pwrscale->devfreq;
	srcu_notifier_call_chain(&pwrscale->nh,
				 ADRENO_DEVFREQ_NOTIFY_RETIRE,
				 devfreq);
}
=======
#include <asm/page.h>

#include "kgsl.h"
#include "kgsl_pwrscale.h"
#include "kgsl_device.h"

struct kgsl_pwrscale_attribute {
	struct attribute attr;
	ssize_t (*show)(struct kgsl_device *device, char *buf);
	ssize_t (*store)(struct kgsl_device *device, const char *buf,
			 size_t count);
};

#define to_pwrscale(k) container_of(k, struct kgsl_pwrscale, kobj)
#define pwrscale_to_device(p) container_of(p, struct kgsl_device, pwrscale)
#define to_device(k) container_of(k, struct kgsl_device, pwrscale_kobj)
#define to_pwrscale_attr(a) \
container_of(a, struct kgsl_pwrscale_attribute, attr)
#define to_policy_attr(a) \
container_of(a, struct kgsl_pwrscale_policy_attribute, attr)

#define PWRSCALE_ATTR(_name, _mode, _show, _store) \
struct kgsl_pwrscale_attribute pwrscale_attr_##_name = \
__ATTR(_name, _mode, _show, _store)

/* Master list of available policies */

static struct kgsl_pwrscale_policy *kgsl_pwrscale_policies[] = {
#ifdef CONFIG_MSM_SCM
	&kgsl_pwrscale_policy_tz,
#endif
#ifdef CONFIG_MSM_SLEEP_STATS_DEVICE
	&kgsl_pwrscale_policy_idlestats,
#endif
	NULL
};

static ssize_t pwrscale_policy_store(struct kgsl_device *device,
				     const char *buf, size_t count)
{
	int i;
	struct kgsl_pwrscale_policy *policy = NULL;

	/* The special keyword none allows the user to detach all
	   policies */
	if (!strncmp("none", buf, 4)) {
		kgsl_pwrscale_detach_policy(device);
		return count;
	}

	for (i = 0; kgsl_pwrscale_policies[i]; i++) {
		if (!strncmp(kgsl_pwrscale_policies[i]->name, buf,
			     strnlen(kgsl_pwrscale_policies[i]->name,
				PAGE_SIZE))) {
			policy = kgsl_pwrscale_policies[i];
			break;
		}
	}

	if (policy)
		if (kgsl_pwrscale_attach_policy(device, policy))
			return -EIO;

	return count;
}

static ssize_t pwrscale_policy_show(struct kgsl_device *device, char *buf)
{
	int ret;

	if (device->pwrscale.policy) {
		ret = snprintf(buf, PAGE_SIZE, "%s",
			       device->pwrscale.policy->name);
		if (device->pwrscale.enabled == 0)
			ret += snprintf(buf + ret, PAGE_SIZE - ret,
				" (disabled)");
		ret += snprintf(buf + ret, PAGE_SIZE - ret, "\n");
	} else
		ret = snprintf(buf, PAGE_SIZE, "none\n");

	return ret;
}

PWRSCALE_ATTR(policy, 0664, pwrscale_policy_show, pwrscale_policy_store);

static ssize_t pwrscale_avail_policies_show(struct kgsl_device *device,
					    char *buf)
{
	int i, ret = 0;

	for (i = 0; kgsl_pwrscale_policies[i]; i++) {
		ret += snprintf(buf + ret, PAGE_SIZE - ret, "%s ",
				kgsl_pwrscale_policies[i]->name);
	}

	ret += snprintf(buf + ret, PAGE_SIZE - ret, "none\n");
	return ret;
}
PWRSCALE_ATTR(avail_policies, 0444, pwrscale_avail_policies_show, NULL);

static struct attribute *pwrscale_attrs[] = {
	&pwrscale_attr_policy.attr,
	&pwrscale_attr_avail_policies.attr,
	NULL
};

static ssize_t policy_sysfs_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct kgsl_pwrscale *pwrscale = to_pwrscale(kobj);
	struct kgsl_device *device = pwrscale_to_device(pwrscale);
	struct kgsl_pwrscale_policy_attribute *pattr = to_policy_attr(attr);
	ssize_t ret;

	if (pattr->show)
		ret = pattr->show(device, pwrscale, buf);
	else
		ret = -EIO;

	return ret;
}

static ssize_t policy_sysfs_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t count)
{
	struct kgsl_pwrscale *pwrscale = to_pwrscale(kobj);
	struct kgsl_device *device = pwrscale_to_device(pwrscale);
	struct kgsl_pwrscale_policy_attribute *pattr = to_policy_attr(attr);
	ssize_t ret;

	if (pattr->store)
		ret = pattr->store(device, pwrscale, buf, count);
	else
		ret = -EIO;

	return ret;
}

static void policy_sysfs_release(struct kobject *kobj)
{
}

static ssize_t pwrscale_sysfs_show(struct kobject *kobj,
				   struct attribute *attr, char *buf)
{
	struct kgsl_device *device = to_device(kobj);
	struct kgsl_pwrscale_attribute *pattr = to_pwrscale_attr(attr);
	ssize_t ret;

	if (pattr->show)
		ret = pattr->show(device, buf);
	else
		ret = -EIO;

	return ret;
}

static ssize_t pwrscale_sysfs_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf, size_t count)
{
	struct kgsl_device *device = to_device(kobj);
	struct kgsl_pwrscale_attribute *pattr = to_pwrscale_attr(attr);
	ssize_t ret;

	if (pattr->store)
		ret = pattr->store(device, buf, count);
	else
		ret = -EIO;

	return ret;
}

static void pwrscale_sysfs_release(struct kobject *kobj)
{
}

static const struct sysfs_ops policy_sysfs_ops = {
	.show = policy_sysfs_show,
	.store = policy_sysfs_store
};

static const struct sysfs_ops pwrscale_sysfs_ops = {
	.show = pwrscale_sysfs_show,
	.store = pwrscale_sysfs_store
};

static struct kobj_type ktype_pwrscale_policy = {
	.sysfs_ops = &policy_sysfs_ops,
	.default_attrs = NULL,
	.release = policy_sysfs_release
};

static struct kobj_type ktype_pwrscale = {
	.sysfs_ops = &pwrscale_sysfs_ops,
	.default_attrs = pwrscale_attrs,
	.release = pwrscale_sysfs_release
};

#define PWRSCALE_ACTIVE(_d) \
	((_d)->pwrscale.policy && (_d)->pwrscale.enabled)

void kgsl_pwrscale_sleep(struct kgsl_device *device)
{
	if (PWRSCALE_ACTIVE(device) && device->pwrscale.policy->sleep)
		device->pwrscale.policy->sleep(device, &device->pwrscale);
}
EXPORT_SYMBOL(kgsl_pwrscale_sleep);

void kgsl_pwrscale_wake(struct kgsl_device *device)
{
	if (PWRSCALE_ACTIVE(device) && device->pwrscale.policy->wake)
		device->pwrscale.policy->wake(device, &device->pwrscale);
}
EXPORT_SYMBOL(kgsl_pwrscale_wake);

void kgsl_pwrscale_busy(struct kgsl_device *device)
{
	if (PWRSCALE_ACTIVE(device) && device->pwrscale.policy->busy)
		device->pwrscale.policy->busy(device,
				&device->pwrscale);
}
EXPORT_SYMBOL(kgsl_pwrscale_busy);

void kgsl_pwrscale_idle(struct kgsl_device *device)
{
	if (PWRSCALE_ACTIVE(device) && device->pwrscale.policy->idle)
		if (device->state == KGSL_STATE_ACTIVE)
			device->pwrscale.policy->idle(device,
					&device->pwrscale);
}
EXPORT_SYMBOL(kgsl_pwrscale_idle);

void kgsl_pwrscale_disable(struct kgsl_device *device)
{
	device->pwrscale.enabled = 0;
}
EXPORT_SYMBOL(kgsl_pwrscale_disable);

void kgsl_pwrscale_enable(struct kgsl_device *device)
{
	device->pwrscale.enabled = 1;
}
EXPORT_SYMBOL(kgsl_pwrscale_enable);

int kgsl_pwrscale_policy_add_files(struct kgsl_device *device,
				   struct kgsl_pwrscale *pwrscale,
				   struct attribute_group *attr_group)
{
	int ret;

	ret = kobject_add(&pwrscale->kobj, &device->pwrscale_kobj,
		"%s", pwrscale->policy->name);

	if (ret)
		return ret;

	ret = sysfs_create_group(&pwrscale->kobj, attr_group);

	if (ret) {
		kobject_del(&pwrscale->kobj);
		kobject_put(&pwrscale->kobj);
	}

	return ret;
}

void kgsl_pwrscale_policy_remove_files(struct kgsl_device *device,
				       struct kgsl_pwrscale *pwrscale,
				       struct attribute_group *attr_group)
{
	sysfs_remove_group(&pwrscale->kobj, attr_group);
	kobject_del(&pwrscale->kobj);
	kobject_put(&pwrscale->kobj);
}

static void _kgsl_pwrscale_detach_policy(struct kgsl_device *device)
{
	if (device->pwrscale.policy != NULL) {
		device->pwrscale.policy->close(device, &device->pwrscale);

		/*
		 * Try to set max pwrlevel which will be limited to thermal by
		 * kgsl_pwrctrl_pwrlevel_change if thermal is indeed lower
		 */

		kgsl_pwrctrl_pwrlevel_change(device,
				device->pwrctrl.max_pwrlevel);
		device->pwrctrl.default_pwrlevel =
				device->pwrctrl.max_pwrlevel;
	}
	device->pwrscale.policy = NULL;
}

void kgsl_pwrscale_detach_policy(struct kgsl_device *device)
{
	mutex_lock(&device->mutex);
	_kgsl_pwrscale_detach_policy(device);
	mutex_unlock(&device->mutex);
}
EXPORT_SYMBOL(kgsl_pwrscale_detach_policy);

int kgsl_pwrscale_attach_policy(struct kgsl_device *device,
				struct kgsl_pwrscale_policy *policy)
{
	int ret = 0;

	mutex_lock(&device->mutex);

	if (device->pwrscale.policy == policy)
		goto done;

	if (device->pwrctrl.num_pwrlevels < 3) {
		ret = -EINVAL;
		goto done;
	}

	if (device->pwrscale.policy != NULL)
		_kgsl_pwrscale_detach_policy(device);

	device->pwrscale.policy = policy;

	device->pwrctrl.default_pwrlevel =
			device->pwrctrl.init_pwrlevel;
	/* Pwrscale is enabled by default at attach time */
	kgsl_pwrscale_enable(device);

	if (policy) {
		ret = device->pwrscale.policy->init(device, &device->pwrscale);
		if (ret)
			device->pwrscale.policy = NULL;
	}

done:
	mutex_unlock(&device->mutex);

	return ret;
}
EXPORT_SYMBOL(kgsl_pwrscale_attach_policy);

int kgsl_pwrscale_init(struct kgsl_device *device)
{
	int ret;

	ret = kobject_init_and_add(&device->pwrscale_kobj, &ktype_pwrscale,
		&device->dev->kobj, "pwrscale");

	if (ret)
		return ret;

	kobject_init(&device->pwrscale.kobj, &ktype_pwrscale_policy);
	return ret;
}
EXPORT_SYMBOL(kgsl_pwrscale_init);

void kgsl_pwrscale_close(struct kgsl_device *device)
{
	kobject_put(&device->pwrscale_kobj);
}
EXPORT_SYMBOL(kgsl_pwrscale_close);
>>>>>>> 6b2fd9dc8e02232511eb141dbdead145fe1cea60
