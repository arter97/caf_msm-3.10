/*
 *	All files except if stated otherwise in the beginning of the file
 *	are under the ISC license:
 *	----------------------------------------------------------------------
 *	Copyright (c) 2015-2016, The Linux Foundation. All rights reserved.
 *	Copyright (c) 2010-2012 Design Art Networks Ltd.
 *
 *	Permission to use, copy, modify, and/or distribute this software for any
 *	purpose with or without fee is hereby granted, provided that the above
 *	copyright notice and this permission notice appear in all copies.
 *
 *	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *	ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *	OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/netdevice.h>
#include <linux/ioctl.h>

#include "danipc_k.h"
#include "ipc_api.h"
#include "danipc_lowlevel.h"

static int
danipc_strncmp(const char *cs, const char *ct, size_t cs_size, size_t ct_size)
{
	return ((strnlen(cs, cs_size) == strnlen(ct, ct_size)) &&
		(strcmp(cs, ct) == 0));
}

static int register_local_agent(struct danipc_fifo *fifo,
				struct danipc_reg *danipc_reg,
				void *owner)
{
	unsigned	agent_id = INVALID_ID;
	uint8_t		lcpuid = fifo->node_id;
	unsigned	agent_idx;
	int		rc = 0;

	if (!local_fifo_owner(fifo, owner))
		return -EPERM;

	for (agent_idx = __IPC_AGENT_ID(lcpuid, 0);
		agent_idx < __IPC_AGENT_ID(lcpuid, MAX_LOCAL_AGENT - 1);
		agent_idx++) {

		if (danipc_strncmp(
			danipc_reg->name,
			agent_table[agent_idx].name,
			MAX_AGENT_NAME, MAX_AGENT_NAME_LEN) ||
			agent_table[agent_idx].name[0] == '\0') {
			agent_id = agent_idx;
			break;
		}
	}

	if (agent_id != INVALID_ID) {
		const unsigned an_siz = sizeof(agent_table[agent_id].name);
		const uint16_t cookie = cpu_to_be16(AGENTID_TO_COOKIE(agent_id,
							danipc_reg->prio));
		strlcpy(agent_table[agent_id].name, danipc_reg->name,
			an_siz);
		agent_table[agent_id].name[an_siz-1] = 0;
		danipc_reg->cookie = cookie;
		danipc_reg->assigned_lid = agent_id;
	} else {
		rc = -ENOBUFS;
	}

	return rc;
}

static int discover_agent(struct danipc_name *danipc_name_p)
{
	struct danipc_drvr	*drv = &danipc_driver;
	int			rc = -ENODATA;
	uint16_t		aid;

	for (aid = 0; aid < MAX_AGENTS; aid++) {
		if (danipc_strncmp(danipc_name_p->name, agent_table[aid].name,
				   MAX_AGENT_NAME, MAX_AGENT_NAME_LEN)) {
			const unsigned cpuid = ipc_get_node(aid);
			const unsigned lid = ipc_lid(aid);
			struct ipc_to_virt_map *map = &ipc_to_virt_map[cpuid]
				[ipc_trns_prio_1];

			if (!map->paddr) {
				char *buf = ipc_buf_alloc(aid, ipc_trns_prio_1);

				if (buf)
					ipc_buf_free(buf,
						     ipc_get_node(aid),
						     ipc_trns_prio_1);
			}

			/* Mark destination agent discovered.
			 * Used in admision contol of packet.
			 */
			DANIPC_AGENT_DISCOVERED(aid, drv->dst_aid);

			danipc_name_p->addr = __IPC_AGENT_ID(cpuid, lid);
			rc = 0;
			break;
		}
	}

	return rc;
}

static int get_agent_name(struct danipc_name *danipc_name)
{
	int	rc = -ENODATA;
	uint8_t addr = danipc_name->addr;

	if (addr >= MAX_AGENTS)
		return -EINVAL;

	if (*agent_table[addr].name) {
		memcpy(danipc_name->name,
		       agent_table[addr].name,
		       sizeof(danipc_name->name));
		rc = 0;
	}

	return rc;
}

int danipc_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc = -EINVAL;
	struct danipc_if *intf;
	struct danipc_reg danipc_reg;
	struct danipc_name danipc_name;
	void __user *puser;

	if (!dev || !ifr || !ifr->ifr_data)
		goto done;

	intf = netdev_priv(dev);
	puser = ifr->ifr_data;

	mutex_lock(&intf->lock);
	switch (cmd) {
	case DANIPC_IOCS_REGISTER:
		if (copy_from_user(&danipc_reg, puser, sizeof(danipc_reg))) {
			rc = -EFAULT;
			break;
		}

		rc = register_local_agent(intf->fifo, &danipc_reg, intf);
		if (rc) {
			netdev_err(dev,
				   "%s: register_local_agent failed, ret=%d\n",
				   __func__, rc);
			break;
		}

		if (put_user(danipc_reg.cookie,
			     &((struct danipc_reg *)puser)->cookie)) {
			rc = -EFAULT;
			break;
		}

		if (put_user(danipc_reg.assigned_lid,
			     &((struct danipc_reg *)puser)->assigned_lid)) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_ADDR2NAME:
		if (get_user(danipc_name.addr,
			     &((struct danipc_name *)puser)->addr)) {
			rc = -EFAULT;
			break;
		}

		rc = get_agent_name(&danipc_name);
		if (rc)
			break;

		if (copy_to_user(((struct danipc_name *)puser)->name,
				 danipc_name.name,
				 sizeof(danipc_name.name))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_NAME2ADDR:
		if (copy_from_user(danipc_name.name,
				   ((struct danipc_name *)puser)->name,
				   sizeof(danipc_name.name))) {
			rc = -EFAULT;
			break;
		}

		rc = discover_agent(&danipc_name);
		if (rc)
			break;

		if (put_user(danipc_name.addr,
			     &((struct danipc_name *)puser)->addr)) {
			rc = -EFAULT;
			break;
		}
		break;
	}
	mutex_unlock(&intf->lock);

done:
	return rc;
}

long danipc_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct danipc_cdev *cdev = file->private_data;
	void __user *argp = (void __user *)arg;
	struct danipc_reg danipc_reg;
	struct danipc_name danipc_name;
	struct danipc_cdev_mmsg mmsg;
	struct danipc_bufs danipc_bufs;
	int i;
	int rc = -EINVAL;
	unsigned num;

	switch (cmd) {
	case DANIPC_IOCS_REGISTER:
		if (copy_from_user(&danipc_reg, argp, sizeof(danipc_reg))) {
			rc = -EFAULT;
			break;
		}

		rc = register_local_agent(cdev->fifo, &danipc_reg, cdev);
		if (rc) {
			dev_err(cdev->dev,
				"%s: register_local_agent failed, ret=%d\n",
			       __func__, rc);
			break;
		}

		if (put_user(danipc_reg.cookie,
			     &((struct danipc_reg *)argp)->cookie)) {
			rc = -EFAULT;
			break;
		}

		if (put_user(danipc_reg.assigned_lid,
			     &((struct danipc_reg *)argp)->assigned_lid)) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_ADDR2NAME:
		if (get_user(danipc_name.addr,
			     &((struct danipc_name *)argp)->addr)) {
			rc = -EFAULT;
			break;
		}

		rc = get_agent_name(&danipc_name);
		if (rc)
			break;

		if (copy_to_user(((struct danipc_name *)argp)->name,
				 danipc_name.name,
				 sizeof(danipc_name.name))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_NAME2ADDR:
		if (copy_from_user(danipc_name.name,
				   &((struct danipc_name *)argp)->name,
				   sizeof(danipc_name.name))) {
			rc = -EFAULT;
			break;
		}

		rc = discover_agent(&danipc_name);
		if (rc)
			break;

		if (put_user(danipc_name.addr,
			     &((struct danipc_name *)argp)->addr)) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCS_MMSGSEND:
		if (copy_from_user(&mmsg, argp, sizeof(mmsg))) {
			rc = -EFAULT;
			break;
		}
		if (!mmsg.msgs.num_entry ||
		    mmsg.msgs.num_entry > DANIPC_BUFS_MAX_NUM_BUF) {
			rc = -EINVAL;
			break;
		}
		for (i = 0; i < mmsg.msgs.num_entry; i++) {
			rc = danipc_cdev_tx(cdev,
					    &mmsg.hdr,
					    mmsg.msgs.entry[i].data,
					    mmsg.msgs.entry[i].data_len);
			if (rc)
				break;
		}
		if (!rc)
			rc = i;
		break;
	case DANIPC_IOCS_MMSGRECV:
		if (copy_from_user(&mmsg, argp, sizeof(mmsg))) {
			rc = -EFAULT;
			break;
		}
		rc = danipc_cdev_mmsg_rx(cdev, &mmsg);
		if (rc < 0)
			break;
		if (copy_to_user(argp, &mmsg, sizeof(mmsg))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_RECV:
		if (get_user(danipc_bufs.num_entry,
			     &((struct danipc_bufs *)argp)->num_entry)) {
			rc = -EFAULT;
			break;
		}
		rc = danipc_cdev_mapped_recv(cdev, cdev->rx_vma, &danipc_bufs);
		if (rc < 0)
			break;

		if (copy_to_user(argp, &danipc_bufs, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCS_RECVACK:
		if (copy_from_user(&danipc_bufs, argp, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		rc = danipc_cdev_mapped_recv_done(cdev,
						  cdev->rx_vma,
						  &danipc_bufs);
		break;
	case DANIPC_IOCS_RECVACK_RECV:
		if (copy_from_user(&danipc_bufs, argp, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		num = danipc_bufs.num_entry;

		rc = danipc_cdev_mapped_recv_done(cdev,
						  cdev->rx_vma,
						  &danipc_bufs);
		if (rc)
			break;

		danipc_bufs.num_entry = num;

		rc = danipc_cdev_mapped_recv(cdev, cdev->rx_vma, &danipc_bufs);

		if (rc < 0)
			break;

		if (copy_to_user(argp, &danipc_bufs, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCS_SEND:
		if (copy_from_user(&danipc_bufs, argp, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}

		rc = danipc_cdev_mapped_tx(cdev, &danipc_bufs);
		break;
	case DANIPC_IOCG_GET_SENDBUF:
		if (get_user(danipc_bufs.num_entry,
			     &((struct danipc_bufs *)argp)->num_entry)) {
			rc = -EFAULT;
			break;
		}
		if (danipc_bufs.num_entry > DANIPC_BUFS_MAX_NUM_BUF) {
			dev_dbg(cdev->dev,
				"%s: IOCG_GET_SENDBUF invalid num_buf %u\n",
				__func__, danipc_bufs.num_entry);
			rc = -EINVAL;
			break;
		}
		rc = danipc_cdev_mapped_tx_get_buf(cdev, &danipc_bufs);
		if (rc)
			break;

		if (copy_to_user(argp, &danipc_bufs, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCG_SEND_GET_SENDBUF:
		if (copy_from_user(&danipc_bufs, argp, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}

		num = danipc_bufs.num_entry;
		rc = danipc_cdev_mapped_tx(cdev, &danipc_bufs);
		if (rc < 0)
			break;

		danipc_bufs.num_entry = num;
		rc = danipc_cdev_mapped_tx_get_buf(cdev, &danipc_bufs);
		if (rc)
			break;

		if (copy_to_user(argp, &danipc_bufs, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}
		break;
	case DANIPC_IOCS_RET_SENDBUF:
		if (copy_from_user(&danipc_bufs, argp, sizeof(danipc_bufs))) {
			rc = -EFAULT;
			break;
		}

		rc = danipc_cdev_mapped_tx_put_buf(cdev, &danipc_bufs);
		break;
	}
	return rc;
}
