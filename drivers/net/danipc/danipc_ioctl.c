/*
 *	All files except if stated otherwise in the beginning of the file
 *	are under the ISC license:
 *	----------------------------------------------------------------------
 *	Copyright (c) 2015, The Linux Foundation. All rights reserved.
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

int
register_agent(struct net_device *dev, struct danipc_reg *danipc_reg_p)
{
	struct danipc_reg	danipc_reg;
	unsigned		agent_id = INVALID_ID;
	int			rc = 0;
	struct danipc_if	*intf = (struct danipc_if *)netdev_priv(dev);
	uint8_t		lcpuid = intf->rx_fifo_idx;
	unsigned		agent_idx;

	if (copy_from_user(&danipc_reg, danipc_reg_p, sizeof(danipc_reg)))
		return -EFAULT;

	for (agent_idx = __IPC_AGENT_ID(lcpuid, 0);
		agent_idx < __IPC_AGENT_ID(lcpuid, MAX_LOCAL_AGENT - 1);
		agent_idx++) {

		if (danipc_strncmp(
			danipc_reg.name,
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
							danipc_reg.prio));
		strlcpy(agent_table[agent_id].name, danipc_reg.name,
			an_siz);
		agent_table[agent_id].name[an_siz-1] = 0;
		if (put_user(cookie, &danipc_reg_p->cookie))
			rc = -EFAULT;

		if (put_user(agent_id, &danipc_reg_p->assigned_lid))
			return -EFAULT;

		netdev_dbg(
		dev, "%s: agent_id=0x%x cpuid=%d agent_table[]=\"%s\"\n",
		__func__, agent_id, lcpuid, agent_table[agent_id].name);
	} else {
		rc = -ENOBUFS;
	}

	return rc;
}

static int
get_name_by_addr(struct net_device *dev, struct danipc_name *danipc_name_p)
{
	int			rc = -ENODATA;
	danipc_addr_t		addr;

	if (get_user(addr, &danipc_name_p->addr))
		return -EFAULT;

	if (*agent_table[addr].name) {
		if (copy_to_user(danipc_name_p->name,
				 agent_table[danipc_name_p->addr].name,
				 sizeof(danipc_name_p->name)))
			rc = -EFAULT;
		else
			rc = 0;
		netdev_dbg(dev, "%s(): addr=0x%x -> name=%s\n", __func__,
			   addr, agent_table[danipc_name_p->addr].name);
	}

	return rc;
}

static int
get_addr_by_name(struct net_device *dev, struct danipc_name *danipc_name_p)
{
	char			name[MAX_AGENT_NAME];
	int			rc = -ENODATA;
	uint16_t		aid;

	if (copy_from_user(name, danipc_name_p->name, sizeof(name)))
		return -EFAULT;

	for (aid = 0; aid < MAX_AGENTS; aid++) {
		if (danipc_strncmp(name, agent_table[aid].name,
				   MAX_AGENT_NAME, MAX_AGENT_NAME_LEN)) {
			const unsigned cpuid = ipc_get_node(aid);
			const unsigned lid = ipc_lid(aid);
			struct danipc_if    *intf = netdev_priv(dev);
			struct ipc_to_virt_map *map = &ipc_to_virt_map[cpuid]
				[ipc_trns_prio_1];

			if (!map->paddr) {
				char *buf = ipc_buf_alloc(aid, ipc_trns_prio_1);

				if (buf)
					ipc_buf_free(buf, aid, ipc_trns_prio_1);
			}

			/* Mark destination agent discovered.
			 * Used in admision contol of packet.
			 */
			DANIPC_AGENT_DISCOVERED(aid, intf->drvr->dst_aid);

			if (put_user(__IPC_AGENT_ID(cpuid, lid),
				     &danipc_name_p->addr)) {
				rc = -EFAULT;
			} else {
				rc = 0;
				break;
			}
			netdev_dbg(dev, "%s: name=%s -> addr=0x%x\n", __func__,
				   agent_table[aid].name, aid);
		}
	}

	return rc;
}

int danipc_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	int rc = -EINVAL;

	if (dev && ifr && ifr->ifr_data) {
		struct danipc_if *intf = netdev_priv(dev);

		mutex_lock(&intf->lock);
		switch (cmd) {
		case DANIPC_IOCS_REGISTER:
			rc = register_agent(dev,
					    (struct danipc_reg *)ifr->ifr_data);
			break;
		case DANIPC_IOCG_ADDR2NAME:
			rc = get_name_by_addr(dev, (struct danipc_name *)
					      ifr->ifr_data);
			break;
		case DANIPC_IOCG_NAME2ADDR:
			rc = get_addr_by_name(dev, (struct danipc_name *)
					      ifr->ifr_data);
			break;
		}
		mutex_unlock(&intf->lock);
	}
	return rc;
}
