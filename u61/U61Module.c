// SPDX-License-Identifier: GPL-2.0 AND MIT
// Copyright © 2021 Dialog Semiconductor
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in 
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
// of the Software, and to permit persons to whom the Software is furnished to do
// so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/*
 ============================================================================
 Name        : U61Module.c
 Author      : dwf
 Version     :
 Description : U61 kernel module
 ============================================================================
 */
#include <linux/module.h>       /* Needed by all modules */
#include <linux/kernel.h>       /* Needed for KERN_INFO */
#include <linux/init.h>         /* Needed for the macros */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/etherdevice.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/tty.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <net/rtnetlink.h>


#include "U61Link.h"
#include "U61Osal.h"
#include "u61_priv.h"
#include "packet_util.h"
#include "ipv6_ls_to_udp.h"
#include "LtPacket.h"

// sysfs support
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fs.h>
#include <linux/string.h>

// TODO - we are still missing auto-layer switch mode,
// TODO - also "go to layer 5" API.
//
// User Space Write:
// Write to Device->netdev->lon driver->tty xmit
// Serial data rx:
// tty read->lon driver->netdev->user

//tty.h defines a number of line disciplines, with a max count of 30 -
//only up to 24 are used so just take a later one
// see #define NR_LDISCS		30
#define N_U61	27		// U-50 uses 28

#define U61_PROTO 0x8950
#define U61_DEV_TYPE 0x950
#define HEADER_SIZE 40 //40 - max size of arbitrary header + npdu


/////////////////////////////////////////////////////////////////////
// "Routing Netlink" - aka RTNL
/////////////////////////////////////////////////////////////////////


static int convert_skb_ip_to_lt(struct sk_buff *skb) {
	struct iphdr* ip = (struct iphdr*)skb->data;
	struct udphdr* udp = (struct udphdr*)&skb->data[(ip->ihl)*4];
	int len = skb->len;
	unsigned char header_buf[HEADER_SIZE];
	unsigned char msg_buf[len+HEADER_SIZE];
	unsigned char *skb_buf;

	uint32_t sourceAddr = ip->saddr;
	uint32_t destAddr = ip->daddr;
	uint16_t sourcePort = ntohs(udp->source);
	uint16_t destPort = ntohs(udp->dest);
	int udplen = ntohs(udp->len);
	int domainlen = 3;
	uint8_t domainid[3];
	int npdulen;
	int rcv_msg_hdr_size = ip->ihl * 4 + sizeof(struct udphdr);
	int totalsize = 0;

	memset(domainid, 0, 3);
	if ((destAddr & 0xff) == IPV6_DOMAIN_LEN_1_PREFIX) {
		domainlen = 1;
		domainid[0] = (destAddr >> 8) & 0xff;
	} else if (((destAddr & 0xffff) == (IPV6_DOMAIN_LEN_0_PREFIX_0 | (IPV6_DOMAIN_LEN_0_PREFIX_1 << 8))) ||
		destAddr == 0xffffffff) {
		domainlen = 0;
	} else {
		domainid[0] = destAddr & 0xff;
		domainid[1] = (destAddr & 0xff00) >> 8;
	}
	npdulen = ipv6_gen_compressed_arbitrary_udp_header((uint8_t*)&sourceAddr, sourcePort,
        (uint8_t*)&destAddr, destPort,
		domainid, domainlen,
		(uint8_t *)header_buf);
	if (npdulen == 0) {
		LDDebugError("ipv6_convert_ls_v1_to_v0 return ltV0len of 0, dropping packet.");
	} else {
		totalsize = udplen - sizeof(struct udphdr) + npdulen;
		msg_buf[0] = 0x12;
		if (totalsize + 2 > MAXLONMSGNOEX) {
			msg_buf[1] = 0xff;
			msg_buf[2] = totalsize & 0xff;
			msg_buf[3] = (totalsize >> 8) & 0xff;
			memcpy(&msg_buf[4], header_buf, npdulen);
			memcpy(&msg_buf[4+npdulen], &skb->data[rcv_msg_hdr_size], udplen - sizeof(struct udphdr));
			totalsize += 4;
		} else {
			msg_buf[1] = totalsize;
			memcpy(&msg_buf[2], header_buf, npdulen);
			memcpy(&msg_buf[2+npdulen], &skb->data[rcv_msg_hdr_size], udplen - sizeof(struct udphdr));
			totalsize += 2; //the smip command and length
		}
		if (totalsize < len) {
			skb_buf = skb_pull(skb, len - totalsize);
		} else {
			//converting to v0 should compress, not make bigger.
			return 0;
			//skb_buf = skb_push(skb, ltV0Len - len);
		}
		memcpy(skb_buf, msg_buf, totalsize);
	}
	return totalsize;
}

// N.A. apparently never used:
static int ldv_header_create (struct sk_buff *skb, struct net_device *dev,
		unsigned short type, const void *daddr, const void *saddr,
		unsigned int len) {
	//struct iphdr* ip = (struct iphdr*)skb->data;
	struct iphdr* ip = (struct iphdr*)skb_network_header(skb);// skb->data;

	//Was checking SKB protocol, but the primary intent is to use this through
    //a packet socket, which doesn't populate the protocol field that I have
    //been able to figure out. Tried using sockaddr_ll on a sendto to no avail.
	//Realistically I can't see non-ip traffic being sent? I guess the lontalk
	//stack isn't sending ip but I also hope that doesn't come through here at
	//all.
//	if (skb->protocol == htons(ETH_P_IP) && ip->protocol == IPPROTO_UDP) {
	if (type == ETH_P_IP && ip->protocol == IPPROTO_UDP) {
		convert_skb_ip_to_lt(skb);
		return 0;
	} else {
		unsigned char *skb_buf = skb_push(skb, 4);
		skb_buf[0] = 0x12;
		skb_buf[1] = len+2;
		generate_lt_header(&skb_buf[2]);
		return 4;
	}
}

static const struct header_ops ldv_header_ops = {
	.create = ldv_header_create,
};

static inline void u61_lock(struct u61_priv *priv) {
	netif_stop_queue(priv->dev);
}

static inline void u61_unlock(struct u61_priv *priv) {
	netif_wake_queue(priv->dev);
}

// Called from the uplink LLP processor - push the LDV message into the SKB
void u61_bump(struct u61_priv *priv, uint8_t *buf, int count) {
	struct net_device *dev = priv->dev;
	struct sk_buff *skb;

	// skb = dev_alloc_skb(count);
	skb = netdev_alloc_skb_ip_align(dev, count);	// see discussion of NET_IP_ALIGN in skbuff.h
	if (skb == NULL) {
		LDDebugError("%s: No memory, dropping packet", dev->name);
		dev->stats.rx_dropped++;
		return;
	}
	memcpy(skb_put(skb, count), buf, count);

	skb->dev = dev;
	skb->protocol = htons(U61_PROTO);
	dev->stats.rx_packets++;
	dev->stats.rx_bytes += count;
	netif_rx_ni(skb);
}

static int u61_dev_init(struct net_device *dev) {
	struct u61_priv *priv = netdev_priv(dev);
	U61LinkInit(&priv->state);
	// Does state->priv require initialization?
	return 0;
}

static void u61_dev_uninit(struct net_device *dev) {
}

static void flush_cancel(struct net_device *dev) {
	struct u61_priv *priv = netdev_priv(dev);
	LDV_Message *msg = (LDV_Message*)allocateMemory(sizeof(LDV_Message));
	msg->NiCmd = 0x60;
	msg->Length = 0;
	U61LinkWrite(&priv->state, msg);
	freeMemory(msg);
}

static int U61SetHWAddr(struct net_device *dev, void *dummy)
{
	struct u61_priv *priv = netdev_priv(dev);
	if (priv->tty == NULL)
		return -ENODEV;
    LDDebugInform("inside U61SetHWAddr [%d]", dev->type);
    if (priv->state.m_bHaveMAC) {
        dev->addr_len = 6;
        memcpy(dev->perm_addr, priv->state.m_mac_id, dev->addr_len);
        memcpy(dev->dev_addr, priv->state.m_mac_id, dev->addr_len);
        memset(dev->broadcast, 0xff, dev->addr_len);
        LDDebugInform("netdev perm_addr and dev_addr set!");
    }
    return 0;
}

static int u61_dev_open(struct net_device *dev) {
	struct u61_priv *priv = netdev_priv(dev);
    struct sockaddr sp;
    sp.sa_family = dev->type;
	if (priv->tty == NULL)
		return -ENODEV;
	U61LinkStart(&priv->state, U61_OPEN_LAYER2);
    dev_set_mac_address(dev, &sp, NULL);
	flush_cancel(dev);
	netif_start_queue(dev);
	return 0;
}

static int u61_dev_stop(struct net_device *dev) {
	struct u61_priv *priv = netdev_priv(dev);
	U61LinkShutdown(&priv->state);
	spin_lock_bh(&priv->lock);
	if (priv->tty)
		clear_bit(TTY_DO_WRITE_WAKEUP, &priv->tty->flags);
	netif_stop_queue(dev);
	spin_unlock_bh(&priv->lock);
	return 0;
}

// Receive a message from the network device. Send the message into the Driver.
static netdev_tx_t  u61_dev_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct u61_priv *priv = netdev_priv(dev);
	struct iphdr *ip = (struct iphdr*)skb_network_header(skb);
	struct udphdr *udp = (struct udphdr*)&skb->data[ip->ihl * 4];
	struct sk_buff *txskb = skb_copy(skb, GFP_ATOMIC);
	u61_lock(priv);
	dev->stats.tx_bytes += skb->len;
	if (skb->protocol == htons(ETH_P_IP) && ip->protocol == IPPROTO_UDP) {
		if ((udp == NULL)  || (htons(udp->dest) != IPV6_LS_UDP_PORT )) {
			if (!convert_skb_ip_to_lt(txskb)) {
				u61_unlock(priv);
				dev_kfree_skb(skb);
				dev_kfree_skb(txskb);
				LDDebugError("Failed to convert message");
				return NETDEV_TX_OK;
			}
		} else {
			uint16_t newlen;
			ipv6_convert_ls_udp_to_ltvx(0,
			    &skb->data[ip->ihl*4 + sizeof(struct udphdr)],
				ntohs(udp->len) - sizeof(struct udphdr),
				(const uint8_t*)&ip->saddr, udp->source,
				(const uint8_t*)&ip->daddr, udp->dest,
				txskb->data, &newlen, NULL);
			skb_trim(txskb, newlen);
			if (txskb->len - 2 > MAXLONMSGNOEX) {
				unsigned char *skb_buf = skb_push(txskb, 4);
				skb_buf[0] = 0x12;
				skb_buf[1] = 0xff;
				skb_buf[2] = (txskb->len-4) & 0xff;
				skb_buf[3] = ((txskb->len-4) >> 8) & 0xff;
			} else {
				unsigned char *skb_buf = skb_push(txskb, 2);
				skb_buf[0] = 0x12;
				skb_buf[1] = txskb->len-2;
			}
		}
	} else if (skb->protocol != htons(U61_PROTO)) {
		if (txskb->len - 2 > MAXLONMSGNOEX) {
			unsigned char *skb_buf = skb_push(txskb, 6);
			skb_buf[0] = 0x12;
			skb_buf[1] = 0xff;
			skb_buf[2] = (txskb->len-4) & 0xff;
			skb_buf[3] = ((txskb->len-4) >> 8) & 0xff;
			generate_lt_header(&skb_buf[4]);
		} else {
			unsigned char *skb_buf = skb_push(txskb, 4);
			skb_buf[0] = 0x12;
			skb_buf[1] = txskb->len-2;
			generate_lt_header(&skb_buf[2]);
		}
	}
	U61LinkWrite(&priv->state, (pLDV_Message)txskb->data);
	dev_kfree_skb(skb);
	dev_kfree_skb(txskb);
	return NETDEV_TX_OK;
}

static int u61_dev_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd) {
	struct u61_priv *priv = netdev_priv(dev);
	if (cmd == SIOCDEVPRIVATE) {
		memcpy(&ifr->ifr_data, priv->tty->name, strlen(priv->tty->name));
	}
	return 0;
}

static void u61_free_netdev(struct net_device *dev) {
	free_netdev(dev);
}

static const struct net_device_ops u61_netdev_ops = {
	.ndo_init = u61_dev_init,
	.ndo_uninit = u61_dev_uninit,
	.ndo_open = u61_dev_open,
	.ndo_stop = u61_dev_stop,
	.ndo_start_xmit = u61_dev_xmit,
	.ndo_do_ioctl = u61_dev_ioctl,
    .ndo_set_mac_address = U61SetHWAddr
};

static void u61_setup(struct net_device *dev) {
//	dev->header_ops = &ldv_header_ops;
	dev->netdev_ops = &u61_netdev_ops;
	dev->priv_destructor = u61_free_netdev;

	dev->type = U61_DEV_TYPE;
	dev->hard_header_len = 0;
	dev->addr_len = 0;
	dev->tx_queue_len = 100;
	dev->flags = IFF_NOARP | IFF_BROADCAST | IFF_MULTICAST;
	dev->mtu = MAXLONMSG;
}


static struct rtnl_link_ops u61_link_ops = {
	.kind = "lon",
	.priv_size = sizeof(struct u61_priv),
	.setup = u61_setup,
};

/////////////////////////////////////////////////////////////////////
// Line Discipline Fun
/////////////////////////////////////////////////////////////////////



static struct u61_priv *u61_alloc(void) {
	struct net_device *dev = NULL;
	struct u61_priv * priv;

	// Register Link Operations for Lon device
	dev = alloc_netdev(sizeof(struct u61_priv), "lon1%d", NET_NAME_USER, u61_setup);
	if (!dev) return NULL;
	priv = netdev_priv(dev);
	priv->dev = dev;
	spin_lock_init(&priv->lock);
	return priv;
}

static int u61_alloc_bufs(struct u61_priv* priv) {
	int len = 576*2;
	int err = -ENOBUFS;
	char *rbuff = NULL;
	char *xbuff = NULL;

	rbuff = kmalloc(len, GFP_KERNEL);
	if (rbuff == NULL) goto err_exit;
	xbuff = kmalloc(len, GFP_KERNEL);
	if (xbuff == NULL) goto err_exit;

	spin_lock_bh(&priv->lock);
	priv->rcount = 0;
	priv->buffsize = len;
	priv->xleft = 0;
	err = 0;
	rbuff = xchg(&priv->rbuff, rbuff);
	xbuff = xchg(&priv->xbuff, xbuff);
	spin_unlock_bh(&priv->lock);
err_exit:
//	kfree(rbuff);
//	kfree(xbuff);
	return err;
}

static int u61_ldisc_open(struct tty_struct *tty)
{
	struct u61_priv * priv;
	int err;
	rtnl_lock();
	priv = u61_alloc();
	if (!priv) {
		LDDebugError("Unable to allocate memory for u61 state");
		err = -1;
	} else {
		memset(&priv->state, 0, sizeof(priv->state));
		priv->tty = tty;
		priv->rcount = 0;
		priv->buffsize = 0;
		priv->xleft = 0;
		tty->disc_data = priv;
		err = u61_alloc_bufs(priv);
		if (err)
			LDDebugError("alloc_bufs %i", err);

		err = register_netdevice(priv->dev);
		if (err)
			LDDebugError("error registering device %i", err);
	}

	rtnl_unlock();
	tty->receive_room = 65536;
	return err;
}

static void    u61_ldisc_close(struct tty_struct *tty)
{
	struct u61_priv *priv = NULL;
	if (tty) {
        priv = tty->disc_data;
		tty->disc_data = NULL;
	}
	if (priv) {
        spin_lock_bh(&priv->lock);
		priv->tty = NULL;
        spin_unlock_bh(&priv->lock);
		if (priv->dev)
			unregister_netdev(priv->dev);
	}
}

static int u61_ldisc_ioctl(struct tty_struct *tty, struct file *file, unsigned int cmd, unsigned long arg)
{
	return 0;
}

static int u61_ldisc_hangup(struct tty_struct *tty)
{
	u61_ldisc_close(tty);
	return 0;
}

// DWF I added the spinlock - seems necessary.
static void u61_ldisc_receive_buf(struct tty_struct *tty,
		const unsigned char *cp, char *fp, int count)
{
	struct u61_priv *priv = tty->disc_data;
	if (!priv || !netif_running(priv->dev)) return;

	if (priv) {
		if (count + priv->rcount >= priv->buffsize) {
			priv->dev->stats.rx_over_errors++;
		} else {
			spin_lock_bh(&priv->lock);
			memcpy(&priv->rbuff[priv->rcount], cp, count);
			priv->rcount += count;
			spin_unlock_bh(&priv->lock);
		}
		OsalSetEvent(priv->state.m_hReadThreadNotifier);	// N.A. Is this needed? Yes.
	}
}

static void u61_ldisc_write_wakeup(struct tty_struct *tty)
{
	int actual;
	struct u61_priv *priv = tty->disc_data;

	if (priv->xleft <= 0) {
		priv->dev->stats.tx_packets++;
		clear_bit(TTY_DO_WRITE_WAKEUP, &tty->flags);
		u61_unlock(priv);
		return;
	}
	spin_lock_bh(&priv->lock);
	actual = tty->ops->write(tty, priv->xhead, priv->xleft);
	priv->xleft -= actual;
	priv->xhead += actual;
	spin_unlock_bh(&priv->lock);
}

static struct tty_ldisc_ops u61_ldisc = {
	.owner = THIS_MODULE,
	.magic = TTY_LDISC_MAGIC,
	.name = "u61",
	.open = u61_ldisc_open,
	.close = u61_ldisc_close,
	.hangup = u61_ldisc_hangup,
	.ioctl = u61_ldisc_ioctl,
	.receive_buf = u61_ldisc_receive_buf,
	.write_wakeup = u61_ldisc_write_wakeup,
};

static inline uint32_t ip_array_to_int(uint8_t* a)
{
	return a[0] | (a[1] << 8) | (a[2] << 16) | (a[3] << 24);
}

static int ldv_rcv(struct sk_buff *skb, struct net_device *dev,
    struct packet_type *pt, struct net_device *orig_dev)
{
	LtPacket* ltp = (LtPacket*)skb->data;
	uint16_t msg_len;
	struct sk_buff *ipskb;
	uint8_t header_version;
	if (ltp->len == EXT_LENGTH) {
		LtExtPacket * ltxp = (LtExtPacket*)skb->data;
		header_version = ltxp->header.version;
	} else {
		header_version = ltp->header.version;
	}

	if (header_version == 0 || header_version == 2) {
		struct udphdr *udp;
		struct iphdr *ip;
		uint8_t udpoffset;
		uint8_t headerlen;
		Ipv6UdpAppMsgHdr udp_app_hdr;
		ipskb = skb_copy(skb, GFP_ATOMIC);
		ipskb->protocol = htons(ETH_P_IP);
		ipskb->pkt_type = PACKET_MULTICAST;
		ltp = (LtPacket*)ipskb->data;
		if (ltp->len == EXT_LENGTH) {
			LtExtPacket * ltxp = (LtExtPacket*)ipskb->data;
			udpoffset = ipv6_inflate_arbitrary_udp_header((uint8_t*)&ltxp->header, &headerlen, &udp_app_hdr);
			msg_len = ltxp->ext_len - 2 - udpoffset;
			skb_pull(ipskb, udpoffset + 4);
		} else {
			udpoffset = ipv6_inflate_arbitrary_udp_header((uint8_t*)&ltp->header, &headerlen, &udp_app_hdr);
			msg_len = ltp->len - 2 - udpoffset;
			skb_pull(ipskb, udpoffset + 2);
		}
		if (headerlen == 0 || headerlen > skb->len) {
			dev_kfree_skb(ipskb);
			goto end;
		}
		skb_push(ipskb, sizeof(struct iphdr) + sizeof(struct udphdr));
		//also cut off anything that isn't the headers and the converted message
		skb_trim(ipskb, sizeof(struct iphdr) + sizeof(struct udphdr) + msg_len);
		skb_reset_network_header(ipskb);
		skb_set_transport_header(ipskb, sizeof(struct iphdr));
		ip = (struct iphdr*)skb_network_header(ipskb);
		udp = (struct udphdr*)skb_transport_header(ipskb);
		ip->version = 4;
		ip->ihl = 5;
		ip->tos = 0;
		ip->tot_len = htons(msg_len + sizeof(struct iphdr) + sizeof(struct udphdr));
		ip->id = htons(1);
		ip->frag_off = 0;
		ip->ttl = 0xff;
		ip->protocol = IPPROTO_UDP;
		ip->check = 0;
		ip->saddr = ip_array_to_int(udp_app_hdr.sourceIpAddress);
		ip->daddr = ip_array_to_int(udp_app_hdr.destIpAddress);
		udp->source = udp_app_hdr.sourcePort;//htons(source_port);
		udp->dest = udp_app_hdr.destPort;//htons(dest_port);
		udp->len = htons(msg_len + sizeof(struct udphdr));
		udp->check = 0;
		ip->check = ip_fast_csum(skb_network_header(ipskb), ip->ihl);
		netif_rx(ipskb);
	} else {
		ipskb = skb_copy(skb, GFP_ATOMIC);
		ipskb->protocol = htons(ETH_P_IP);
		ipskb->pkt_type = PACKET_MULTICAST;
		if (ltp->len == EXT_LENGTH)
			skb_pull(ipskb, 6);
		else
			skb_pull(ipskb, 4);
		skb_trim(ipskb, ipskb->len - 3);
		netif_rx(ipskb);
	}
end:
	dev_kfree_skb(skb);
	return NET_RX_SUCCESS;
}

static struct packet_type ldv_packet_type __read_mostly = {
	.type = __constant_htons(U61_PROTO),
	.func = ldv_rcv,
};

volatile uint8_t ipv6_one_len_domain_prefix = 44;
static struct kobject *obdn_file;

static ssize_t showEntry(struct kobject *kobj, struct kobj_attribute *attr, char *buf) {
    LDDebugInform("showEntry(%d)", ipv6_one_len_domain_prefix);
    return sprintf(buf, "%d\n", ipv6_one_len_domain_prefix);
}

static ssize_t storeEntry(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count) {
    int val = 0;
    sscanf(buf,"%d",&val);
    ipv6_one_len_domain_prefix = val;
    LDDebugInform("storeEntry(%d)", ipv6_one_len_domain_prefix);
    return count;
}

static struct kobj_attribute obdn_attribute =__ATTR(ltip_obd_prefix, 0664, showEntry,  storeEntry);

static int __init u61_init(void) {
	int err2, err = 0;
	// Register TTY Line Discipline - used to handle serial connection
    obdn_file = &(THIS_MODULE->mkobj.kobj);
    if(!obdn_file) {
        err = -ENOMEM;
    }
    else {
        err = rtnl_link_register(&u61_link_ops);
        dev_add_pack(&ldv_packet_type);
        err = tty_register_ldisc(N_U61, &u61_ldisc);
        
        err2 = sysfs_create_file(obdn_file, &obdn_attribute.attr);
        if (err2) {
            LDDebugInform("Failed to create the ltip_obd_prefix file in /sys/module/u61 (%d/%x)\n", err, err);
        }
    }
	return err;
}

static void __exit u61_exit(void) {
	rtnl_link_unregister(&u61_link_ops);	// got an Oops / seg fault here a few times.
	dev_remove_pack(&ldv_packet_type);
	tty_unregister_ldisc(N_U61);
    sysfs_remove_file(obdn_file, &obdn_attribute.attr);
}

module_init(u61_init);
module_exit(u61_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("dwf kb");
MODULE_ALIAS_LDISC(N_U61);
MODULE_DESCRIPTION("U60 UMIP Driver 1.1");
