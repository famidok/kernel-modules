#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("edo");
MODULE_DESCRIPTION("A kernel module to log incoming ICMP (ping) packets");
MODULE_VERSION("1.0");

static struct nf_hook_ops netfilter_ops;

static unsigned int icmp_logger_hook(void *priv,
									 struct sk_buff *skb,
									 const struct nf_hook_state *state) {
	struct iphdr *iph;

	if (!skb) {
		return NF_ACCEPT;
	}

	iph = ip_hdr(skb);
	if (!iph) {
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "[ICMP-LOGGER] Ping detected! Source IP: %pI4 --> Destination IP: %pI4\n",
               &iph->saddr, &iph->daddr);
	}


	return NF_ACCEPT;
}

static int __init icmp_logger_init(void) {
	printk(KERN_INFO "[ICMP-LOGGER] Module loaded successfully.\n");

	netfilter_ops.hook = (nf_hookfn *)icmp_logger_hook;
	netfilter_ops.pf = PF_INET;
	netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops.priority = NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net, &netfilter_ops);

	return 0;
}

static void __exit icmp_logger_exit(void) {
	nf_unregister_net_hook(&init_net, &netfilter_ops);
	printk(KERN_INFO "[ICMP-LOGGER] Module unloaded successfully.\n");
}

module_init(icmp_logger_init);
module_exit(icmp_logger_exit);



