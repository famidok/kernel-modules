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

// This structure holds the configuration settings required to register a hook into Netfilter.
static struct nf_hook_ops netfilter_ops;

/*
icmp_logger_hook(...) -> This functiın executes every single time a packet passes
through our hook point (PRE_ROUTING).

struct sk_buff *skb -> The pointer to the socket buffer containing the raw packet data.

void *priv -> It is a generic void pointer that allows you to pass custom user-defined
data or configuration context directly to your hook function when you register it.

const struct nf_hook_state *state -> state is a pointer to a structured object that
provides metadata and environmental context about the packet's current traversal
through the network stack.
*/
static unsigned int icmp_logger_hook(void *priv,
									 struct sk_buff *skb,
									 const struct nf_hook_state *state) {
	struct iphdr *iph;
	// Safety check to ensure the packet buffer exists.
	if (!skb) {
		// Tells the kernel to let the packet continue normally.
		return NF_ACCEPT;
	}

	// A helper that strips away link-layer headers and gives us a pointer pointing
	// directly to the start of the IP header inside the raw byte stream.
	iph = ip_hdr(skb);
	if (!iph) {
		return NF_ACCEPT;
	}

	// Checks the protocol byte inside the IP header.
	if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "[ICMP-LOGGER] Ping detected! Source IP: %pI4 --> Destination IP: %pI4\n",
               &iph->saddr, &iph->daddr);
	}


	return NF_ACCEPT;
}

/*
__init -> tells the compiler that this function is only used during the loading phase.
Once the module is successfully loaded, the kernel frees up the RAM occupied by __init.
*/
static int __init icmp_logger_init(void) {
	printk(KERN_INFO "[ICMP-LOGGER] Module loaded successfully.\n");


	/*
	hook -> Points to our callback function.
	pf -> Specifies the protocol family.
	hooknum -> Tells netfilter where in the packet path to intercept packets.
	priority -> Sets execution priority so our hook runs before others at this hook point.
	nf_register_net_hook(...) -> Officially registers our configuration into the kernel's
	network subsystem (&init_net).
	*/
	netfilter_ops.hook = (nf_hookfn *)icmp_logger_hook;
	netfilter_ops.pf = PF_INET;
	netfilter_ops.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops.priority = NF_IP_PRI_FIRST;

	nf_register_net_hook(&init_net, &netfilter_ops);

	return 0;
}

/*
__exit -> Marks code used exclusively when the module is being removed.
nf_unregister_net_hook(...) -> Unregisters our hook to prevent kernel crashes or dangling
pointers when the module is removed via rmmod.
*/
static void __exit icmp_logger_exit(void) {
	nf_unregister_net_hook(&init_net, &netfilter_ops);
	printk(KERN_INFO "[ICMP-LOGGER] Module unloaded successfully.\n");
}

/*
Module entry/exit registration macros, tells the linux kernel macro-expansions which
functions should be invoked when insmod / modprobe and rmmod are executed.
*/
module_init(icmp_logger_init);
module_exit(icmp_logger_exit);



