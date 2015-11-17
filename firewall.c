#include <linux/module.h>  /* Needed by all modules */
#include <linux/kernel.h>  /* Needed for KERN_ALERT */
#include <linux/netfilter.h> 
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/compiler.h>
#include <net/tcp.h>
#include "klist.h"
#include <linux/proc_fs.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/string.h>

Klist * rules;
#define FALSE (1==0)
#define TRUE (1==1)

static struct proc_dir_entry *Our_Proc_File;
/* make IP4-addresses readable */
#define PROC_ENTRY_FILENAME "firewallExtension"
#define NIPQUAD(addr) \
        ((unsigned char *)&addr)[0], \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]


struct nf_hook_ops *reg;

/*static ssize_t addRules(struct file *file,	
			    const char *buf,	
			    size_t length,
			    loff_t * offset)
{
	 char *stringp = buf;
    const char *delim = "\n";
    char *token;
 
    
    token = strsep(&buf, delim); 
    printk(KERN_INFO "token = '%s', ", token);
    if (buf == NULL)
        printk(KERN_INFO"buf == NULL\n");
    else
        printf("stringp - string = %d\n", stringp - string);
 
    // stringp is updated to point to the next token 'C'
    token = strsep(&stringp, delim); 
	char[10] LISTRULES = "L"
    ssize_t i = 0;
	if (strncmp(buf[0], LISTRULES, 1)){
		printKlist(rules);
		return i;
	}
	
	if(strncmp(buf[0], SETRULES, 1)){
		return i;
	}
    return i;
}
*/


int getProgramName(char * name, size_t size){ 
	struct path path;
    pid_t mod_pid;
    struct dentry *procDentry;
 	char cmdlineFile[256];
    int res;

	printk(KERN_INFO "*name @ start %p\n", name);

    /* current is pre-defined pointer to task structure of currently running task */
    mod_pid = current->pid;
    snprintf (cmdlineFile, 256, "/proc/%d/exe", mod_pid); 
    res = kern_path (cmdlineFile, LOOKUP_FOLLOW, &path);
    if (res) {
		return -EFAULT;
    }
	procDentry = path.dentry;

	name = d_path(&path, name, size);
	printk(KERN_INFO "*name after d_path %p\n", name);
	printk (KERN_INFO "path to binary = '%s'\n", name);
    return 0;
}


const struct file_operations File_Ops_4_Our_Proc_File = {
    .owner = THIS_MODULE,
//    .write 	 = addRules,
//    .open 	 = procfs_open,
//    .release = procfs_close,
};


unsigned int FirewallExtensionHook (const struct nf_hook_ops *ops,
				    struct sk_buff *skb,
				    const struct net_device *in,
				    const struct net_device *out,
				    int (*okfn)(struct sk_buff *)) {

	struct tcphdr *tcp;
	struct tcphdr _tcph;
	struct sock *sk;
	char *procName;

	

	sk = skb->sk;
	if (!sk) {
		printk (KERN_INFO "firewall: netfilter called with empty socket!\n");;
		return NF_ACCEPT;
  	}

	if(sk->sk_protocol != IPPROTO_TCP) {
	printk (KERN_INFO "firewall: netfilter called with non-TCP-packet.\n");
	return NF_ACCEPT;
	}

    

    /* get the tcp-header for the packet */
    tcp = skb_header_pointer(skb, ip_hdrlen(skb), sizeof(struct tcphdr), &_tcph);
    if (!tcp) {
	printk (KERN_INFO "Could not get tcp-header!\n");
	return NF_ACCEPT;
    }
    if (tcp->syn) {
	struct iphdr *ip;
	
	printk (KERN_INFO "firewall: Starting connection \n");
	ip = ip_hdr (skb);
	if (!ip) {
	    printk (KERN_INFO "firewall: Cannot get IP header!\n!");
	}
	else {
	    printk (KERN_INFO "firewall: Destination address = %u.%u.%u.%u\n", NIPQUAD(ip->daddr));
	}
	printk (KERN_INFO "firewall: destination port = %d\n", ntohs(tcp->dest)); 
		
	

	if (in_irq() || in_softirq()) {
		printk (KERN_INFO "Not in user context - retry packet\n");
		return NF_ACCEPT;
	}
	procName = kmalloc(256, GFP_KERNEL);
	printk(KERN_INFO "*procName before call %p\n", procName);
	getProgramName(procName, 256);
	printk(KERN_INFO "*procName after call %p\n", procName);
	if(contains(rules,ntohs (tcp->dest),procName,256) == TRUE){
		printk(KERN_INFO "WIN");
		printk(KERN_INFO "the proccess sending this packet is : %s\n", procName);
	    tcp_done (sk); /* terminate connection immediately */
	    printk (KERN_INFO "Connection shut down\n");
		kfree(procName);
	    return NF_DROP;
	}
	kfree(procName);
	/*if (ntohs (tcp->dest) == 80) {
		
		printk(KERN_INFO "the proccess sending this packet is : %s\n", procName);
	    tcp_done (sk); // terminate connection immediately 
	    printk (KERN_INFO "Connection shut down\n");
	    return NF_DROP;
	}*/
    }
    return NF_ACCEPT;	
}


EXPORT_SYMBOL (FirewallExtensionHook);

static struct nf_hook_ops firewallExtension_ops = {
	.hook    = FirewallExtensionHook,
	.owner   = THIS_MODULE,
	.pf      = PF_INET,
	.priority = NF_IP_PRI_FIRST,
	.hooknum = NF_INET_LOCAL_OUT
};

int init_module(void)
{
	int errno;
	char firefox[256] = "/usr/lib/firefox/firefox";
	rules = create_klist();
	add_message(443,firefox, 256, rules);

	if(contains(rules,443,firefox,256) == TRUE){
		printk(KERN_INFO "WIN");
	}
	if(rules == NULL){
		printk(KERN_INFO "was not able to create the rules list.\n");
		return -ENOMEM;
	}
	printk(KERN_INFO "rules list created\n");
	
	Our_Proc_File = proc_create_data (PROC_ENTRY_FILENAME, 0644, NULL, &File_Ops_4_Our_Proc_File, NULL);
  	errno = nf_register_hook (&firewallExtension_ops); /* register the hook */
  	if (errno) {
		printk (KERN_INFO "Firewall extension could not be registered!\n");
	} 
	else{
		printk(KERN_INFO "Firewall extensions module loaded\n");
	}

	// A non 0 return means init_module failed; module can't be loaded.
	return errno;
}


void cleanup_module(void)
{
	free_klist(rules);
	remove_proc_entry(PROC_ENTRY_FILENAME, NULL);
	nf_unregister_hook (&firewallExtension_ops); /* restore everything to normal */
	printk(KERN_INFO "Firewall extensions module unloaded\n");
}



MODULE_AUTHOR ("Paul Dines <pjd201@student.bham.ac.uk>");
MODULE_DESCRIPTION ("Extensions to the firewall") ;
MODULE_LICENSE("GPL"); 
