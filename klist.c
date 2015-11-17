/*no longer used, this was the original list structure i had before i used KFIFO.
 *this structure is mostly untested but appeared to work.
 */

#include <linux/types.h>
#include <linux/stddef.h>
#include <linux/const.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "klist.h"

#define FALSE (1==0)
#define TRUE (1==1)
/*returns a pointer to an initalised list.*/
Klist* create_klist(){

	Klist * p_klist = kmalloc(sizeof(Klist), GFP_KERNEL);
	p_klist->p_head = NULL;
	p_klist->p_tail = NULL;

	return p_klist;
}

int contains(Klist * lst, int port,char * fileName, size_t len){
	Node * cur= lst->p_head;	
	while(cur != NULL){
		printk(KERN_INFO "port in list: '%d' port in contains '%d'\n" , cur -> port ,port );
		printk(KERN_INFO "filename in list: '%s' filename in contains '%s'\n", cur->p_msg, fileName);
		
		if(strncmp(fileName, cur->p_msg, cur->data_size) == 0 && port == cur ->port){
			return TRUE;
		}
		cur = cur->p_next;
	}
	return FALSE;
}
/*returns the total size of the messages stored in memory.*/
int m_size(Klist * lst){
	int length = 0;
	Node * cur;
	if(lst-> p_head == NULL){
		return 0;
	}
	
	cur = lst->p_head;
	while(cur != NULL){
		length = length + 1;
		cur = cur->p_next;
	}
	return length;
}

/*adds a new list node which contains the message and message length.*/
int add_message( int port, char * msg, int size, Klist * lst){
    Node * new_node = create_node(port, msg, size);
	lst->size = lst->size + size;
	
	if(m_size(lst) == 0){
		lst->p_head = new_node;
		lst->p_tail = new_node;
		return 1;
	}

	lst->p_tail->p_next = new_node;
	lst->p_tail = new_node;

	return 1;
}



/*creates a new node and stores the message in the data structure*/
Node * create_node (int port, char * msg, int size){ 
	Node * new_node = kmalloc(sizeof(Node), GFP_KERNEL);
	new_node->p_msg = kmalloc(size, GFP_KERNEL);
	strncpy(new_node->p_msg, msg, size);
	new_node->port = port;
	new_node->p_next = NULL;
	return new_node;
}





/*free the list after you have finished with it.*/
void free_klist(Klist * lst){ 
	Node * cur = lst->p_head;
	Node * tmp = NULL;
	while(cur != NULL){ 
		tmp = cur->p_next;
		kfree(cur->p_msg);
		kfree(cur);
		cur = tmp;
	}
	kfree(lst);
	return;
}

void printKlist(Klist * lst){
	Node * cur = lst->p_head;
	printk(KERN_INFO "Listing the Rules");
	
	while(cur != NULL){
		printk(KERN_INFO "Program: %s  Port: %d" , cur->p_msg, cur->port);
		cur = cur-> p_next;
	}
}


