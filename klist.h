#ifndef _LINKED_LIST_H
#define _LINKED_LIST_H

typedef struct Node {
	int data_size;
	char * p_msg;
	int port;
	struct Node *p_next;
} Node;

// Defines a list by its head and tail, to save carting about two
// pointers.
typedef struct Klist {
	size_t size;
	Node *p_head;
	Node *p_tail;
} Klist;



//prints the list to the kernel output
void printKlist(Klist * lst);

//sets all the rules in a list based on the string of <port> <program>
int setRules(char * tmprules, Klist * lst);

//returns a pointer to an initalised list.
Klist* create_klist(void);

//adds a new list node which contains the message and message length.
int add_message( int port, char * msg, int size, Klist * lst);

//returns the total size of the messages stored in memory.
int m_size(Klist * lst);

//frees all the nodes in the list and then frees the list;
void free_klist(Klist * lst);

//mallocs the size for a new node.
Node * create_node (int port, char * msg, int size);

//contains returns whether the list supplied contains the string.
int contains(Klist * lst, int port,char * fileName, size_t len);

//returns true of the port is mentioned at any point in the list
int containsPort(Klist * lst, int port);




#endif
