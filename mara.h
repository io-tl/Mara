#include <linux/netlink.h>
#include <linux/connector.h>
#include <linux/cn_proc.h>
#include <sys/socket.h>


// main

void jack(pid_t pid, char *exe, char *pty, char *stdin, char *user);
void nl_listen();
int handle(struct proc_event proc_ev);

// log.c

void hd(const void* data, size_t size);

#ifdef PROD
#define TRACE   (void)sizeof
void trace(const char* format, ...);
#else
#define TRACE( fmt , args... ) trace("\033[1;36m%-18s\033[0;33m%-18s\033[0;32m#%d  \t\033[0m" fmt , __FILE__ , __FUNCTION__ , __LINE__ , ##args );
void trace(const char* format, ...);
#endif

// shelljack.c
int shelljack(int target_pid,char *filename);