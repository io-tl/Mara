#undef DEBUG

#define _GNU_SOURCE


#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/sysctl.h>

#include <sys/stat.h>
#include <sys/types.h>


#define BUFF_LEN 1024

/*
 * A sid_node represents one session.
 *
 * "man 7 credentials" for details on sessions.
 *
 */
struct sid_node{
	pid_t sid;
	uid_t uid;
	char *ctty;

	struct pgid_node *pgid_head;

	struct sid_node *next;
};


/*
 * A pgid_node represents one process group.
 * Note that unlike a session leader where sid == pgid == pid,
 * a pgid leader may not exist. (E.g. first command in a pipeline
 * after it finishes. The remaining pipeline processes will have
 * the parents pgid, though the parent has exited already.)
 *
 */
struct pgid_node{
	pid_t pgid;

	struct pid_node *pid_head;

	struct pgid_node *next;	
};


/*
 * A pid_node represents the process itself.
 *
 */
struct pid_node{
	pid_t ppid;
	pid_t pid;
	pid_t pgid;
	pid_t sid;

	int fd_count;	
	int *fds;

	struct pid_node *next;
};


/*
 * Used when parsing the /proc/PID/stat file.
 *
 */
struct proc_stat{
	pid_t ppid;
	pid_t pid;
	pid_t pgrp;
	pid_t session;
	int tty_nr;
};


/* ctty_get_name() is used to discover the controlling tty for a process. */
char *ctty_get_name(int pid);

/* ctty_get_session() is used to map out the entire process session. */
struct sid_node *ctty_get_session(char *tty_name);

/* ctty_free_session() is used to release the session data structure. */
void ctty_free_session(struct sid_node *session);

/* ctty_stat_parse() will pull ctty and session related info from the processes stat file. */
int ctty_stat_parse(int pid, struct proc_stat *stat_info);

/* ctty_get_fds() returns the list of file descriptors open to the tty you're interested in. */
int ctty_get_fds(int pid, char *tty, int **fds);
