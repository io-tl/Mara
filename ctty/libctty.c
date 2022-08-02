
/************************************************************************
 *	libctty : 2013-03-20
 *
 *		emptymonkey's library for discovery of controlling ttys and their 
 *		associated sessions.
 *
 *	For an example usage, check the ctty.c code in this same package.
 *
 ************************************************************************/

#include "libctty.h"


void clean_pids(struct pid_node *head);
void clean_pgids(struct pgid_node *head);


// "/dev/pts/" -> 9 + KERN_PIDMAX
#define MAX_PATH_LEN KERN_PIDMAX + 19


/************************************************************************
 *
 * ctty_get_name()
 *
 * Inputs:
 *		The process id.
 *
 * Outputs:
 *		The name of the controlling tty.
 *
 ************************************************************************/
char *ctty_get_name(int pid){
	int retval;
	int i;

	char *name = NULL;
	char path[MAX_PATH_LEN + 1];
	char scratch[MAX_PATH_LEN + 1];

	DIR *dev_dir = NULL;
	struct dirent *dir_entry;

	struct stat dev_info;
	struct proc_stat stat_info;


	if((retval = ctty_stat_parse(pid, &stat_info)) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_name(): ctty_stat_parse(%d, %lx): %s\n", program_invocation_short_name, \
				pid, (unsigned long) &stat_info, \
				strerror(errno));
#endif
		goto CLEAN_UP;
	}

	for(i = 0; i < 2; i++){
		memset(path, 0, sizeof(path));
		if(snprintf(path, sizeof(path), "/dev/") < 0){
			return(NULL);
		}

		if(i){
			if(snprintf(path + 5, sizeof(path) - 5, "pts/") < 0){
				return(NULL);
			}
		}

		if(!(dev_dir = opendir(path))){
#ifdef DEBUG
			fprintf(stderr, "%s: ctty_get_name(): opendir(%s): %s\n", program_invocation_short_name, \
					path, \
					strerror(errno));
#endif
			return(NULL);
		}

		while((dir_entry = readdir(dev_dir))){

			if(!i){
				if(strncmp(dir_entry->d_name, "tty", 3)){
					continue;
				}
			}

			memset(scratch, 0, sizeof(scratch));
			if(snprintf(scratch, sizeof(scratch), "%s%s", path, dir_entry->d_name) < 0){
				goto CLEAN_UP;
			}

			if(stat(scratch, &dev_info)){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_name(): stat(%s, %lx): %s\n", program_invocation_short_name, \
						scratch, (unsigned long) &dev_info, \
						strerror(errno));
#endif
				goto CLEAN_UP;
			}

			if(stat_info.tty_nr == (int) dev_info.st_rdev){
				if((name = (char *) malloc(strlen(scratch) + 1)) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: ctty_get_name(): malloc(%d): %s\n", program_invocation_short_name, \
							(int) strlen(scratch) + 1, \
							strerror(errno));
#endif
					goto CLEAN_UP;
				}
				memset(name, 0, strlen(scratch) + 1);
				strncpy(name, scratch, MAX_PATH_LEN);
				goto CLEAN_UP;
			}
		}

		closedir(dev_dir);
	}

CLEAN_UP:
	closedir(dev_dir);
	return(name);
}


/************************************************************************
 * ctty_get_session()
 *
 * Inputs:
 *		The name of a tty.
 *
 * Outputs:
 *		A session, as represented by a pointer to a populated sid_node.
 *
 ************************************************************************/
struct sid_node *ctty_get_session(char *tty_name){
	int i, retval;
	int ctty_nr;
	int pid;

	uid_t ctty_uid;

	struct stat stat_buf;
	struct proc_stat tmp_stat_info;
	struct pid_node *tmp_pid_ptr, *new_pid_ptr, *head_pid_ptr = NULL, *tail_pid_ptr = NULL, *leader_pid_ptr = NULL;
	struct pgid_node *tmp_pgid_ptr, *new_pgid_ptr, *tail_pgid_ptr = NULL, *leader_pgid_ptr = NULL;
	struct sid_node	*tmp_sid_ptr;

	glob_t pglob;

	/*
	 * Grab information about the tty.
	 *
	 */
	if((retval = stat(tty_name, &stat_buf)) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_session(): stat(%s, %lx): %s\n", program_invocation_short_name, \
				tty_name, (unsigned long) &stat_buf, \
				strerror(errno));
#endif
		return(NULL);
	}

	ctty_nr = stat_buf.st_rdev;
	ctty_uid = (int) stat_buf.st_uid;

	/*
	 * Find all the relevant stat files. Ignore any that don't share the uid of the tty.
	 * We are only interested in processes for which tty_name is a controlling tty.
	 */
	if((retval = glob("/proc/[0-9]*/stat", 0, NULL, &pglob))){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_session(): glob(%s, %d, %p, %lx): retval == %d\n", program_invocation_short_name, \
				"/proc/[0-9]*/stat", 0, NULL, (unsigned long) &pglob, \
				retval);
#endif
		return(NULL);
	}

	for(i = 0; i < (int) pglob.gl_pathc; i++){
		if((retval = stat(pglob.gl_pathv[i], &stat_buf)) == -1){
#ifdef DEBUG
			fprintf(stderr, "%s: ctty_get_session(): stat(%s, %lx): %s\n", program_invocation_short_name, \
					pglob.gl_pathv[i], (unsigned long) &stat_buf, \
					strerror(errno));
#endif
			globfree(&pglob);
			return(NULL);
		}

			if((pid = (int) strtol((pglob.gl_pathv[i]) + 6, NULL, 10)) == 0){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_session(): strtol(%lx, %p, %d): %s\n", program_invocation_short_name, \
						(unsigned long) (pglob.gl_pathv[i]) + 6, NULL, 10, \
						strerror(errno));
#endif
				globfree(&pglob);
				return(NULL);
			}

			if((retval = ctty_stat_parse(pid, &tmp_stat_info)) == -1){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_session(): ctty_stat_parse(%d, %lx): %s\n", program_invocation_short_name, \
						pid, (unsigned long) &tmp_stat_info, \
						strerror(errno));
#endif
				globfree(&pglob);
				return(NULL);
			}	

			if(ctty_nr == tmp_stat_info.tty_nr){

				/*
				 * We've got a match, so lets build a pid_node to represent this process.
				 *
				 */
				if((new_pid_ptr = (struct pid_node *) malloc(sizeof(struct pid_node))) == NULL){
#ifdef DEBUG
					fprintf(stderr, "%s: ctty_get_session(): malloc(%d): %s\n", program_invocation_short_name, \
							(int) sizeof(struct pid_node), \
							strerror(errno));
#endif
					globfree(&pglob);
					return(NULL);
				}	
				memset(new_pid_ptr, 0, sizeof(struct pid_node));

				new_pid_ptr->pid = tmp_stat_info.pid;
				new_pid_ptr->pgid = tmp_stat_info.pgrp;
				new_pid_ptr->sid = tmp_stat_info.session;

				if((new_pid_ptr->fd_count = ctty_get_fds(new_pid_ptr->pid, tty_name, &new_pid_ptr->fds)) == -1){
#ifdef DEBUG
					fprintf(stderr, "%s: ctty_get_session(): ctty_get_fds(%d, %s, %lx): %s\n", program_invocation_short_name, \
							new_pid_ptr->pid, tty_name, (unsigned long) &new_pid_ptr->fds, \
							strerror(errno));
#endif
					globfree(&pglob);
					clean_pids(new_pid_ptr);
					clean_pids(head_pid_ptr);
					return(NULL);
				}

				/*
				 * Add the pid_node to a linked list of pid_nodes. Let's make sure it's sorted numerically.
				 * Also, note that we want the head of the list to point to the session leader. Keep in 
				 * mind that when you hit pid_max (~32k) you run out of pids and start over at the 
				 * beginning. As such, the lowest number is not necessarily the session leader.
				 *
				 */
				if(new_pid_ptr->sid == new_pid_ptr->pid){
					leader_pid_ptr = new_pid_ptr;
				}

				if(!head_pid_ptr){
					head_pid_ptr = new_pid_ptr;
					tail_pid_ptr = new_pid_ptr;
				}else{

					if(tail_pid_ptr->pid < new_pid_ptr->pid){
						tail_pid_ptr->next = new_pid_ptr;
						tail_pid_ptr = new_pid_ptr;

					}else if(head_pid_ptr->pid > new_pid_ptr->pid){
						new_pid_ptr->next = head_pid_ptr;
						head_pid_ptr = new_pid_ptr;

					}else{
						tmp_pid_ptr = head_pid_ptr;
						while(tmp_pid_ptr){
							if((tmp_pid_ptr->pid < new_pid_ptr->pid) && \
									(tmp_pid_ptr->next->pid > new_pid_ptr->pid)){
								new_pid_ptr->next = tmp_pid_ptr->next;
								tmp_pid_ptr->next = new_pid_ptr;
							}
							tmp_pid_ptr = tmp_pid_ptr->next;
						}
					}
				}
			}
	}
	globfree(&pglob);

	/*
	 * Return immediately if this tty isn't controlling for any sessions.
	 *
	 */
	if(!head_pid_ptr){
		errno = 0;
		return(NULL);
	}

	if(leader_pid_ptr != head_pid_ptr){

		tmp_pid_ptr = head_pid_ptr;
		while(tmp_pid_ptr){
			if(tmp_pid_ptr->next == leader_pid_ptr){
				break;
			}	
			tmp_pid_ptr = tmp_pid_ptr->next;
		}
		tail_pid_ptr->next = head_pid_ptr;
		tmp_pid_ptr->next = NULL;
		head_pid_ptr = leader_pid_ptr;
		tail_pid_ptr = tmp_pid_ptr;
	}

	/*
	 * Time to set up the session itself, and at least one group too.
	 *
	 */
	if((tmp_sid_ptr = (struct sid_node *) malloc(sizeof(struct sid_node))) == NULL){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_session(): malloc(%d): %s\n", program_invocation_short_name, \
				(int) sizeof(struct sid_node), \
				strerror(errno));
#endif
		clean_pids(head_pid_ptr);
		return(NULL);
	}
	memset(tmp_sid_ptr, 0, sizeof(struct sid_node));

	tmp_sid_ptr->sid = head_pid_ptr->pid;
	tmp_sid_ptr->uid = ctty_uid;

	retval = strlen(tty_name);
	if((tmp_sid_ptr->ctty = (char *) malloc(retval + 1)) == NULL){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_session(): malloc(%d): %s\n", program_invocation_short_name, \
				retval + 1, \
				strerror(errno));
#endif
		clean_pids(head_pid_ptr);
		ctty_free_session(tmp_sid_ptr);
		return(NULL);
	}
	memcpy(tmp_sid_ptr->ctty, tty_name, retval + 1);

	/*
	 * Here, we have the linked list of all pid_nodes for this session pointed to by head_pid_ptr.
	 * We will remove one node at a time from the old list and move it into a new list on a pgid
	 * by pgid basis. (Each pass of the loop will remove all pids that match the pgid.) 
	 *
	 * We will want to reuse the pid_node pointers from above. Here, they break down as such:
	 *	head_pid_ptr : head of the old list.
	 *	tmp_pid_ptr : the current node being examined in the old list.
	 *	new_pid_ptr : the node right before tmp_pid_ptr.
	 *
	 *	new_pgid_ptr->pid_head : head of the new list.
	 *	tail_pid_ptr : the last element of the new list.
	 *
	 */
	while(head_pid_ptr){

		if((new_pgid_ptr = (struct pgid_node *) malloc(sizeof(struct pgid_node))) == NULL){
#ifdef DEBUG
			fprintf(stderr, "%s: ctty_get_session(): malloc(%d): %s\n", program_invocation_short_name, \
					(int) sizeof(struct pgid_node), \
					strerror(errno));
#endif
			clean_pids(head_pid_ptr);
			ctty_free_session(tmp_sid_ptr);
			return(NULL);
		}
		memset(new_pgid_ptr, 0, sizeof(struct pgid_node));

		if(tmp_sid_ptr->sid == head_pid_ptr->pgid){
			leader_pgid_ptr = new_pgid_ptr;
		}
		if(head_pid_ptr->pid == head_pid_ptr->pgid){
			leader_pid_ptr = head_pid_ptr;
		}

		new_pgid_ptr->pgid = head_pid_ptr->pgid;	

		new_pgid_ptr->pid_head = head_pid_ptr;
		head_pid_ptr = head_pid_ptr->next;
		new_pgid_ptr->pid_head->next = NULL;
		tail_pid_ptr = new_pgid_ptr->pid_head;

		tmp_pid_ptr = head_pid_ptr;
		new_pid_ptr = NULL;
		leader_pid_ptr = NULL;
		while(tmp_pid_ptr){
			if(tmp_pid_ptr->pgid == new_pgid_ptr->pgid){

				if(tmp_pid_ptr->pid == new_pgid_ptr->pgid){
					leader_pid_ptr = tmp_pid_ptr;
				}

				if(!new_pid_ptr){
					head_pid_ptr = tmp_pid_ptr->next;
				}else{
					new_pid_ptr->next = tmp_pid_ptr->next;
				}
				tmp_pid_ptr->next = NULL;
				tail_pid_ptr->next = tmp_pid_ptr;
				tail_pid_ptr = tmp_pid_ptr;
				tmp_pid_ptr = head_pid_ptr;
			}else{
				new_pid_ptr = tmp_pid_ptr;
				tmp_pid_ptr = tmp_pid_ptr->next;
			}
		}

		if(leader_pid_ptr && (leader_pid_ptr != new_pgid_ptr->pid_head)){
			tmp_pid_ptr = new_pgid_ptr->pid_head;
			while(tmp_pid_ptr){
				if(tmp_pid_ptr->next == leader_pid_ptr){
					break;
				}
				tmp_pid_ptr = tmp_pid_ptr->next;
			}

			tail_pid_ptr->next = new_pgid_ptr->pid_head;
			tmp_pid_ptr->next = NULL;
			new_pgid_ptr->pid_head = leader_pid_ptr;
		}

		/*
		 * Now insert the pgid_node into the session.
		 *
		 */
		if(!tmp_sid_ptr->pgid_head){
			tmp_sid_ptr->pgid_head = new_pgid_ptr;	
			tail_pgid_ptr = new_pgid_ptr;
		}else{

			if(new_pgid_ptr->pgid > tail_pgid_ptr->pgid){
				tail_pgid_ptr->next = new_pgid_ptr;
				tail_pgid_ptr = new_pgid_ptr;

			}else if(new_pgid_ptr->pgid < tmp_sid_ptr->pgid_head->pgid){
				new_pgid_ptr->next = tmp_sid_ptr->pgid_head;
				tmp_sid_ptr->pgid_head = new_pgid_ptr;

			}else{
				tmp_pgid_ptr = tmp_sid_ptr->pgid_head;
				while(tmp_pgid_ptr){
					if((tmp_pgid_ptr->pgid < new_pgid_ptr->pgid) && \
							(tmp_pgid_ptr->next->pgid > new_pgid_ptr->pgid)){
						new_pgid_ptr->next = tmp_pgid_ptr->next;
						tmp_pgid_ptr->next = new_pgid_ptr;
					}
					tmp_pgid_ptr = tmp_pgid_ptr->next;
				}
			}
		}	
	}

	/*
	 * We also have to try to point to the pgid leader (if it exists)
	 * and deal with the same pid_max wrap around condition.
	 *
	 */
	if(leader_pgid_ptr != tmp_sid_ptr->pgid_head){
		tmp_pgid_ptr = tmp_sid_ptr->pgid_head;
		while(tmp_pgid_ptr){
			if(tmp_pgid_ptr->next == leader_pgid_ptr){
				break;
			}
			tmp_pgid_ptr = tmp_pgid_ptr->next;
		}
		tail_pgid_ptr->next = tmp_sid_ptr->pgid_head;
		tmp_pgid_ptr->next = NULL;
		tmp_sid_ptr->pgid_head = leader_pgid_ptr;
	}

	/*
	 * All done!
	 *
	 */
	return(tmp_sid_ptr);
}


/************************************************************************
 *
 * ctty_stat_parse()
 *
 * Inputs: 
 *		The name of the /proc/PID/stat file you want to parse.
 *		A pointer to the stat_info struct where you want us to put the data.
 *
 * Outputs:
 *		An error code. (Hopefully zero, if all is well.)
 *
 ************************************************************************/
int ctty_stat_parse(int pid, struct proc_stat *stat_info){
	int stat_fd;

	char scratch[BUFF_LEN];
	char *parse_ptr;

	memset(scratch, 0, BUFF_LEN);
	snprintf(scratch, BUFF_LEN, "/proc/%d/stat", pid);

	if((stat_fd = open(scratch, O_RDONLY)) == -1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): open(%s, %d): %s\n", program_invocation_short_name, \
				scratch, O_RDONLY, \
				strerror(errno));
#endif
		return(-1);
	}

	if((read(stat_fd, scratch, sizeof(scratch))) < 1){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): read(%d, %lx, %d): %s\n", program_invocation_short_name, \
				stat_fd, (unsigned long) scratch, (int) sizeof(scratch), \
				strerror(errno));
#endif
		return(-1);
	}
	close(stat_fd);

	stat_info->pid = strtol(scratch, NULL, 10);

	if((parse_ptr = strrchr(scratch, ')')) == NULL){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_stat_parse(): strrchr(%lx, %d): %s\n", program_invocation_short_name, \
				(unsigned long) scratch, ')', \
				strerror(errno));
#endif
		return(-1);
	}

	/* ppid starts 4 chars after the final ')'. */
	parse_ptr += 4;
	stat_info->ppid = strtol(parse_ptr, &parse_ptr, 10);
	stat_info->pgrp = strtol(parse_ptr, &parse_ptr, 10);
	stat_info->session = strtol(parse_ptr, &parse_ptr, 10);
	stat_info->tty_nr = strtol(parse_ptr, NULL, 10);

	return(0);
}


/************************************************************************
 *
 * ctty_get_fds()
 *
 * Inputs:
 *		The pid of the process we are interested in.
 *		The name of the tty we are interested in.
 *		A pointer to the array where we will put matching file descriptors. 
 *		(File descriptors "match" if they are pointing to the tty mentioned above.)
 *
 * Outputs:
 *		The total count of file descriptors being returned in the array.
 *
 ************************************************************************/
int ctty_get_fds(int pid, char *tty, int **fds){
	char path[MAX_PATH_LEN + 1];
	char scratch[MAX_PATH_LEN + 1];
	DIR *proc_pid_fd;
	struct dirent *dir_entry;
	int count, i;

	memset(path, 0, sizeof(path));
	if(snprintf(path, sizeof(path), "/proc/%d/fd/", pid) < 0){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_fds(): snprintf(%lx, %d, %s, %d): %s\n", program_invocation_short_name, \
				(unsigned long) path, (int) sizeof(path), "/proc/%%d/fd/", pid, \
				strerror(errno));
#endif
		return(-1);
	}
	
	if(!(proc_pid_fd = opendir(path))){
#ifdef DEBUG
		fprintf(stderr, "%s: ctty_get_fds(): opendir(%s): %s\n", program_invocation_short_name, \
				path, \
				strerror(errno));
#endif
		return(-1);
	}

	count = 0;
	for(i = 0; i < 2; i++){
		while((dir_entry = readdir(proc_pid_fd))){

			if(!(strcmp(dir_entry->d_name, ".") && strcmp(dir_entry->d_name, ".."))){
				continue;
			}

			memset(scratch, 0, sizeof(scratch));
			if(snprintf(scratch, sizeof(scratch), "/proc/%d/fd/%s", pid, dir_entry->d_name) < 0){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_fds(): snprintf(%lx, %d, %s, %d, %s): %s\n", program_invocation_short_name, \
						(unsigned long) scratch, (int) sizeof(scratch), "/proc/%%d/fd/", pid, dir_entry->d_name, \
						strerror(errno));
#endif
				count = -1;
				goto CLEAN_UP;
			}

			memset(path, 0, sizeof(path));
			if(readlink(scratch, path, sizeof(path) - 1) == -1){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_fds(): readlink(%lx, %s, %d): %s\n", program_invocation_short_name, \
						(unsigned long) scratch, path, (int) sizeof(path) - 1, \
						strerror(errno));
#endif
				count = -1;
				goto CLEAN_UP;
			}

			if(!strncmp(path, tty, sizeof(path))){
				if(i){
					(*fds)[count] = (int) strtol(dir_entry->d_name, NULL, 10);
				}
				count++;
			}
		}

		if(!i){
			rewinddir(proc_pid_fd);
			if(((*fds = (int *) malloc(count * sizeof(int))) == 0) && count){
#ifdef DEBUG
				fprintf(stderr, "%s: ctty_get_fds(): malloc(%d): %s\n", program_invocation_short_name, \
						count * (int) sizeof(int), \
						strerror(errno));
#endif
				count = -1;
				goto CLEAN_UP;
			}
			memset(*fds, 0, count * sizeof(int));
			count = 0;
		}
	}

CLEAN_UP:
	closedir(proc_pid_fd);
	return(count);
}


/************************************************************************
 *
 * ctty_free_session()
 *
 * Inputs:
 *		A pointer to the session object you no longer need.
 *
 * Outputs:
 *		None.
 *
 ************************************************************************/
void ctty_free_session(struct sid_node *head){
	struct sid_node *tmp;

	while(head){	
		tmp = head;
		head = head->next;

		clean_pgids(tmp->pgid_head);
		free(tmp->ctty);
		free(tmp);
	}
}


// Just some helpful cleaning functions after this.

void clean_pgids(struct pgid_node *head){
	struct pgid_node *tmp;

	while(head){	
		tmp = head;
		head = head->next;

		clean_pids(tmp->pid_head);
		free(tmp);
	}
}

void clean_pids(struct pid_node *head){
	struct pid_node *tmp;

	while(head){	
		tmp = head;
		head = head->next;

		free(tmp->fds);
		free(tmp);
	}
}
