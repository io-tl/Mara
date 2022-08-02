
/**********************************************************************
 *
 *	ctty : 2013-03-20
 *
 *	emptymonkey's tool for mapping sessions by their controlling tty.
 *              
 *
 *	Example use:
 *		empty@monkey:~$ ctty /dev/pts/3
 *		/dev/pts/3:empty:3099:3099:3099:0,1,2,255
 *		/dev/pts/3:empty:3099:3158:3158:0,1,2
 *		/dev/pts/3:empty:3099:3158:3170:1,2
 *		/dev/pts/3:empty:3099:3176:3176:15,16,17,18,19
 *		/dev/pts/3:empty:3099:3184:3184:0,1,2,5,6,7
 *
 *	The output format is:
 *		TTY:USER:SID:PGID:PID:FD0,FD1,...,FDn
 *
 *	Notes:
 *		* Only the file descriptors that are pointing to the ctty are listed.
 *
 *		* If you run ctty without any arguments, it will attempt to return
 *			the results for all ttys. (This will probably fail for most ttys
 *			unless you are root.)
 *
 *		* The -v switch will give a different output format that is a bit
 *			easier to read, though much longer and not fit for scripting.
 *
 **********************************************************************/


#include "libctty.h"

#include <pwd.h>


void usage();
void ctty_print_session(struct sid_node *session_list, int verbose);


#define MAX_INT_LEN 10


void usage(){
	fprintf(stderr, "usage: %s [-v] [TTY_NAME]\n", program_invocation_short_name);
	fprintf(stderr, "\t-v\tverbose reporting format\n");
	exit(-1);
}


int main(int argc, char **argv){
	int i, retval;
	struct sid_node *session_head = NULL, *session_tail = NULL, *session_tmp;	
	glob_t pglob;
	int opt, verbose = 0;

	while ((opt = getopt(argc, argv, "v")) != -1) {
		switch (opt) {
			case 'v':
				verbose = 1;
				break;
			
			default: 
				usage();
		}
	}

	if((argc - optind) > 1){
		usage();
	}

	if((argc - optind) == 1){	
		if((session_head = ctty_get_session(argv[optind])) == NULL){
			error(-1, errno, "ctty_get_session(%s)", argv[optind]);
		}
	}else{
		if((retval = glob("/dev/tty*", 0, NULL, &pglob))){
			error(-1, errno, "glob(%s, %d, %p, %lx)", \
					"/dev/tty*", 0, NULL, (unsigned long) &pglob);
		}

		if((retval = glob("/dev/pts/[0-9]*", GLOB_APPEND, NULL, &pglob))){
			error(-1, errno, "glob(%s, %d, %p, %lx)", \
					"/dev/pts/[0-9]*", 0, NULL, (unsigned long) &pglob);
		}
		for(i = 0; i < (int) pglob.gl_pathc; i++){
			errno = 0;
			if(((session_tmp = ctty_get_session(pglob.gl_pathv[i])) == NULL) && (errno)){
				fprintf(stderr, "ctty_get_session(%s): %s\n", pglob.gl_pathv[i], strerror(errno));
			}else if(session_tmp){

				if(!session_head){
					session_head = session_tmp;
					session_tail = session_tmp;
				}else{
					session_tail->next = session_tmp;
					session_tail = session_tmp;
				}
			}
		}
		globfree(&pglob);
	}
	
	ctty_print_session(session_head, verbose);

	return(0);
}


void ctty_print_session(struct sid_node *session_list, int verbose){
	int i;

	struct sid_node *session;
	struct pgid_node *pgroup;
	struct pid_node *proc;

	struct passwd *user;

	session = session_list;
	while(session){

		errno = 0;	
		user = getpwuid(session->uid);
		if(errno){
			error(-1, errno, "getpwuid(%d)", session->uid);
			continue;
		}

	
		if(verbose){
			printf("--------------------------------\n");
			printf("TTY: %s\n", session->ctty);

			if(user){
				printf("USER: %s\n\n", user->pw_name);
			}else{
				printf("USER: No such user: %d\n\n", session->uid);
			}

			printf("SID\tPGID\tPID\tFDs\n");
			printf("---\t----\t---\t---\n");

			printf("%d\n", session->sid);
		}

		pgroup = session->pgid_head;
		while(pgroup){
			if(verbose){
				printf("\t%d\n", pgroup->pgid);
			}

			proc = pgroup->pid_head;
			while(proc){

				if(verbose){
					printf("\t\t%d\n", proc->pid);
					for(i = 0; i < proc->fd_count; i++){
						printf("\t\t\t%d\n", proc->fds[i]);
					}
				}else{
					if(user){
						printf("%s:%s:%d:%d:%d:", session->ctty, user->pw_name, session->sid, pgroup->pgid, proc->pid);
					}else{
						printf("%s:%d:%d:%d:%d:", session->ctty, session->uid, session->sid, pgroup->pgid, proc->pid);
					}

					for(i = 0; i < proc->fd_count; i++){
						if(!i){
							printf("%d", proc->fds[i]);
						}else{
							printf(",%d", proc->fds[i]);
						}
					}
					printf("\n");
				}
				proc = proc->next;
			}
			pgroup = pgroup->next;
		}
		session = session->next;
	}

	if(verbose){
		printf("--------------------------------\n");
	}
}
