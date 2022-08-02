# ctty #

_ctty_ is a [controlling tty](http://en.wikipedia.org/wiki/POSIX_terminal_interface#Controlling_terminals_and_process_groups) discovery tool (and library) for [Linux](http://en.wikipedia.org/wiki/Linux).

**What is a tty?**

In Linux, users can issue commands to the operating system through a [command line](http://en.wikipedia.org/wiki/Command_line). In the modern era, a command line is implemented as a [shell](http://en.wikipedia.org/wiki/Shell_%28computing%29) attached to a [pseudo-terminal](http://linux.die.net/man/7/pty). The pseudo-terminal itself is a type of [tty](http://en.wikipedia.org/wiki/Teleprinter) and leverages the [tty driver](http://lxr.linux.no/#linux+v3.9.5/drivers/tty) section of the [Linux kernel](https://www.kernel.org/).

**What is a _controlling_ tty?**

A controlling tty is a tty that has a special relationship with a [process session](http://www.win.tue.nl/~aeb/linux/lk/lk-10.html). When a tty is "controlling" for a session, it will send the session leader, and other members of that session, [signals](http://en.wikipedia.org/wiki/Unix_signal) to help control the user experience. 

**What is a session?**

Processes are grouped into process groups for [job control](http://en.wikipedia.org/wiki/Job_control_%28Unix%29). Process groups themselves are grouped together into a session to facilitate the resource sharing of a tty. The [man page](http://en.wikipedia.org/wiki/Man_page) for [credentials](http://linux.die.net/man/7/credentials) is an excellent resource on this topic.

**What part of the operating system keeps track of all this?**

The tty driver in the kernel will know what session ID a tty is "controlling" for. Likewise, every process in a session will know which tty is "controlling" for it. There is no single authoritative point on the topic and a stable system requires the cooperation of all the players involved.

**This sounds totally crazy? How did it end up this way?**

Back in late 1960s, computers were finally fast enough to interact with users in real time. Coincidentally, the [old teletype terminals](http://en.wikipedia.org/wiki/Teleprinter) were broadly used throughout the telecommunications industry. The engineers of the day, being appropriately [lazy](http://threevirtues.com/), simply re-purposed this existing technology to fit their needs. This was the birth of the command line.

Make sure you read [The TTY demystified](http://www.linusakesson.net/programming/tty/) by [Linus Åkesson](http://www.linusakesson.net/). His page is the most enlightening for this topic anywhere on the internet. Many thanks to Linus for putting it together!

**How can you tell what the controlling tty is for any given process?**

The [ctermid](http://linux.die.net/man/3/ctermid) function will return the name of the controlling tty for the process that calls it, but this output is not particularly helpful for discovery. This function exists only to aid in portability and will always return the string "/dev/tty" regardless of which terminal or pseudo-terminal device is controlling for the process.

Further, there is no system or library call that will report the controlling tty for another process. The [stat](http://linux.die.net/man/5/proc) file for any given process will contain that information, though not in a format easily consumed by humans:

	tty_nr %d   The controlling terminal of the process.  (The minor device number is contained in
	            the combination  of  bits 31 to 20 and 7 to 0; the major device number is in bits
	            15 to 8.)

The ["ps j -p PID"](http://linux.die.net/man/1/ps) command will report the controlling tty in a human readable format for any given PID.

**How can you tell which session is controlled by any given tty?**

Traditionally, there is no easy way to see this information programmatically. (Again, examining the results of the ["ps j"](http://linux.die.net/man/1/ps) command will allow you to perform this discovery manually.) I wrote _ctty_ to fill this gap. It does the needed detective work, and reports back to the user. _libctty_ gives you a C interface to this functionality.


## _ctty_ Usage ##

	usage: ctty [-v] [TTY_NAME]
		-v	verbose reporting format

To see the session information for a particular tty:

	empty@monkey:~$ ctty /dev/pts/3
	/dev/pts/3:empty:3099:3099:3099:0,1,2,255
	/dev/pts/3:empty:3099:3158:3158:0,1,2
	/dev/pts/3:empty:3099:3158:3170:1,2
	/dev/pts/3:empty:3099:3176:3176:15,16,17,18,19
	/dev/pts/3:empty:3099:3184:3184:0,1,2,5,6,7

The format is:

	TTY_NAME:USER:SID:PGID:PID:FD1,FD2,...,FDn

The fields are:

* TTY_NAME: tty name
* USER: user name (or uid if no match in /etc/passwd)
* SID:	session ID
* PGID:	process group ID
* PID:	process ID
* FDs:	file descriptors *which this process has open to the controlling tty.*

Note:

* Running _ctty_ without any arguments will attempt to return the results for all ttys.
* The -v switch will give a different output format that is a bit easier to read, though much longer and not fit for scripting.

## _libctty_ Usage ##

This is best documented inside the source code. However, as a quick overview, _libctty.h_ defines the following interfaces:

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

## Installation ##

	git clone https://github.com/emptymonkey/ctty.git
	cd ctty
	make

