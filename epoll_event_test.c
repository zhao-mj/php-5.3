#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <sys/epoll.h>
#include <errno.h>
#define FPM_EV_READ     (1 << 1)
#define FPM_EV_PERSIST  (1 << 2)
#define FPM_EV_EDGE     (1 << 3)

enum {
    FPM_PCTL_STATE_UNSPECIFIED,
    FPM_PCTL_STATE_NORMAL,
    FPM_PCTL_STATE_RELOADING,
    FPM_PCTL_STATE_TERMINATING,
    FPM_PCTL_STATE_FINISHING
};
enum {
    FPM_PCTL_ACTION_SET,
    FPM_PCTL_ACTION_TIMEOUT,
    FPM_PCTL_ACTION_LAST_CHILD_EXITED
};

enum {
    FPM_PCTL_TERM,
    FPM_PCTL_STOP,
    FPM_PCTL_CONT,
    FPM_PCTL_QUIT
};

struct epoll_event *epollfds = NULL;
int nepollfds = 0;
int epollfd = 0;
static int sp[2];

static int fpm_state = FPM_PCTL_STATE_NORMAL;
static int fpm_signal_sent = 0;

static const char *fpm_state_names[] = {
    [FPM_PCTL_STATE_NORMAL] = "normal",
    [FPM_PCTL_STATE_RELOADING] = "reloading",
    [FPM_PCTL_STATE_TERMINATING] = "terminating",
    [FPM_PCTL_STATE_FINISHING] = "finishing"
};

struct fpm_event_s {
    int fd;                   /* not set with FPM_EV_TIMEOUT */
    struct timeval timeout;   /* next time to trigger */
    struct timeval frequency;
    void (*callback)(struct fpm_event_s *, short, void *);
    void *arg;
    int flags;
    int index;                /* index of the fd in the ufds array */
    short which;              /* type of event */
};

void fpm_event_fire(struct fpm_event_s *ev);
int fpm_event_set(struct fpm_event_s *ev, int fd, int flags, void (*callback)(struct fpm_event_s *, short, void *), void *arg);
int fpm_event_add(struct fpm_event_s *ev, unsigned long int frequency);


//****************epoll事件*******************//
//epoll初始化
static int epoll_init(int max){
   epollfd = epoll_create(max + 1);
   epollfds = malloc(sizeof(struct epoll_event) * max);
   if (!epollfds) {
      printf("malloc epoll error\n");
      return -1;
   }    
   memset(epollfds, 0, sizeof(struct epoll_event) * max);
   nepollfds = max;
   return 0;
}

//epoll等待事件
static int fpm_event_epoll_wait(unsigned long int timeout)
{
    int ret, i;
    /* ensure we have a clean epoolfds before calling epoll_wait() */
    memset(epollfds, 0, sizeof(struct epoll_event) * nepollfds);
    /* wait for inconming event or timeout */
    //timeout = 0 表示立刻返回
    //timeout = -1 标识一直等待
    //timeout>0 超时时间
    ret = epoll_wait(epollfd, epollfds, nepollfds, timeout);
    if (ret == -1) {
        if (errno != EINTR) {
            printf("epoll_wait() returns %d\n", errno);
            return -1;
        }
    }
    /* events have been triggered, let's fire them */
    for (i = 0; i < ret; i++) {
        /* do we have a valid ev ptr ? */
        if (!epollfds[i].data.ptr) {
            continue;
        }
        /* fire the event */
        //回调事件
        fpm_event_fire((struct fpm_event_s *)epollfds[i].data.ptr);
    }

    return ret;
}

//epoll注册事件
static int fpm_event_epoll_add(struct fpm_event_s *ev)
{
    struct epoll_event e;
    /* fill epoll struct */
    e.events = EPOLLIN;
    e.data.fd = ev->fd;
    e.data.ptr = (void *)ev;

    if (ev->flags & FPM_EV_EDGE) {
        e.events = e.events | EPOLLET;
    }

    /* add the event to epoll internal queue */
    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, ev->fd, &e) == -1) {
        printf("epoll: unable to add fd %d\n", ev->fd);
        return -1;
    }

    /* mark the event as registered */
    ev->index = ev->fd;
    return 0;
}
//清除epoll
static int fpm_event_epoll_clean() /* {{{ */
{
    /* free epollfds */
    if (epollfds) {
        free(epollfds);
        epollfds = NULL;
    }
    nepollfds = 0;
    return 0;
}
//epoll移除事件
static int fpm_event_epoll_remove(struct fpm_event_s *ev) /* {{{ */
{
    struct epoll_event e;

    /* fill epoll struct the same way we did in fpm_event_epoll_add() */
    e.events = EPOLLIN;
    e.data.fd = ev->fd;
    e.data.ptr = (void *)ev;

    if (ev->flags & FPM_EV_EDGE) {
        e.events = e.events | EPOLLET;
    }

    /* remove the event from epoll internal queue */
    if (epoll_ctl(epollfd, EPOLL_CTL_DEL, ev->fd, &e) == -1) {
        printf("epoll: unable to remove fd %d\n", ev->fd);
        return -1;
    }

    /* mark the event as not registered */
    ev->index = -1;
    return 0;
}


//***********自定义事件函数**************/
//触发事件
void fpm_event_fire(struct fpm_event_s *ev) 
{
    if (!ev || !ev->callback) {
        return;
    }
    (*ev->callback)( (struct fpm_event_s *) ev, ev->which, ev->arg);
}

//设置事件信息
int fpm_event_set(struct fpm_event_s *ev, int fd, int flags, void (*callback)(struct fpm_event_s *, short, void *), void *arg)
{
    if (!ev || !callback || fd < -1) {
        return -1;
    }
    memset(ev, 0, sizeof(struct fpm_event_s));
    ev->fd = fd;
    ev->callback = callback;
    ev->arg = arg;
    ev->flags = flags;
    return 0;
}
//添加事件
int fpm_event_add(struct fpm_event_s *ev, unsigned long int frequency)
{
    struct timeval now;
    struct timeval tmp;

    if (!ev) {
        return -1;
    }

    ev->index = -1;
    if (ev->flags & FPM_EV_READ) {
        ev->which = FPM_EV_READ;
        //if (fpm_event_queue_add(&fpm_event_queue_fd, ev) != 0) {
        //    return -1;
        //}
        fpm_event_epoll_add(ev);
        return 0;
    }
}


//************信号处理**************//
//信号回调函数
static void sig_handler(int signo) /* {{{ */
{
    static const char sig_chars[NSIG + 1] = {
        [SIGTERM] = 'T',
        [SIGINT]  = 'I',
        [SIGUSR1] = '1',
        [SIGUSR2] = '2',
        [SIGQUIT] = 'Q',
        [SIGCHLD] = 'C'
    };
    char s;
    int saved_errno;
    saved_errno = errno;
    s = sig_chars[signo];
    printf("sig_handler in:%c\n",s);
    write(sp[1], &s, sizeof(s));
    errno = saved_errno;
}
//非阻塞
static inline int fd_set_blocked(int fd, int blocked) /* {{{ */
{
    int flags = fcntl(fd, F_GETFL);

    if (flags < 0) {
        return -1;
    }

    if (blocked) {
        flags &= ~O_NONBLOCK;
    } else {
        flags |= O_NONBLOCK;
    }
    return fcntl(fd, F_SETFL, flags);
}
//注册主进程信号
int fpm_signals_init_main() /* {{{ */
{
    struct sigaction act;
    if (0 > socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
        printf("failed to init signals: socketpair()\n");
        return -1;
    }

    if (0 > fd_set_blocked(sp[0], 0) || 0 > fd_set_blocked(sp[1], 0)) {
        printf("failed to init signals: fd_set_blocked()\n");
        return -1;
    }
    if (0 > fcntl(sp[0], F_SETFD, FD_CLOEXEC) || 0 > fcntl(sp[1], F_SETFD, FD_CLOEXEC)) {
        printf("falied to init signals: fcntl(F_SETFD, FD_CLOEXEC)\n");
        return -1;
    }

    memset(&act, 0, sizeof(act));
    act.sa_handler = sig_handler;
    sigfillset(&act.sa_mask);
    if (0 > sigaction(SIGTERM,  &act, 0) ||
        0 > sigaction(SIGINT,   &act, 0) ||
        0 > sigaction(SIGUSR1,  &act, 0) ||
        0 > sigaction(SIGUSR2,  &act, 0) ||
        0 > sigaction(SIGCHLD,  &act, 0) ||
        0 > sigaction(SIGQUIT,  &act, 0)) {

        printf("failed to init signals: sigaction()\n");
        return -1;
    }
    return 0;
}

void fpm_pctl(int new_state, int action) /* {{{ */
{
    switch (action) {
        case FPM_PCTL_ACTION_SET :
            if (fpm_state == new_state) { /* already in progress - just ignore duplicate signal */
                return;
            }

            switch (fpm_state) { /* check which states can be overridden */
                case FPM_PCTL_STATE_NORMAL :
                    /* 'normal' can be overridden by any other state */
                    break;
                case FPM_PCTL_STATE_RELOADING :
                    /* 'reloading' can be overridden by 'finishing' */
                    if (new_state == FPM_PCTL_STATE_FINISHING) break;
                case FPM_PCTL_STATE_FINISHING :
                    /* 'reloading' and 'finishing' can be overridden by 'terminating' */
                    if (new_state == FPM_PCTL_STATE_TERMINATING) break;
                case FPM_PCTL_STATE_TERMINATING :
                    /* nothing can override 'terminating' state */
                    printf("not switching to '%s' state, because already in '%s' state",
                        fpm_state_names[new_state], fpm_state_names[fpm_state]);
                    return;
            }

            fpm_signal_sent = 0;
            fpm_state = new_state;

            printf("switching to '%s' state\n", fpm_state_names[fpm_state]);
            /* fall down */

        case FPM_PCTL_ACTION_TIMEOUT :
            printf("hahahah--here!\n");
            exit(0);
            break;
        case FPM_PCTL_ACTION_LAST_CHILD_EXITED :
             printf("fefeef--here!\n");
            break;

    }
}
//获取信号
static void fpm_got_signal(struct fpm_event_s *ev, short which, void *arg) /* {{{ */
{
    char c;
    int res, ret;
    int fd = ev->fd;
    int pid;
    int status;
    do {
        do {
            res = read(fd, &c, 1);
        } while (res == -1 && errno == EINTR);
        printf("read:%c",c);

        switch (c) {
            case 'C' :                  /* SIGCHLD */
                printf( "received SIGCHLD\n");
                //获取子进程退出信号
                pid = waitpid(-1, &status, WNOHANG | WUNTRACED);
                printf("waitpid:%d\n",pid);
                break;
            case 'I' :                  /* SIGINT  */
                printf( "received SIGINT\n");
                fpm_pctl(FPM_PCTL_STATE_TERMINATING, FPM_PCTL_ACTION_SET);
                break;
            case 'T' :                  /* SIGTERM */
                printf( "received SIGTERM\n");
                fpm_pctl(FPM_PCTL_STATE_TERMINATING, FPM_PCTL_ACTION_SET);
                break;
            case 'Q' :                  /* SIGQUIT */
                printf( "received SIGQUIT\n");
                fpm_pctl(FPM_PCTL_STATE_FINISHING, FPM_PCTL_ACTION_SET);
                break;
            case '1' :                  /* SIGUSR1 */
                printf( "received SIGUSR1\n");
                break;
            case '2' :                  /* SIGUSR2 */
                printf( "received SIGUSR2\n");
                fpm_pctl(FPM_PCTL_STATE_RELOADING, FPM_PCTL_ACTION_SET);
                break;
        }
        break;
    } while (1);
    return;
}
//获取fd
int fpm_signals_get_fd()
{
    return sp[0];
}
int in_shutdown = 0;

static void sig_soft_quit(int signo) /* {{{ */
{
    in_shutdown = 1;
}

int fpm_signals_init_child()
{
    struct sigaction act, act_dfl;

    memset(&act, 0, sizeof(act));
    memset(&act_dfl, 0, sizeof(act_dfl));

    act.sa_handler = &sig_soft_quit;
    act.sa_flags |= SA_RESTART;

    act_dfl.sa_handler = SIG_DFL;

    close(sp[0]);
    close(sp[1]);
    if (0 > sigaction(SIGTERM,  &act_dfl,  0) ||
        0 > sigaction(SIGINT,   &act_dfl,  0) ||
        0 > sigaction(SIGUSR1,  &act_dfl,  0) ||
        0 > sigaction(SIGUSR2,  &act_dfl,  0) ||
        0 > sigaction(SIGCHLD,  &act_dfl,  0) ||
        0 > sigaction(SIGQUIT,  &act,      0)) {

        printf("failed to init child signals: sigaction()\n");
        return -1;
    }
    return 0;
}
int main(void){
    static struct fpm_event_s signal_fd_event;
    int ret;
    int pid;
    //初始化事件
    epoll_init(30);
    //注册信号
    fpm_signals_init_main();
    //监听管道
    fpm_event_set(&signal_fd_event, fpm_signals_get_fd(), FPM_EV_READ, &fpm_got_signal, NULL);
    fpm_event_add(&signal_fd_event, 0);
    
    pid = fork();
    printf("pid:%d\n",pid);
    if(pid==0)
    {
        fpm_signals_init_child();
        printf("child in\n");
        while (!in_shutdown)
        {
            printf("..sleep...\n");
            sleep(3);
        }        
        printf("child out\n");
    }else{
        while(1){
            //获取事件
            ret = fpm_event_epoll_wait(10000);
            printf("ret:%d in_shutdown:%d\n",ret,in_shutdown);
        }
    }
    return 0;
}
