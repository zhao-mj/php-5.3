
	/* $Id: fpm_signals.c,v 1.24 2008/08/26 15:09:15 anight Exp $ */
	/* (c) 2007,2008 Andrei Nigmatulin */

#include "fpm_config.h"

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "fpm.h"
#include "fpm_signals.h"
#include "fpm_sockets.h"
#include "fpm_php.h"
#include "zlog.h"

static int sp[2];

const char *fpm_signal_names[NSIG + 1] = {
#ifdef SIGHUP
	[SIGHUP] 		= "SIGHUP",
#endif
#ifdef SIGINT
	[SIGINT] 		= "SIGINT",
#endif
#ifdef SIGQUIT
	[SIGQUIT] 		= "SIGQUIT",
#endif
#ifdef SIGILL
	[SIGILL] 		= "SIGILL",
#endif
#ifdef SIGTRAP
	[SIGTRAP] 		= "SIGTRAP",
#endif
#ifdef SIGABRT
	[SIGABRT] 		= "SIGABRT",
#endif
#ifdef SIGEMT
	[SIGEMT] 		= "SIGEMT",
#endif
#ifdef SIGBUS
	[SIGBUS] 		= "SIGBUS",
#endif
#ifdef SIGFPE
	[SIGFPE] 		= "SIGFPE",
#endif
#ifdef SIGKILL
	[SIGKILL] 		= "SIGKILL",
#endif
#ifdef SIGUSR1
	[SIGUSR1] 		= "SIGUSR1",
#endif
#ifdef SIGSEGV
	[SIGSEGV] 		= "SIGSEGV",
#endif
#ifdef SIGUSR2
	[SIGUSR2] 		= "SIGUSR2",
#endif
#ifdef SIGPIPE
	[SIGPIPE] 		= "SIGPIPE",
#endif
#ifdef SIGALRM
	[SIGALRM] 		= "SIGALRM",
#endif
#ifdef SIGTERM
	[SIGTERM] 		= "SIGTERM",
#endif
#ifdef SIGCHLD
	[SIGCHLD] 		= "SIGCHLD",
#endif
#ifdef SIGCONT
	[SIGCONT] 		= "SIGCONT",
#endif
#ifdef SIGSTOP
	[SIGSTOP] 		= "SIGSTOP",
#endif
#ifdef SIGTSTP
	[SIGTSTP] 		= "SIGTSTP",
#endif
#ifdef SIGTTIN
	[SIGTTIN] 		= "SIGTTIN",
#endif
#ifdef SIGTTOU
	[SIGTTOU] 		= "SIGTTOU",
#endif
#ifdef SIGURG
	[SIGURG] 		= "SIGURG",
#endif
#ifdef SIGXCPU
	[SIGXCPU] 		= "SIGXCPU",
#endif
#ifdef SIGXFSZ
	[SIGXFSZ] 		= "SIGXFSZ",
#endif
#ifdef SIGVTALRM
	[SIGVTALRM] 	= "SIGVTALRM",
#endif
#ifdef SIGPROF
	[SIGPROF] 		= "SIGPROF",
#endif
#ifdef SIGWINCH
	[SIGWINCH] 		= "SIGWINCH",
#endif
#ifdef SIGINFO
	[SIGINFO] 		= "SIGINFO",
#endif
#ifdef SIGIO
	[SIGIO] 		= "SIGIO",
#endif
#ifdef SIGPWR
	[SIGPWR] 		= "SIGPWR",
#endif
#ifdef SIGSYS
	[SIGSYS] 		= "SIGSYS",
#endif
#ifdef SIGWAITING
	[SIGWAITING] 	= "SIGWAITING",
#endif
#ifdef SIGLWP
	[SIGLWP] 		= "SIGLWP",
#endif
#ifdef SIGFREEZE
	[SIGFREEZE] 	= "SIGFREEZE",
#endif
#ifdef SIGTHAW
	[SIGTHAW] 		= "SIGTHAW",
#endif
#ifdef SIGCANCEL
	[SIGCANCEL] 	= "SIGCANCEL",
#endif
#ifdef SIGLOST
	[SIGLOST] 		= "SIGLOST",
#endif
};

static void sig_soft_quit(int signo) /* {{{ */
{
	int saved_errno = errno;

	/* closing fastcgi listening socket will force fcgi_accept() exit immediately */
	close(0);
	if (0 > socket(AF_UNIX, SOCK_STREAM, 0)) {
		zlog(ZLOG_WARNING, "failed to create a new socket");
	}
	fpm_php_soft_quit();
	errno = saved_errno;
}
/* }}} */

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

	if (fpm_globals.parent_pid != getpid()) {
		/* prevent a signal race condition when child process
			have not set up it's own signal handler yet */
		return;
	}

	saved_errno = errno;
	s = sig_chars[signo];
	write(sp[1], &s, sizeof(s));
	errno = saved_errno;
}
/* }}} */

int fpm_signals_init_main() /* {{{ */
{
	struct sigaction act;

	if (0 > socketpair(AF_UNIX, SOCK_STREAM, 0, sp)) {
		zlog(ZLOG_SYSERROR, "failed to init signals: socketpair()");
		return -1;
	}

	if (0 > fd_set_blocked(sp[0], 0) || 0 > fd_set_blocked(sp[1], 0)) {
		zlog(ZLOG_SYSERROR, "failed to init signals: fd_set_blocked()");
		return -1;
	}
	//改变已打开的文件性质
	//F_DUPFD用来查找大于或等于参数arg的最小且仍未使用的文件描述符，并且复制参数fd的文件描述符。执行成功则返回新复制的文件描述符。新描述符与fd共享同一文件表项，但是新描述符有它自己的一套文件描述符标志，其中FD_CLOEXEC文件描述符标志被清除。请参考dup2()。
	//F_GETFD取得close-on-exec旗标。若此旗标的FD_CLOEXEC位为0，代表在调用exec()相关函数时文件将不会关闭。
	//F_SETFD 设置close-on-exec 旗标。该旗标以参数arg 的FD_CLOEXEC位决定。
	//F_GETFL 取得文件描述符状态旗标，此旗标为open（）的参数flags。
	//F_SETFL 设置文件描述符状态旗标，参数arg为新旗标，但只允许O_APPEND、O_NONBLOCK和O_ASYNC位的改变，其他位的改变将不受影响。
	//F_GETLK 取得文件锁定的状态。
	//F_SETLK 设置文件锁定的状态。此时flcok 结构的l_type 值必须是F_RDLCK、F_WRLCK或F_UNLCK。如果无法建立锁定，则返回-1，错误代码为EACCES 或EAGAIN。
	//F_SETLKW F_SETLK 作用相同，但是无法建立锁定时，此调用会一直等到锁定动作成功为止。若在等待锁定的过程中被信号中断时，会立即返回-1，错误代码为EINTR。
	if (0 > fcntl(sp[0], F_SETFD, FD_CLOEXEC) || 0 > fcntl(sp[1], F_SETFD, FD_CLOEXEC)) {
		zlog(ZLOG_SYSERROR, "falied to init signals: fcntl(F_SETFD, FD_CLOEXEC)");
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

		zlog(ZLOG_SYSERROR, "failed to init signals: sigaction()");
		return -1;
	}
	return 0;
}
/* }}} */

int fpm_signals_init_child() /* {{{ */
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

		zlog(ZLOG_SYSERROR, "failed to init child signals: sigaction()");
		return -1;
	}
	return 0;
}
/* }}} */

int fpm_signals_get_fd() /* {{{ */
{
	return sp[0];
}
/* }}} */

