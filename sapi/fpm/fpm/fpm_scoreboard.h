
	/* $Id: fpm_status.h 312263 2011-06-18 17:46:16Z felipe $ */
	/* (c) 2009 Jerome Loyet */

#ifndef FPM_SCOREBOARD_H
#define FPM_SCOREBOARD_H 1

#include <sys/time.h>
#ifdef HAVE_TIMES
#include <sys/times.h>
#endif

#include "fpm_request.h"
#include "fpm_worker_pool.h"
#include "fpm_atomic.h"

#define FPM_SCOREBOARD_ACTION_SET 0
#define FPM_SCOREBOARD_ACTION_INC 1

struct fpm_scoreboard_proc_s {
	union {
		atomic_t lock;
		char dummy[16];
	};//锁状态
	int used; //使用标识 0=未使用 1=正在使用
	time_t start_epoch; //使用开始时间
	pid_t pid; //进程id
	unsigned long requests; //处理请求次数
	enum fpm_request_stage_e request_stage; //处理请求阶段
	struct timeval accepted; //accept请求的时间
	struct timeval duration; //脚本执行时间
	time_t accepted_epoch;//accept请求时间戳(秒)
	struct timeval tv; //活跃时间
	char request_uri[128]; //请求路径
	char query_string[512]; //请求参数
	char request_method[16]; //请求方式
	size_t content_length; //请求内容长度 /* used with POST only */
	char script_filename[256];//脚本名称
	char auth_user[32];
#ifdef HAVE_TIMES
	struct tms cpu_accepted;
	struct timeval cpu_duration;
	struct tms last_request_cpu;
	struct timeval last_request_cpu_duration;
#endif
	size_t memory;//脚本占用的内存大小
};

struct fpm_scoreboard_s {
	union {
		atomic_t lock;
		char dummy[16];
	};//锁状态
	char pool[32];//实例名称 例如：[www]
	int pm; //PM运行模式
	time_t start_epoch; //开始时间
	int idle;//procs的空闲数
	int active;//procs的使用数
	int active_max; //最大procs的使用数
	unsigned long int requests;
	unsigned int max_children_reached; //到达最大进程数次数
	int lq; //当前listen queue的请求数(accept操作，可以过tcpi_unacked或getsocketopt获取)
	int lq_max;//listen queue大小
	unsigned int lq_len;
	unsigned int nprocs; //procs总数
	int free_proc; //遍历下一个空闲的下标
	struct fpm_scoreboard_proc_s *procs[]; //节点列表
};

int fpm_scoreboard_init_main();
int fpm_scoreboard_init_child(struct fpm_worker_pool_s *wp);

void fpm_scoreboard_update(int idle, int active, int lq, int lq_len, int requests, int max_children_reached, int action, struct fpm_scoreboard_s *scoreboard);
struct fpm_scoreboard_s *fpm_scoreboard_get();
struct fpm_scoreboard_proc_s *fpm_scoreboard_proc_get(struct fpm_scoreboard_s *scoreboard, int child_index);

struct fpm_scoreboard_s *fpm_scoreboard_acquire(struct fpm_scoreboard_s *scoreboard, int nohang);
void fpm_scoreboard_release(struct fpm_scoreboard_s *scoreboard);
struct fpm_scoreboard_proc_s *fpm_scoreboard_proc_acquire(struct fpm_scoreboard_s *scoreboard, int child_index, int nohang);
void fpm_scoreboard_proc_release(struct fpm_scoreboard_proc_s *proc);

void fpm_scoreboard_free(struct fpm_scoreboard_s *scoreboard);

void fpm_scoreboard_child_use(struct fpm_scoreboard_s *scoreboard, int child_index, pid_t pid);

void fpm_scoreboard_proc_free(struct fpm_scoreboard_s *scoreboard, int child_index);
int fpm_scoreboard_proc_alloc(struct fpm_scoreboard_s *scoreboard, int *child_index);

#ifdef HAVE_TIMES
float fpm_scoreboard_get_tick();
#endif

#endif
