/*
   +----------------------------------------------------------------------+
   | PHP Version 5                                                        |
   +----------------------------------------------------------------------+
   | Copyright (c) 1997-2013 The PHP Group                                |
   +----------------------------------------------------------------------+
   | This source file is subject to version 3.01 of the PHP license,      |
   | that is bundled with this package in the file LICENSE, and is        |
   | available through the world-wide-web at the following url:           |
   | http://www.php.net/license/3_01.txt                                  |
   | If you did not receive a copy of the PHP license and are unable to   |
   | obtain it through the world-wide-web, please send a note to          |
   | license@php.net so we can mail you a copy immediately.               |
   +----------------------------------------------------------------------+
   | Author: Sascha Schumann <sascha@schumann.cx>                         |
   +----------------------------------------------------------------------+
 */

/* $Id$ */

#include "php.h"

#include <sys/stat.h>
#include <sys/types.h>

#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

#if HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef PHP_WIN32
#include "win32/readdir.h"
#endif
#include <time.h>

#include <fcntl.h>
#include <errno.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "php_session.h"
#include "mod_files.h"
#include "ext/standard/flock_compat.h"
#include "php_open_temporary_file.h"

#define FILE_PREFIX "sess_"

typedef struct {
	int fd;
	char *lastkey;
	char *basedir;
	size_t basedir_len;
	size_t dirdepth;
	size_t st_size;
	int filemode;
} ps_files;
//定义session文件
ps_module ps_mod_files = {
	PS_MOD(files)
};

/* If you change the logic here, please also update the error message in
 * ps_files_open() appropriately */
static int ps_files_valid_key(const char *key)
{
	size_t len;
	const char *p;
	char c;
	int ret = 1;

	for (p = key; (c = *p); p++) {
		/* valid characters are a..z,A..Z,0..9 */
		if (!((c >= 'a' && c <= 'z')
				|| (c >= 'A' && c <= 'Z')
				|| (c >= '0' && c <= '9')
				|| c == ','
				|| c == '-')) {
			ret = 0;
			break;
		}
	}

	len = p - key;

	/* Somewhat arbitrary length limit here, but should be way more than
	   anyone needs and avoids file-level warnings later on if we exceed MAX_PATH */
	if (len == 0 || len > 128) {
		ret = 0;
	}

	return ret;
}

static char *ps_files_path_create(char *buf, size_t buflen, ps_files *data, const char *key)
{
	size_t key_len;
	const char *p;
	int i;
	int n;

	key_len = strlen(key);
	if (key_len <= data->dirdepth ||
		buflen < (strlen(data->basedir) + 2 * data->dirdepth + key_len + 5 + sizeof(FILE_PREFIX))) {
		return NULL;
	}

	p = key;
	memcpy(buf, data->basedir, data->basedir_len);
	n = data->basedir_len;
	buf[n++] = PHP_DIR_SEPARATOR;
	for (i = 0; i < (int)data->dirdepth; i++) {
		buf[n++] = *p++;
		buf[n++] = PHP_DIR_SEPARATOR;
	}
	memcpy(buf + n, FILE_PREFIX, sizeof(FILE_PREFIX) - 1);
	n += sizeof(FILE_PREFIX) - 1;
	memcpy(buf + n, key, key_len);
	n += key_len;
	buf[n] = '\0';

	return buf;
}

#ifndef O_BINARY
# define O_BINARY 0
#endif

static void ps_files_close(ps_files *data)
{
	if (data->fd != -1) {
#ifdef PHP_WIN32
		/* On Win32 locked files that are closed without being explicitly unlocked
		   will be unlocked only when "system resources become available". */
		flock(data->fd, LOCK_UN);
#endif
		close(data->fd);
		data->fd = -1;
	}
}

static void ps_files_open(ps_files *data, const char *key TSRMLS_DC)
{
	char buf[MAXPATHLEN];

	if (data->fd < 0 || !data->lastkey || strcmp(key, data->lastkey)) {
		if (data->lastkey) {
			efree(data->lastkey);
			data->lastkey = NULL;
		}

		ps_files_close(data);

		if (!ps_files_valid_key(key)) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "The session id is too long or contains illegal characters, valid characters are a-z, A-Z, 0-9 and '-,'");
			PS(invalid_session_id) = 1;
			return;
		}
		if (!ps_files_path_create(buf, sizeof(buf), data, key)) {
			return;
		}

		data->lastkey = estrdup(key);

		data->fd = VCWD_OPEN_MODE(buf, O_CREAT | O_RDWR | O_BINARY, data->filemode);

		if (data->fd != -1) {
#ifndef PHP_WIN32
			/* check to make sure that the opened file is not a symlink, linking to data outside of allowable dirs */
			if (PG(safe_mode) || PG(open_basedir)) {
				struct stat sbuf;

				if (fstat(data->fd, &sbuf)) {
					close(data->fd);
					return;
				}
				if (
					S_ISLNK(sbuf.st_mode) &&
					(
						php_check_open_basedir(buf TSRMLS_CC) ||
						(PG(safe_mode) && !php_checkuid(buf, NULL, CHECKUID_CHECK_FILE_AND_DIR))
					)
				) {
					close(data->fd);
					return;
				}
			}
#endif
			flock(data->fd, LOCK_EX);

#ifdef F_SETFD
# ifndef FD_CLOEXEC
#  define FD_CLOEXEC 1
# endif
			if (fcntl(data->fd, F_SETFD, FD_CLOEXEC)) {
				php_error_docref(NULL TSRMLS_CC, E_WARNING, "fcntl(%d, F_SETFD, FD_CLOEXEC) failed: %s (%d)", data->fd, strerror(errno), errno);
			}
#endif
		} else {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "open(%s, O_RDWR) failed: %s (%d)", buf, strerror(errno), errno);
		}
	}
}

static int ps_files_cleanup_dir(const char *dirname, int maxlifetime TSRMLS_DC)
{
	DIR *dir;
	char dentry[sizeof(struct dirent) + MAXPATHLEN];
	struct dirent *entry = (struct dirent *) &dentry;
	struct stat sbuf;
	char buf[MAXPATHLEN];
	time_t now;
	int nrdels = 0;
	size_t dirname_len;

	dir = opendir(dirname);
	if (!dir) {
		php_error_docref(NULL TSRMLS_CC, E_NOTICE, "ps_files_cleanup_dir: opendir(%s) failed: %s (%d)", dirname, strerror(errno), errno);
		return (0);
	}

	time(&now);

	dirname_len = strlen(dirname);

	/* Prepare buffer (dirname never changes) */
	memcpy(buf, dirname, dirname_len);
	buf[dirname_len] = PHP_DIR_SEPARATOR;

	while (php_readdir_r(dir, (struct dirent *) dentry, &entry) == 0 && entry) {
		/* does the file start with our prefix? */
		if (!strncmp(entry->d_name, FILE_PREFIX, sizeof(FILE_PREFIX) - 1)) {
			size_t entry_len = strlen(entry->d_name);

			/* does it fit into our buffer? */
			if (entry_len + dirname_len + 2 < MAXPATHLEN) {
				/* create the full path.. */
				memcpy(buf + dirname_len + 1, entry->d_name, entry_len);

				/* NUL terminate it and */
				buf[dirname_len + entry_len + 1] = '\0';

				/* check whether its last access was more than maxlifet ago */
				if (VCWD_STAT(buf, &sbuf) == 0 &&
						(now - sbuf.st_mtime) > maxlifetime) {
					VCWD_UNLINK(buf);
					nrdels++;
				}
			}
		}
	}

	closedir(dir);

	return (nrdels);
}

#define PS_FILES_DATA ps_files *data = PS_GET_MOD_DATA()
//#define PS_OPEN_ARGS void **mod_data, const char *save_path, const char *session_name TSRMLS_DC
//#define PS_OPEN_FUNC(x) 	int ps_open_##x(PS_OPEN_ARGS)
//        PS_OPEN_FUNC(files) --->ps_open_files(PS_OPEN_ARGS)
//open方法
//PS(mod)->s_open(&PS(mod_data), PS(save_path), PS(session_name) TSRMLS_CC)
//save_path: 此指令还有一个可选的 N 参数来决定会话文件分布的目录深度。例如，设定为 '5;/tmp' 将使创建的会话文件和路径类似于 /tmp/4/b/1/e/3/sess_4b1e384ad74619bd212e236e52a5a174If。
// 要使用 N 参数，必须在使用前先创建好这些目录。
// 在 ext/session 目录下有个小的 shell 脚本名叫 mod_files.sh，windows 版本是 mod_files.bat 可以用来做这件事。此外注意如果使用了 N 参数并且大于 0，那么将不会执行自动垃圾回收，更多信息见 php.ini。另外如果用了 N 参数，要确保将 session.save_path 的值用双引号 "quotes" 括起来，因为分隔符分号（ ;）在 php.ini 中也是注释符号。
PS_OPEN_FUNC(files)
{
	ps_files *data;
	const char *p, *last;
	const char *argv[3];
	int argc = 0;
	size_t dirdepth = 0;
	int filemode = 0600;
	//未设置路径
	if (*save_path == '\0') {
		/* if save path is an empty string, determine the temporary dir */
		//获取临时的路径
		save_path = php_get_temporary_directory();
		//安全模式
		if (PG(safe_mode) && (!php_checkuid(save_path, NULL, CHECKUID_CHECK_FILE_AND_DIR))) {
			return FAILURE;
		}
		if (php_check_open_basedir(save_path TSRMLS_CC)) {
			return FAILURE;
		}
	}

	/* split up input parameter */
	last = save_path;
	//strchr函数原型：extern char *strchr(const char *s,char c);
	//查找字符串s中首次出现字符c的位置
	p = strchr(save_path, ';');
	while (p) {
		argv[argc++] = last;
		last = ++p;
		p = strchr(p, ';');
		if (argc > 1) break;
	}
	argv[argc++] = last;

	if (argc > 1) {
		errno = 0;
		//long int strtol(const char *nptr,char **endptr,int base);
		//strtol函数会将参数nptr字符串根据参数base来转换成长整型数。
		//参数base范围从2至36，或0。参数base代表采用的进制方式，如base值为10则采用10进制，若base值为16则采用16进制等。当base值为0时则是采用10进制做转换，但遇到如’0x’前置字符则会使用16进制做转换、遇到’0’前置字符而不是’0x’的时候会使用8进制做转换。
		//目录层级
		dirdepth = (size_t) strtol(argv[0], NULL, 10);
		if (errno == ERANGE) {
			php_error(E_WARNING, "The first parameter in session.save_path is invalid");
			return FAILURE;
		}
	}

	if (argc > 2) {
		errno = 0;
		//权限
		filemode = strtol(argv[1], NULL, 8);
		if (errno == ERANGE || filemode < 0 || filemode > 07777) {
			php_error(E_WARNING, "The second parameter in session.save_path is invalid");
			return FAILURE;
		}
	}
	save_path = argv[argc - 1];

	data = ecalloc(1, sizeof(*data));

	data->fd = -1;
	data->dirdepth = dirdepth;
	data->filemode = filemode;
	data->basedir_len = strlen(save_path);
	data->basedir = estrndup(save_path, data->basedir_len);

	PS_SET_MOD_DATA(data);

	return SUCCESS;
}

PS_CLOSE_FUNC(files)
{
	PS_FILES_DATA;

	ps_files_close(data);

	if (data->lastkey) {
		efree(data->lastkey);
	}

	efree(data->basedir);
	efree(data);
	*mod_data = NULL;

	return SUCCESS;
}

PS_READ_FUNC(files)
{
	long n;
	struct stat sbuf;
	PS_FILES_DATA;

	ps_files_open(data, key TSRMLS_CC);
	if (data->fd < 0) {
		return FAILURE;
	}

	if (fstat(data->fd, &sbuf)) {
		return FAILURE;
	}

	data->st_size = *vallen = sbuf.st_size;

	if (sbuf.st_size == 0) {
		*val = STR_EMPTY_ALLOC();
		return SUCCESS;
	}

	*val = emalloc(sbuf.st_size);

#if defined(HAVE_PREAD)
	n = pread(data->fd, *val, sbuf.st_size, 0);
#else
	lseek(data->fd, 0, SEEK_SET);
	n = read(data->fd, *val, sbuf.st_size);
#endif

	if (n != sbuf.st_size) {
		if (n == -1) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "read failed: %s (%d)", strerror(errno), errno);
		} else {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "read returned less bytes than requested");
		}
		efree(*val);
		return FAILURE;
	}

	return SUCCESS;
}

PS_WRITE_FUNC(files)
{
	long n;
	PS_FILES_DATA;

	ps_files_open(data, key TSRMLS_CC);
	if (data->fd < 0) {
		return FAILURE;
	}

	/* Truncate file if the amount of new data is smaller than the existing data set. */

	if (vallen < (int)data->st_size) {
		ftruncate(data->fd, 0);
	}

#if defined(HAVE_PWRITE)
	n = pwrite(data->fd, val, vallen, 0);
#else
	lseek(data->fd, 0, SEEK_SET);
	n = write(data->fd, val, vallen);
#endif

	if (n != vallen) {
		if (n == -1) {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "write failed: %s (%d)", strerror(errno), errno);
		} else {
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "write wrote less bytes than requested");
		}
		return FAILURE;
	}

	return SUCCESS;
}

PS_DESTROY_FUNC(files)
{
	char buf[MAXPATHLEN];
	PS_FILES_DATA;

	if (!ps_files_path_create(buf, sizeof(buf), data, key)) {
		return FAILURE;
	}

	if (data->fd != -1) {
		ps_files_close(data);

		if (VCWD_UNLINK(buf) == -1) {
			/* This is a little safety check for instances when we are dealing with a regenerated session
			 * that was not yet written to disk. */
			if (!VCWD_ACCESS(buf, F_OK)) {
				return FAILURE;
			}
		}
	}

	return SUCCESS;
}

PS_GC_FUNC(files)
{
	PS_FILES_DATA;

	/* we don't perform any cleanup, if dirdepth is larger than 0.
	   we return SUCCESS, since all cleanup should be handled by
	   an external entity (i.e. find -ctime x | xargs rm) */

	if (data->dirdepth == 0) {
		*nrdels = ps_files_cleanup_dir(data->basedir, maxlifetime TSRMLS_CC);
	}

	return SUCCESS;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
