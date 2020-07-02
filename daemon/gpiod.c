// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020 Matthew Bobrowski <matthew@bobrowski.net>
 */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/un.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#define SUCCESS 0
#define FAILURE 1

#define BUF_SZ  4096
#define BACKLOG 1024

#define GPIOD_PID_FILE "/var/run/gpiod.pid"
#define GPIOD_PID_FILE_MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)
#define GPIOD_DOMAIN_SOCK "/var/run/gpiod.sock"

enum modes {
	PRINT_STDERR = 0,
	PRINT_SYSLOG,
};

static int mode;
static int sockfd;
static int pipefd[2];

static void print(int priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	if (mode == PRINT_SYSLOG) {
		vsyslog(priority, format, ap);
	} else {
		vfprintf(stderr, format, ap);
		fputc('\n', stderr);
	}

	va_end(ap);
	return;
}

static void notify_parent(int status)
{
	ssize_t ret;

	do {
		ret = write(pipefd[1], &status, sizeof(status));
	} while (ret == -1 && errno == EINTR);
}

static int write_pid_file(void)
{
	int fd, len;
	ssize_t ret;
	char buf[16];

	fd = creat(GPIOD_PID_FILE, GPIOD_PID_FILE_MODE);
	if (fd == -1) {
		print(LOG_ERR,
		      "Failed to create PID file %s (%s)",
		      GPIOD_PID_FILE, strerror(errno));
		return -1;
	}

	len = snprintf(buf, sizeof(buf), "%u\n", getpid());
	if (len <= 0) {
		print(LOG_ERR,
		      "Failed to store PID %d in buf",
		      getpid());
		goto error;
	}

	do {
		ret = write(fd, buf, len);
	} while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		print(LOG_ERR,
		      "Failed to write PID %d to PID file %s (%s)",
		      getpid(), GPIOD_PID_FILE, strerror(errno));
		goto error;
	}

	ret = flock(fd, LOCK_EX);
	if (ret == -1) {
		print(LOG_ERR,
		      "Failed to apply exclusive lock on PID file %s (%s)",
		      GPIOD_PID_FILE, strerror(errno));
		goto error;
	}

	return 0;
error:
	close(fd);
	return -1;
}


static int daemonize(void)
{
	ssize_t ret;
	int fd, status;

	if (pipe(pipefd)) {
		print(LOG_ERR,
		      "Failed to create pipe (%s)",
		      strerror(errno));
		return -1;
	}

	switch (fork()) {
	case 0:
		close(pipefd[0]);

		if (setsid() == -1) {
			print(LOG_ERR,
			      "Failed to become session leader (%s)",
			      strerror(errno));
			return -1;
		}

		umask(0);

		if (chdir("/") == -1) {
			print(LOG_ERR,
			      "Failed to change working directory to / (%s)",
			      strerror(errno));
			return -1;
		}

		fd = open("/dev/null", O_RDWR);
		if (fd == -1) {
			print(LOG_ERR,
			      "Failed to open /dev/null device (%s)",
			      strerror(errno));
			return -1;
		}

		if ((dup2(fd, STDIN_FILENO) == -1) ||
		    (dup2(fd, STDOUT_FILENO) == -1) ||
		    (dup2(fd, STDERR_FILENO) == -1)) {
			print(LOG_ERR,
			      "Failed to duplicate standard file "
			      "descriptors (%s)",
			      strerror(errno));
			close(fd);
			return -1;
		}

		break;
	case -1:
		print(LOG_ERR,
		      "Failed to create child process via fork (%s)",
		      strerror(errno));
		return -1;
	default:
		do {
			ret = read(pipefd[0], &status, sizeof(status));
		} while (ret == -1 && errno == EINTR);

		if (ret == -1)
			return -1;

		if (status == SUCCESS)
			_exit(EXIT_SUCCESS);
		return -1;
	}

	return 0;
}

static int close_file_descriptors(size_t min)
{
	DIR *dirp;
	char *endptr;
	int i, fd, dfd;
	struct rlimit rlim;
	struct dirent *entry;

	dirp = opendir("/proc/self/fd");
	if (!dirp) {
		print(LOG_ERR,
		      "Failed to open directory stream to /proc/self/fd (%s)",
		      strerror(errno));
		goto fallback;
	}

	dfd = dirfd(dirp);
	if (dfd == -1) {
		print(LOG_ERR,
		      "Failed to get associated file descriptor for directory stream "
		      "/proc/self/fd (%s)",
		      strerror(errno));
		goto fallback;
	}

	errno = 0;
	while((entry = readdir(dirp)) != NULL) {
		if (!strcmp(".", entry->d_name) ||
		    !strcmp("..", entry->d_name))
			continue;

		fd = strtol(entry->d_name, &endptr, 10);
		if (fd == dfd || fd < min)
			continue;

		close(fd);
	}

	if (errno && !entry) {
		print(LOG_ERR,
		      "Failed to obtain dirent structure while reading from "
		      "/proc/self/fd (%s)",
		      strerror(errno));
		goto fallback;
	}

	closedir(dirp);
	return 0;

	/*
	 * This is an aggressive fallback mechanism used to close file
	 * descriptors. This path should rarely ever be taken.
	 */
fallback:
	if (dirp)
		closedir(dirp);

	if (getrlimit(RLIMIT_NOFILE, &rlim) == -1) {
		print(LOG_ERR,
		      "Failed to obtain resource limits (%s)",
		      strerror(errno));
		return -1;
	}

	if (rlim.rlim_max == RLIM_INFINITY)
		rlim.rlim_max = 1024;

	for (i = 0; i < rlim.rlim_max; i++) {
		if (i < min)
			continue;
		close(i);
	}

	return 0;
}

static int daemon_running(void)
{
	int fd;

	fd = open(GPIOD_PID_FILE, O_RDONLY);
	if (fd == -1) {
		/*
		 * A non-existent PID file is an indication that an
		 * instance of this program does not exist. This
		 * however does not catch the edge case where the PID
		 * file has been manually cleaned up by an
		 * administrator.
		 */
		if (errno == ENOENT)
			return 0;

		print(LOG_ERR,
		      "Failed to open PID file %s (%s)",
		      GPIOD_PID_FILE, strerror(errno));
		return -1;
	}

	if (flock(fd, LOCK_EX | LOCK_NB)) {
		if (errno == EWOULDBLOCK)
			print(LOG_ERR,
			      "Failed to obtain lock on PID file %s. "
			      "File is locked by another process (%s)",
			      GPIOD_PID_FILE, strerror(errno));
		else
			print(LOG_ERR,
			      "Failed to obtain lock on PID file %s (%s)",
			      GPIOD_PID_FILE, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

static void clean_up(void)
{
	if (close_file_descriptors(0))
		print(LOG_ERR,
		      "Failed to close process file descriptors during "
		      "shutdown");

	unlink(GPIOD_PID_FILE);
	unlink(GPIOD_DOMAIN_SOCK);
	closelog();
}

static void sigterm_handler(int signum)
{
	exit(EXIT_SUCCESS);
}

static int init_domain_sock(void)
{
	int ret;
	struct sockaddr_un servaddr;

	sockfd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (sockfd == -1) {
		print(LOG_ERR,
		      "Failed to create domain socket (%s)",
		      strerror(errno));
		return -1;
	}

	unlink(GPIOD_DOMAIN_SOCK);
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sun_family = AF_LOCAL;
	strncpy(servaddr.sun_path, GPIOD_DOMAIN_SOCK,
		sizeof(servaddr.sun_path) - 1);

	ret = bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	if (ret == -1) {
		print(LOG_ERR,
		      "Failed to bind to domain socket %d (%s)",
		      sockfd, strerror(errno));
		return -1;
	}

	return 0;
}

int main(int argc, char **argv)
{
	ssize_t ret;
	int i, connfd;
	char buf[BUF_SZ];
	struct sigaction sa;

	if (daemon_running()) {
		print(LOG_ERR,
		      "An instance of this program is already running");
		exit(EXIT_FAILURE);
	}

	if (close_file_descriptors(3)) {
		print(LOG_ERR,
		      "Failed to close non standard file descriptors");
		exit(EXIT_FAILURE);
	}

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_IGN;
	for (i = 1; i < NSIG; i++)
		sigaction(i, &sa, NULL);

	sa.sa_handler = sigterm_handler;
	if (sigaction(SIGTERM, &sa, NULL)) {
		print(LOG_ERR,
		      "Failed to register SIGTERM handler (%s)",
		      strerror(errno));
		exit(EXIT_FAILURE);
	}

	atexit(clean_up);

	if (daemonize()) {
		print(LOG_ERR,
		      "Failed to daemonize program");
		notify_parent(FAILURE);
		exit(EXIT_FAILURE);
	}

	mode = PRINT_SYSLOG;
	openlog("gpiod", LOG_CONS | LOG_PID, LOG_DAEMON);

	if (write_pid_file()) {
		print(LOG_ERR,
		      "Failed to write PID %d to daemon PID file %s",
		      getpid(), GPIOD_PID_FILE);
		notify_parent(FAILURE);
		exit(EXIT_FAILURE);
	}

	if (init_domain_sock()) {
		print(LOG_ERR,
		      "Failed to setup domain socket for IPC");
		notify_parent(FAILURE);
		exit(EXIT_FAILURE);
	}

	if (listen(sockfd, BACKLOG)) {
		print(LOG_ERR,
		      "Failed to mark socket(%d) as passize socket (%s)",
		      sockfd, strerror(errno));
		notify_parent(FAILURE);
		exit(EXIT_FAILURE);
	}

	notify_parent(SUCCESS);
	close(pipefd[1]);

	for (;;) {
		connfd = accept(sockfd, NULL, NULL);
		if (connfd == -1) {
			if (errno == EINTR)
				continue;
			print(LOG_ERR,
			      "Failed to extract pending connection (%s)",
			      strerror(errno));
			exit(EXIT_FAILURE);
		}

		do {
			ret = read(connfd, buf, BUF_SZ);
		} while (ret == -1 && errno == EINTR);

		if (ret == -1) {
			print(LOG_ERR,
			      "Failed to read bytes from file descriptor %d (%s)",
			      connfd, strerror(errno));
			close(connfd);
			exit(EXIT_FAILURE);
		}

		close(connfd);
	}

	exit(EXIT_SUCCESS);
}
