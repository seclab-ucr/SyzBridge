#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

static bool write_file1(const char* file, const char* what, ...)
{
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

void setup_sandbox() {
    int real_uid = getuid();
    int real_gid = getgid();

    if (unshare(CLONE_NEWUSER) != 0) {
        perror("[-] unshare(CLONE_NEWUSER)");
        exit(EXIT_FAILURE);
    }

    if (!write_file1("/proc/self/setgroups", "deny")) {
        perror("[-] write_file(/proc/self/set_groups)");
        exit(EXIT_FAILURE);
    }
    if (!write_file1("/proc/self/uid_map", "0 %d 1\n", real_uid)){
        perror("[-] write_file(/proc/self/uid_map)");
        exit(EXIT_FAILURE);
    }
    if (!write_file1("/proc/self/gid_map", "0 %d 1\n", real_gid)) {
        perror("[-] write_file(/proc/self/gid_map)");
        exit(EXIT_FAILURE);
    }

    if (unshare(CLONE_NEWNS) != 0) {
        perror("unshare(CLONE_NEWNS)");
        exit(EXIT_FAILURE);
    }

    if (unshare(CLONE_NEWNET) != 0) {
        perror("[-] unshare(CLONE_NEWNET)");
        exit(EXIT_FAILURE);
    }
}