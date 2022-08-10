#ifndef COMMON_H
#define COMMON_H

#include <sys/types.h>
#include <stdint.h>

#define SC_EXIT 1
#define SC_FORK 2
#define SC_READ 3
#define SC_WRITE 4
#define SC_OPEN 5
#define SC_CLOSE 6
#define SC_EXECVE 11
#define SC_SETUID 23
#define SC_PAUSE 29
#define SC_LSEEK 19
#define SC_IOCTL 54
#define SC_DUP2 63
#define SC_SETSID 66
#define SC_SIGACTION 67
#define SC_SELECT 142
#define SC_POLL 168
#define SC_PRCTL 172
#define SC_SOCKET 281
#define SC_BIND 282
#define SC_CONNECT 283
#define SC_ACCEPT 285
#define SC_LISTEN 284

#define TIOCGPTN 0x80045430
#define TIOCSPTLCK 0x40045431

#define PR_SET_NAME 15

void *memset(void *ptr, int what, size_t size);
void *memcpy(void *dest, const void *src, size_t size);
uint32_t syscall0(uint32_t id);
uint32_t syscall1(uint32_t id, uint32_t arg1);
uint32_t syscall2(uint32_t id, uint32_t arg1, uint32_t arg2);
uint32_t syscall3(uint32_t id, uint32_t arg1, uint32_t arg2, uint32_t arg3);
uint32_t syscall4(uint32_t id, uint32_t arg1, uint32_t arg2, uint32_t arg3, uint32_t arg4);
size_t strlen(const char *src);
void fputstring(int fd, const char *src);
void fputhex(int fd, uint32_t val);
void check(int fd, int ret, char *str, int quit);
int strcmp(const char *s1, const char *s2);
int parse_int(const char *s);
int explode(char *str, char sep, char **parts, int parts_size);
int main(int argc, char **argv);
#endif
