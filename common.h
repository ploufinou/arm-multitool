#ifndef COMMON_H
#define COMMON_H

#define O_CREAT 00000100
#define O_NOCTTY 00000400
#define O_RDONLY 00000000
#define O_RDWR 00000002
#define O_TRUNC 00001000
#define O_WRONLY 00000001
#define SEEK_END 2
#define SEEK_SET 0
#define SIGCHLD 17

typedef short int16_t;
typedef unsigned short uint16_t;

typedef int int32_t;
typedef unsigned int uint32_t;

typedef uint32_t size_t;

#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
#define ct_assert(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }

ct_assert(sizeof(short) == 2);
ct_assert(sizeof(int) == 4);

typedef long int __fd_mask;

#define __FD_SETSIZE 1024
#define __NFDBITS       (8 * (int) sizeof (__fd_mask))
#define __FD_ELT(d)     ((d) / __NFDBITS)
#define __FD_MASK(d)    ((__fd_mask) (1UL << ((d) % __NFDBITS)))

/* fd_set for select and pselect.  */
typedef struct
  {
    __fd_mask __fds_bits[__FD_SETSIZE / __NFDBITS];
# define __FDS_BITS(set) ((set)->__fds_bits)
  } fd_set;



#define FD_ZERO(s) \
  do {                                                                        \
    unsigned int __i;                                                         \
    fd_set *__arr = (s);                                                      \
    for (__i = 0; __i < sizeof (fd_set) / sizeof (__fd_mask); ++__i)          \
      __FDS_BITS (__arr)[__i] = 0;                                            \
  } while (0)
#define FD_SET(d, s) \
  ((void) (__FDS_BITS (s)[__FD_ELT(d)] |= __FD_MASK(d)))
#define FD_ISSET(d, s) \
  ((__FDS_BITS (s)[__FD_ELT (d)] & __FD_MASK (d)) != 0)


#define _SIGSET_NWORDS (1024 / (8 * sizeof (unsigned long int)))
typedef struct
{
  unsigned long int __val[_SIGSET_NWORDS];
} __sigset_t;


typedef void (*__sighandler_t) (int);

/* Structure describing the action to be taken when a signal arrives.  */
struct sigaction
  {
    /* Signal handler.  */
    __sighandler_t sa_handler;

    /* Additional set of signals to be blocked.  */
    __sigset_t sa_mask;

    /* Special flags.  */
    int sa_flags;

    /* Restore handler.  */
    void (*sa_restorer) (void);
  };

typedef unsigned short int sa_family_t;

#define __SOCKADDR_COMMON(sa_prefix) \
  sa_family_t sa_prefix##family

#define __SOCKADDR_COMMON_SIZE  (sizeof (unsigned short int))
/* Structure describing a generic socket address.  */
struct sockaddr
  {
    __SOCKADDR_COMMON (sa_);    /* Common data: address family and length.  */
    char sa_data[14];           /* Address data.  */
  };


#define SIG_IGN ((__sighandler_t)1)
#define SOCK_STREAM 1
#define AF_INET 2
#define     INADDR_ANY              ((in_addr_t) 0x00000000)
typedef uint32_t in_addr_t;
struct in_addr
  {
    in_addr_t s_addr;
  };

typedef uint16_t in_port_t;


struct sockaddr_in
  {
    __SOCKADDR_COMMON (sin_);
    in_port_t sin_port;                 /* Port number.  */
    struct in_addr sin_addr;            /* Internet address.  */

    /* Pad to size of `struct sockaddr'.  */
    unsigned char sin_zero[sizeof (struct sockaddr)
                           - __SOCKADDR_COMMON_SIZE
                           - sizeof (in_port_t)
                           - sizeof (struct in_addr)];
  };


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
uint16_t htons(uint16_t arg);

#endif
