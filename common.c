#include "common.h"

void *memset(void *ptr, int what, size_t size) {
	int i;
	char *cptr = ptr;
	for (i = 0; i < size; i++) cptr[i] = what;	
	return ptr;
}

void *memcpy(void *dest, const void *src, size_t size) {
	int i;
	char *cdest = dest;
	const char *csrc = src;
	for (i = 0; i < size; i++) cdest[i] = csrc[i];
	return dest;
}

size_t strlen(const char *src) {
    int i;
    for (i = 0; src[i]; i++);
    return i;
}

int strcmp(const char *s1, const char *s2) {
	int i;
	for (i = 0; s1[i] == s2[i] && s1[i]; i++) {
	}
	return !(s1[i] == s2[i]);
}

int parse_int(const char *s) {
	int res = 0, i, d;
	for (i = 0; s[i]; i++) {
		d = s[i] - '0';
		if ((d < 0) || (d > 9)) return -1;
		res *=10;
		res += d;
	}
	return res;
}

void fputstring(int fd, const char *src) {
    syscall3(SC_WRITE, fd, (uint32_t) src, strlen(src));
}

void fputhex(int fd, uint32_t val) {
    char c;
    if (val >> 4) {
        fputhex(fd, val >> 4);
    }
    
    if ((val & 0xF) < 10) {
        c = (val & 0xF) + '0';
    } else {
        c = (val & 0xF) + 'A' - 10;
    }
    syscall3(SC_WRITE, fd, (uint32_t) &c, 1);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#pragma GCC diagnostic ignored "-Wuninitialized"
static void call_main(void *saddr) {
  uint32_t argc = *(((uint32_t *)saddr) + 3);
  char **argv = ((char**)saddr) + 4;
  uint32_t ret;
  
  ret = main(argc, argv);
  syscall1(SC_EXIT, ret);
}
#pragma GCC diagnostic pop

void _start(void) {
	uint32_t stack;
	call_main(&stack);
}


void check(int fd, int ret, char *str, int quit) {
  if (ret < 0) {
    fputstring(fd, str);
    fputstring(fd, ": errno=0x");
    fputhex(fd, -ret);
    fputstring(fd, "\n");
    if (quit)
	    syscall1(SC_EXIT, 1);
  }
}

int explode(char *str, char sep, char **parts, int parts_size) {

	int i, np = 1;

	parts[0] = str;

	for (i = 0; str[i] && np < parts_size; i++) {
		if (str[i] == sep) {
			str[i] = 0;
			parts[np] = str + i + 1;
			np++;
		}
	}
	return np;
}

uint32_t syscall3(uint32_t id, uint32_t arg1, uint32_t arg2, uint32_t arg3) {
	return syscall4(id, arg1, arg2, arg3, 0);
}

uint32_t syscall2(uint32_t id, uint32_t arg1, uint32_t arg2) {
	return syscall4(id, arg1, arg2, 0, 0);
}

uint32_t syscall1(uint32_t id, uint32_t arg1) {
	return syscall4(id, arg1, 0, 0, 0);
}

uint32_t syscall0(uint32_t id) {
	return syscall4(id, 0, 0, 0, 0);
}

uint16_t htons(uint16_t arg) {
	return ((arg & 0xFF) << 8) | ((arg >> 8) & 0xFF);
}

long int __fdelt_chk (long int d)
{
  return d / __NFDBITS;
}
