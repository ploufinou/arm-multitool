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
    syscall(SC_WRITE, fd, (uint32_t) src, strlen(src), 0, 0);
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
    syscall(SC_WRITE, fd, (uint32_t) &c, 1, 0, 0);
}

static void call_main(void *saddr) {
#pragma GCC diagnostic ignored "-Wuninitialized"
  uint32_t argc = *(((uint32_t *)saddr) + 3);
#pragma GCC diagnostic warning "-Wuninitialized"
  char **argv = ((char**)saddr) + 4;
  uint32_t ret;
  
  ret = main(argc, argv);
  syscall(SC_EXIT, ret, 0, 0, 0, 0);
}

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
	    syscall(SC_EXIT, 1, 0, 0, 0, 0);
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
