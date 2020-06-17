/*
 * Copyright (c) 2020 Léonard Bise
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <logging/log.h>
LOG_MODULE_REGISTER(toolbox, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <shell/shell.h>
#include <net/socket.h>



static int cmd_sock_new(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock new <family> <type> <proto> */
	int arg = 1;
	int fd;
	int family;
	int type;
	int proto;

	if (argc < 4) {
		return -ENOEXEC;
	}

	if (strncmp(argv[arg], "inet", 5) == 0) {
		family = AF_INET;
	} else if (strncmp(argv[arg], "inet6", 6) == 0) {
		family = AF_INET6;
	} else {
		LOG_ERR("Unsupported socket family %s", argv[arg]);
		return -ENOEXEC;
	}

	arg++;

	if (strncmp(argv[arg], "stream", 6) == 0) {
		type = SOCK_STREAM;
	} else if (strncmp(argv[arg], "dgram", 5) == 0) {
		type = SOCK_DGRAM;
	} else {
		LOG_ERR("Unsupported socket type %s", argv[arg]);
		return -ENOEXEC;
	}

	arg++;

	if (strncmp(argv[arg], "tcp", 3) == 0) {
		proto = IPPROTO_TCP;
	} else if (strncmp(argv[arg], "tls_1_2", 5) == 0) {
		proto = IPPROTO_TLS_1_2;
	} else {
		LOG_ERR("Unsupported socket proto %s", argv[arg]);
		return -ENOEXEC;
	}

	arg++;

	fd = socket(family, type, proto);
	if (fd < 0) {
		LOG_ERR("Cannot create new socket %d", errno);
		return errno;
	}

	LOG_INF("Created socket fd=%d", fd);

	return 0;
}

static int cmd_sock_connect(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock connect <fd> <ip>:<port> or [<ipv6>]:port */
	int arg = 1;
	int fd;
	struct sockaddr addr;
	const char *addr_str;
	int err;

	if (argc < 3) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	addr_str = argv[arg++];
	if (!net_ipaddr_parse(addr_str, strnlen(addr_str, NET_IPV6_ADDR_LEN),
			     &addr)) {
		LOG_ERR("Cannot parse ip and port: %s", addr_str);
		return -ENOEXEC;
	}

	err = connect(fd, &addr, sizeof(addr));
	if (err) {
		LOG_ERR("Cannot connect to %s (%d)", addr_str, -errno);
		return -ENOEXEC;
	}

	return 0;
}

static int cmd_sock_bind(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock bind <fd> <ip>:<port> or [<ipv6>]:port */
	int arg = 1;
	int fd;
	struct sockaddr addr;
	const char *addr_str;
	int err;

	if (argc < 3) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	addr_str = argv[arg++];
	if (!net_ipaddr_parse(addr_str, strnlen(addr_str, NET_IPV6_ADDR_LEN),
			     &addr)) {
		LOG_ERR("Cannot parse ip and port: %s", addr_str);
		return -ENOEXEC;
	}

	err = bind(fd, &addr, sizeof(addr));
	if (err) {
		LOG_ERR("Cannot bind to %s (%d)", addr_str, -errno);
		return -ENOEXEC;
	}

	return 0;
}

static int cmd_sock_listen(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock listen <fd> <max client> */
	int arg = 1;
	int fd;
	int max;
	int err;

	if (argc < 3) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	max = strtoul(argv[arg++], NULL, 10);

	err = listen(fd, max);
	if (err) {
		LOG_ERR("Cannot listen (%d)", -errno);
		return -ENOEXEC;
	}

	return 0;
}

static int cmd_sock_close(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock close <fd> */
	int arg = 1;
	int fd;
	int err;

	if (argc < 2) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	err = close(fd);
	if (err) {
		LOG_ERR("Cannot close (%d)", -errno);
		return -ENOEXEC;
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sock_commands,
	SHELL_CMD(new, NULL, "'sock new <family inet|inet6> <type stream|dgram>"
			     "<proto tcp|tls_1_2>' Create a new socket",
		  cmd_sock_new),
	SHELL_CMD(connect, NULL, "'sock connect <fd> <ip>:<port> or [<ipv6>]:<port>'"
			     "Connect a socket",
		  cmd_sock_connect),
	SHELL_CMD(bind, NULL, "'sock bind <fd> <ip>:<port> or [<ipv6>]:<port>'"
			     "Connect a socket",
		  cmd_sock_bind),
	SHELL_CMD(listen, NULL, "'sock listen <fd> <max client>'"
			     "Make a socket listen",
		  cmd_sock_listen),
	SHELL_CMD(close, NULL, "'sock close <fd>'"
			     "Close a socket",
		  cmd_sock_close),

	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sock, &sock_commands, "Sockets commands", NULL);

void main(void)
{


}
