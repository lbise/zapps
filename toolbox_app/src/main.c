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
#include <net/tls_credentials.h>
#include "net_private.h"

/* Used signed certificates */
#define SIGNED_CERTS
#include "certificate.h"

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

static int cmd_sock_accept(const struct shell *shell, size_t argc, char *argv[])
{
	/* sock accept <fd> */
	int arg = 1;
	int fd;
	struct sockaddr client_addr;
	socklen_t client_addr_len = sizeof(client_addr);
	int err;

	if (argc < 2) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	err = accept(fd, &client_addr, &client_addr_len);
	if (err < 0) {
		LOG_ERR("Cannot accept client (%d)", -errno);
		return -ENOEXEC;
	}

	if (client_addr.sa_family == AF_INET) {
		LOG_INF("New client fd=%d %s:%d", err,
			log_strdup(net_sprint_ipv4_addr(
					&net_sin(&client_addr)->sin_addr)),
			ntohs(net_sin(&client_addr)->sin_port));
	} else if (client_addr.sa_family == AF_INET6) {
		LOG_INF("New client fd=%d [%s]:%d", err,
			log_strdup(net_sprint_ipv6_addr(
					&net_sin6(&client_addr)->sin6_addr)),
				   ntohs(net_sin6(&client_addr)->sin6_port));
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

static int cmd_sock_tlsopt(const struct shell *shell, size_t argc, char *argv[])
{
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	/* sock tlsopt <fd> <srv|cli> */
	int arg = 1;
	int fd;
	bool srv;
	int err;

	if (argc < 3) {
		return -ENOEXEC;
	}

	fd = strtoul(argv[arg++], NULL, 10);

	if (strncmp(argv[arg], "srv", 3) == 0) {
		srv = true;
	} else if (strncmp(argv[arg], "cli", 3) == 0) {
		srv = false;
	} else {
		LOG_ERR("Unknown type %s", argv[arg]);
		return -ENOEXEC;
	}

	sec_tag_t sec_tag_list[] = {
		CERTIFICATE_TAG,
#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
		PSK_TAG,
#endif
	};

	err = setsockopt(fd, SOL_TLS, TLS_SEC_TAG_LIST,
			 sec_tag_list, sizeof(sec_tag_list));
	if (err < 0) {
		LOG_ERR("Failed to set TCP secure option (%d)", -errno);
		return -errno;
	}

	if (!srv) {
		err = setsockopt(fd, SOL_TLS, TLS_HOSTNAME,
				 TLS_PEER_HOSTNAME, sizeof(TLS_PEER_HOSTNAME));
		if (err < 0) {
			LOG_ERR("Failed to set TLS_HOSTNAME option (%d)",
				-errno);
			return -errno;
		}
	}

	LOG_INF("Set TLS socket options for %d", fd);

	return 0;
#else
	LOG_ERR("CONFIG_NET_SOCKETS_SOCKOPT_TLS not enabled");
	return -ENOTSUP;
#endif
}

SHELL_STATIC_SUBCMD_SET_CREATE(sock_commands,
	SHELL_CMD(new, NULL, "'sock new <family inet|inet6> <type stream|dgram>"
			     "<proto tcp|tls_1_2>' Create a new socket",
		  cmd_sock_new),
	SHELL_CMD(connect, NULL, "'sock connect <fd> <ip>:<port> or [<ipv6>]:<port>' "
			     "Connect a socket",
		  cmd_sock_connect),
	SHELL_CMD(bind, NULL, "'sock bind <fd> <ip>:<port> or [<ipv6>]:<port>' "
			     "Connect a socket",
		  cmd_sock_bind),
	SHELL_CMD(listen, NULL, "'sock listen <fd> <max client>' "
			     "Make a socket listen",
		  cmd_sock_listen),
	SHELL_CMD(accept, NULL, "'sock accept <fd>' "
			     "Accept an incoming connection",
		  cmd_sock_accept),
	SHELL_CMD(close, NULL, "'sock close <fd>' "
			     "Close a socket",
		  cmd_sock_close),
	SHELL_CMD(tlsopt, NULL, "'sock tlsopt <fd> <srv|cli>' "
			     "Set TLS related options",
		  cmd_sock_tlsopt),

	SHELL_SUBCMD_SET_END
);

SHELL_CMD_REGISTER(sock, &sock_commands, "Sockets commands", NULL);

void main(void)
{

#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err;

#if defined(SIGNED_CERTS)
	err = tls_credential_add(CERTIFICATE_TAG,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate,
				 sizeof(ca_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register CA certificate: %d", err);
		return;
	}
#endif

	err = tls_credential_add(CERTIFICATE_TAG,
				 TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 server_certificate,
				 sizeof(server_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register public certificate: %d", err);
		return;
	}


	err = tls_credential_add(CERTIFICATE_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, sizeof(private_key));
	if (err < 0) {
		LOG_ERR("Failed to register private key: %d", err);
		return;
	}

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK,
				psk,
				sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
		return;
	}
	err = tls_credential_add(PSK_TAG,
				TLS_CREDENTIAL_PSK_ID,
				psk_id,
				sizeof(psk_id) - 1);
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
		return;
	}
#endif

#endif

}
