/*
 * Copyright (c) 2020 Léonard Bise
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __CERTIFICATE_H__
#define __CERTIFICATE_H__

#define CERTIFICATE_TAG 1
#define PSK_TAG 2

#define TLS_PEER_HOSTNAME "localhost"

#if !defined(SIGNED_CERTS)
static const unsigned char server_certificate[] = {
#include "echo-apps-cert.der.inc"
};

/* This is the private key in pkcs#8 format. */
static const unsigned char private_key[] = {
#include "echo-apps-key.der.inc"
};

#else

static const unsigned char ca_certificate[] = {
#include "ca.der.inc"
};

static const unsigned char server_certificate[] = {
#include "server.der.inc"
};

/* This is the private key in pkcs#8 format. */
static const unsigned char private_key[] = {
#include "server_privkey.der.inc"
};
#endif

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
#include CONFIG_NET_SAMPLE_PSK_HEADER_FILE
#endif

#endif /* __CERTIFICATE_H__ */
