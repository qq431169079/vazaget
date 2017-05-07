/*
 * ssl_vazaget.h
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  ssl_vazaget.h is part of vazaget.
 *
 *  vazaget is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  vazaget is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with vazaget.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SSL_VAZAGET_H_
#define SSL_VAZAGET_H_

#include "include_mbedtls/entropy.h"
#include "include_mbedtls/ctr_drbg.h"
#include "include_mbedtls/x509_crt.h"

/************SSL**************/

#define SSL_VERIFY_CERT_REQUIRED	2
#define SSL_VERIFY_CERT_OPTIONAL	1
#define SSL_VERIFY_CERT_NONE		0
#define SSL_DEFAULT_VERIFY_CERT		SSL_VERIFY_CERT_NONE /*0=none, 1=optional, 2=required*/
#define SSL_DEFAULT_DBG_FLAG		0

#define SSL_VER_SSL_3				0
#define SSL_VER_TLS_1_0				1
#define SSL_VER_TLS_1_1				2
#define SSL_VER_TLS_1_2				3
#define SSL_DEFAULT_MIN_VER			SSL_VER_SSL_3
#define SSL_DEFAULT_MAX_VER			SSL_VER_TLS_1_2
#define SSL_MAX_FORCE_CIPHERS		4

#define	EWOULDBLOCK	EAGAIN	/* Operation would block */

typedef struct
{
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_x509_crt cacert;
	mbedtls_ssl_config  conf;
	int cipher_list_to_set[SSL_MAX_FORCE_CIPHERS];
}global_ssl_params_t;
global_ssl_params_t global_ssl;

/*SSL*/

int ssl_net_send( void *ctx, const unsigned char *buf, size_t len );
int ssl_net_would_block( int fd );
int ssl_net_recv( void *ctx, unsigned char *buf, size_t len );
void init_ssl_cert();
uint ssl_init_ssl_to_new_fd(uint fd_idx);
void ssl_print_cipher_list();

#endif /* SSL_VAZAGET_H_ */
