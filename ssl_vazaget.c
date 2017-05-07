/* ssl_vazaget.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  ssl_vazaget.c is part of vazaget.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include "global.h"
#include "ssl_mbedtls.h"
#include "ssl_vazaget.h"
#include "config.h"

#define CA_CRT_EC_TEST                                                  \
		"-----BEGIN CERTIFICATE-----\r\n"                                       \
		"MIICUjCCAdegAwIBAgIJAMFD4n5iQ8zoMAoGCCqGSM49BAMCMD4xCzAJBgNVBAYT\r\n"  \
		"Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"  \
		"QyBDQTAeFw0xMzA5MjQxNTQ5NDhaFw0yMzA5MjIxNTQ5NDhaMD4xCzAJBgNVBAYT\r\n"  \
		"Ak5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UEAxMTUG9sYXJzc2wgVGVzdCBF\r\n"  \
		"QyBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABMPaKzRBN1gvh1b+/Im6KUNLTuBu\r\n"  \
		"ww5XUzM5WNRStJGVOQsj318XJGJI/BqVKc4sLYfCiFKAr9ZqqyHduNMcbli4yuiy\r\n"  \
		"aY7zQa0pw7RfdadHb9UZKVVpmlM7ILRmFmAzHqOBoDCBnTAdBgNVHQ4EFgQUnW0g\r\n"  \
		"JEkBPyvLeLUZvH4kydv7NnwwbgYDVR0jBGcwZYAUnW0gJEkBPyvLeLUZvH4kydv7\r\n"  \
		"NnyhQqRAMD4xCzAJBgNVBAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEcMBoGA1UE\r\n"  \
		"AxMTUG9sYXJzc2wgVGVzdCBFQyBDQYIJAMFD4n5iQ8zoMAwGA1UdEwQFMAMBAf8w\r\n"  \
		"CgYIKoZIzj0EAwIDaQAwZgIxAMO0YnNWKJUAfXgSJtJxexn4ipg+kv4znuR50v56\r\n"  \
		"t4d0PCu412mUC6Nnd7izvtE2MgIxAP1nnJQjZ8BWukszFQDG48wxCCyci9qpdSMv\r\n"  \
		"uCjn8pwUOkABXK8Mss90fzCfCEOtIA==\r\n"                                  \
		"-----END CERTIFICATE-----\r\n"

#define CA_CRT_RSA_TEST                                                 \
		"-----BEGIN CERTIFICATE-----\r\n"                                       \
		"MIIDhzCCAm+gAwIBAgIBADANBgkqhkiG9w0BAQUFADA7MQswCQYDVQQGEwJOTDER\r\n"  \
		"MA8GA1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwHhcN\r\n"  \
		"MTEwMjEyMTQ0NDAwWhcNMjEwMjEyMTQ0NDAwWjA7MQswCQYDVQQGEwJOTDERMA8G\r\n"  \
		"A1UEChMIUG9sYXJTU0wxGTAXBgNVBAMTEFBvbGFyU1NMIFRlc3QgQ0EwggEiMA0G\r\n"  \
		"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDA3zf8F7vglp0/ht6WMn1EpRagzSHx\r\n"  \
		"mdTs6st8GFgIlKXsm8WL3xoemTiZhx57wI053zhdcHgH057Zk+i5clHFzqMwUqny\r\n"  \
		"50BwFMtEonILwuVA+T7lpg6z+exKY8C4KQB0nFc7qKUEkHHxvYPZP9al4jwqj+8n\r\n"  \
		"YMPGn8u67GB9t+aEMr5P+1gmIgNb1LTV+/Xjli5wwOQuvfwu7uJBVcA0Ln0kcmnL\r\n"  \
		"R7EUQIN9Z/SG9jGr8XmksrUuEvmEF/Bibyc+E1ixVA0hmnM3oTDPb5Lc9un8rNsu\r\n"  \
		"KNF+AksjoBXyOGVkCeoMbo4bF6BxyLObyavpw/LPh5aPgAIynplYb6LVAgMBAAGj\r\n"  \
		"gZUwgZIwDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUtFrkpbPe0lL2udWmlQ/rPrzH\r\n"  \
		"/f8wYwYDVR0jBFwwWoAUtFrkpbPe0lL2udWmlQ/rPrzH/f+hP6Q9MDsxCzAJBgNV\r\n"  \
		"BAYTAk5MMREwDwYDVQQKEwhQb2xhclNTTDEZMBcGA1UEAxMQUG9sYXJTU0wgVGVz\r\n"  \
		"dCBDQYIBADANBgkqhkiG9w0BAQUFAAOCAQEAuP1U2ABUkIslsCfdlc2i94QHHYeJ\r\n"  \
		"SsR4EdgHtdciUI5I62J6Mom+Y0dT/7a+8S6MVMCZP6C5NyNyXw1GWY/YR82XTJ8H\r\n"  \
		"DBJiCTok5DbZ6SzaONBzdWHXwWwmi5vg1dxn7YxrM9d0IjxM27WNKs4sDQhZBQkF\r\n"  \
		"pjmfs2cb4oPl4Y9T9meTx/lvdkRYEug61Jfn6cA+qHpyPYdTH+UshITnmp5/Ztkf\r\n"  \
		"m/UTSLBNFNHesiTZeH31NcxYGdHSme9Nc/gfidRa0FLOCfWxRlFqAI47zG9jAQCZ\r\n"  \
		"7Z2mCGDNMhjQc+BYcdnl0lPXjdDK6V0qCg1dVewhUBcW5gZKzV7e9+DpVA==\r\n"      \
		"-----END CERTIFICATE-----\r\n"

const char test_cas_pem[] = CA_CRT_RSA_TEST CA_CRT_EC_TEST;
const uint test_cas_pem_len = sizeof( test_cas_pem );

extern void mbedtls_debug_set_threshold( int threshold );

static void ssl_debug( void *ctx, int level, const char *file, int line, const char *str )
{
	((void) level);
	fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
}

void ssl_set_force_ciphers_list(mbedtls_ssl_config *conf, char *force_ciphers_list, int *parsed_cipher_list)
{
	char *next_cipher_ptr = NULL;
	char *cur_cipher_ptr = force_ciphers_list;
	uint cipher_num = 0, ciphers_cntr=0;

	DBG_SSL PRINTF_VZ("start : force_ciphers_list=%s\n",force_ciphers_list);
	while (1)
	{
		cipher_num = (uint)strtoul (cur_cipher_ptr, &next_cipher_ptr, 16);
		if (!cipher_num)
		{/*invalid strtoul*/
			break;
		}
		if (!mbedtls_ssl_ciphersuite_from_id((int)cipher_num))
		{
			snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): unknown cipher number = 0x%x\n", FUNC_LINE, cipher_num);
			exit_vz(EXIT_FAILURE , exit_buf);
		}
		else
		{
			DBG_SSL PRINTF_VZ("setting cipher[%d]=0x%x\n",ciphers_cntr , cipher_num);
			parsed_cipher_list[ciphers_cntr] = (int)cipher_num;
			ciphers_cntr++;
		}

		if ((!next_cipher_ptr) || (next_cipher_ptr[0] != ',') || (ciphers_cntr == SSL_MAX_FORCE_CIPHERS))
		{/*no more ciphers*/
			break;
		}
		cur_cipher_ptr = next_cipher_ptr + 1;
		next_cipher_ptr = NULL;
	}

	mbedtls_ssl_conf_ciphersuites( conf, parsed_cipher_list );
	DBG_SSL PRINTF_VZ("Success setting %d ciphers\n",ciphers_cntr);
}

/*********************************/
/*ssl_init_ssl_to_new_fd()*/
/*********************************/
uint ssl_init_ssl_to_new_fd(uint fd_idx)
{
	int ret;

	/*SSL connection*/
	fd_db[fd_idx].ssl_db.is_ssl = 1;
	mbedtls_ssl_init(&fd_db[fd_idx].ssl_db.ssl);

	//#if defined(MBEDTLS_DEBUG_C)
	mbedtls_debug_set_threshold( cfg.int_v.ssl_debug_flag.val );
	//#endif

	if( ( ret = mbedtls_ssl_config_defaults( &global_ssl.conf,
			MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM,
			MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
	{
		DBG_SSL PRINTF_VZ( "Failed --> mbedtls_ssl_config_defaults returned 0x%x\n", ret );
		mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	mbedtls_ssl_conf_authmode( &global_ssl.conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
	mbedtls_ssl_conf_ca_chain( &global_ssl.conf, &global_ssl.cacert, NULL );
	mbedtls_ssl_conf_rng( &global_ssl.conf, mbedtls_ctr_drbg_random, &global_ssl.ctr_drbg );
	mbedtls_ssl_conf_dbg( &global_ssl.conf, ssl_debug, stdout );
	mbedtls_ssl_conf_min_version( &global_ssl.conf, MBEDTLS_SSL_MAJOR_VERSION_3, cfg.int_v.ssl_min_ver.val );
	mbedtls_ssl_conf_max_version( &global_ssl.conf, MBEDTLS_SSL_MAJOR_VERSION_3, cfg.int_v.ssl_max_ver.val );
	mbedtls_ssl_conf_renegotiation( &global_ssl.conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED );

	if (IS_STRING_SET(cfg.str_v.ssl_ciphers))
	{
		ssl_set_force_ciphers_list(&global_ssl.conf, cfg.str_v.ssl_ciphers, global_ssl.cipher_list_to_set);
	}

	if( ( ret = mbedtls_ssl_setup( &fd_db[fd_idx].ssl_db.ssl, &global_ssl.conf ) ) != 0 )
	{
		DBG_SSL PRINTF_VZ( "Failed --> mbedtls_ssl_setup returned 0x%x\n", ret );
		mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*in order to support SNI , need to activate mbedtls_ssl_set_hostname */

	char *hostname = get_dest_host_ptr(&cfg.dest_params);
	if (hostname)
	{
		DBG_SSL PRINTF_VZ("mbedtls: setting hostname = %s\n",hostname);
		if( ( ret = mbedtls_ssl_set_hostname( &fd_db[fd_idx].ssl_db.ssl, hostname ) ) != 0 )
		{
			DBG_SSL PRINTF_VZ( "Failed --> mbedtls_ssl_set_hostname returned 0x%x\n", ret );
			mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}

	mbedtls_ssl_set_bio( &fd_db[fd_idx].ssl_db.ssl, &fd_db[fd_idx].gen.fd, ssl_net_send, ssl_net_recv, NULL );

	while( ( ret = mbedtls_ssl_handshake( &fd_db[fd_idx].ssl_db.ssl ) ) != 0 )
	{
		if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
		{
			DBG_SSL PRINTF_VZ( "Failed --> mbedtls_ssl_handshake returned 0x%x\n", ret );
			mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}

	DBG_SSL PRINTF_VZ("mbedtls - (fd=%d , fd_db[fd_idx=%d].gen.fd=%d)ssl_handshake Done\n",fd_db[fd_idx].gen.fd , fd_idx ,fd_db[fd_idx].gen.fd);
	if (cfg.int_v.ssl_verify_cert.val > SSL_VERIFY_CERT_NONE)
	{
		uint32_t flags;
		/* In real life, we probably want to bail out when ret != 0 */
		if( ( flags = mbedtls_ssl_get_verify_result( &fd_db[fd_idx].ssl_db.ssl ) ) != 0 )
		{
			mbedtls_x509_crt_verify_info( exit_buf, EXIT_BUF_LEN , "  ! ", flags );
			DBG_SSL PRINTF_VZ_N ( "%s\n", exit_buf );
			if (cfg.int_v.ssl_verify_cert.val == SSL_VERIFY_CERT_REQUIRED)
			{
				exit_vz(EXIT_FAILURE, exit_buf);
			}
		}
	}

	DBG_SSL
	{
		PRINTF_VZ_N( "  [ Protocol is %s ]\n  [ Ciphersuite is (0x%x)%s ]\n",
				mbedtls_ssl_get_version( &fd_db[fd_idx].ssl_db.ssl ),
				mbedtls_ssl_get_ciphersuite_id(mbedtls_ssl_get_ciphersuite(&fd_db[fd_idx].ssl_db.ssl)),
				mbedtls_ssl_get_ciphersuite(&fd_db[fd_idx].ssl_db.ssl));

		if( ( ret = mbedtls_ssl_get_record_expansion( &fd_db[fd_idx].ssl_db.ssl ) ) >= 0 )
			PRINTF_VZ_N( "  [ Record expansion is %d ]\n", ret );
		else
			PRINTF_VZ_N( "  [ Record expansion is unknown (compression) ]\n" );


		PRINTF_VZ_N( "  [ Maximum fragment length is %u ]\n",
				(unsigned int) mbedtls_ssl_get_max_frag_len( &fd_db[fd_idx].ssl_db.ssl ) );

		const char *alp = mbedtls_ssl_get_alpn_protocol( &fd_db[fd_idx].ssl_db.ssl );
		PRINTF_VZ_N( "  [ Application Layer Protocol is %s ]\n",
				alp ? alp : "(none)" );

		if( mbedtls_ssl_get_peer_cert( &fd_db[fd_idx].ssl_db.ssl ) != NULL )
		{
			char tmp_buf[STRING_500_B_LENGTH];
			PRINTF_VZ_N( "\n");
			PRINTF_VZ_N( "  Peer certificate information :\n" );
			mbedtls_x509_crt_info( (char *) tmp_buf, sizeof( tmp_buf ) - 1, "      ",
					mbedtls_ssl_get_peer_cert( &fd_db[fd_idx].ssl_db.ssl ) );
			PRINTF_VZ_N( "%s", tmp_buf );
		}
		PRINTF_VZ_N( "\n");
	}
	return TRUE_1;
}

/*
 * Write at most 'len' characters
 */
int ssl_net_send( void *ctx, const unsigned char *buf, size_t len )
{
	int fd = *((int *) ctx);
	uint fd_idx = fd_to_fd_idx((uint)fd);
	int ret = 0;

	if (fd_idx == INIT_IDX)
	{
		PANIC_NO_DUMP(fd_idx == INIT_IDX);
	}

	/*block until get tx_rx mutex*/
	pthread_mutex_lock(&fd_db[fd_idx].gen.tx_rx_mutex);

	ret = (int) write( fd, buf, len );

	if( ret < 0 )
	{

		if( ssl_net_would_block( fd ) != 0 )
		{
			ret = MBEDTLS_ERR_SSL_WANT_WRITE;

		}

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
		!defined(EFI32)
		else if( WSAGetLastError() == WSAECONNRESET )
		{
			ret = POLARSSL_ERR_NET_CONN_RESET;
		}
#else
		else if( errno == EPIPE || errno == ECONNRESET )
		{
			ret = MBEDTLS_ERR_NET_CONN_RESET;
		}

		else if( errno == EINTR )
		{
			ret = MBEDTLS_ERR_SSL_WANT_WRITE;
		}
#endif
		else
		{
			ret = MBEDTLS_ERR_NET_SEND_FAILED;
		}
	}

	/*release tx_rx mutex*/
	pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);

	return( ret );
}

/*
 * Read at most 'len' characters
 */
int ssl_net_recv( void *ctx, unsigned char *buf, size_t len )
{
	int fd = *((int *) ctx);
	uint fd_idx = fd_to_fd_idx((uint)fd);
	int ret = 0;
	PANIC_NO_DUMP(fd_idx == INIT_IDX);

	/*block until get tx_rx mutex*/
	pthread_mutex_lock(&fd_db[fd_idx].gen.tx_rx_mutex);

	ret = (int) read( fd, buf, len );

	if( ret < 0 )
	{
		if( ssl_net_would_block( fd ) != 0 )
		{
			ret = MBEDTLS_ERR_SSL_WANT_READ;
		}

#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
		!defined(EFI32)
		else if( WSAGetLastError() == WSAECONNRESET )
		{
			ret = POLARSSL_ERR_NET_CONN_RESET;
		}
#else
		else if( errno == EPIPE || errno == ECONNRESET )

		{
			ret = MBEDTLS_ERR_NET_CONN_RESET ;
		}

		else if( errno == EINTR )
		{
			ret = MBEDTLS_ERR_SSL_WANT_READ;
		}
#endif
		else
		{
			ret = MBEDTLS_ERR_NET_RECV_FAILED ;
		}
	}

	/*release tx_rx mutex*/
	pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);

	return( ret );
}


/*********************************/
void init_ssl_cert()
{
	int ret;
	char *pers = "vazaget_client";

	if (cfg.int_v.port.val == DEFAULT_PORT)
	{/*set default SSL port*/
		cfg.int_v.port.val = DEFAULT_SSL_PORT;
	}

	DBG_SSL PRINTF_VZ("Starting init_ssl, port=%d\n", cfg.int_v.port.val);

	mbedtls_ssl_config_init( &global_ssl.conf);
	mbedtls_x509_crt_init( &global_ssl.cacert);
	mbedtls_ctr_drbg_init(&global_ssl.ctr_drbg);
	mbedtls_entropy_init( &global_ssl.entropy);

	DBG_SSL PRINTF_VZ("Seeding the random number generator...\n" );
	if( ( ret = mbedtls_ctr_drbg_seed( &global_ssl.ctr_drbg, mbedtls_entropy_func, &global_ssl.entropy,
			(const unsigned char *) pers,
			strlen( pers ) ) ) != 0 )
	{
		DBG_SSL PRINTF_VZ( "Failed --> mbedtls_ctr_drbg_seed returned 0x%x\n", ret );
		mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	DBG_SSL PRINTF_VZ("Loading the CA root certificate...\n" );

	if IS_STRING_SET(cfg.str_v.ca_path)
	{/*loading CA's from path*/
		ret = mbedtls_x509_crt_parse_path( &global_ssl.cacert, cfg.str_v.ca_path );
	}
	else if IS_STRING_SET(cfg.str_v.ca_file)
	{/*loading CA's from private file*/
		ret = mbedtls_x509_crt_parse_file( &global_ssl.cacert, cfg.str_v.ca_file );
	}
	else
	{/*use the default built in certificate*/
		ret = mbedtls_x509_crt_parse( &global_ssl.cacert, (const unsigned char *)test_cas_pem, test_cas_pem_len );
	}

	if( ret < 0 )
	{
		DBG_SSL PRINTF_VZ( "Failed --> mbedtls_x509_crt_parse returned 0x%x\n", ret );
		mbedtls_strerror( ret, exit_buf, EXIT_BUF_LEN );
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	DBG_SSL PRINTF_VZ("ok (%d skipped)\n", ret);
}

/*
 * Check if the requested operation would be blocking on a non-blocking socket
 * and thus 'failed' with a negative return value.
 *
 * Note: on a blocking socket this function always returns 0!
 */
int ssl_net_would_block( int fd )
{
	/*
	 * Never return 'WOULD BLOCK' on a non-blocking socket
	 */
	if( ( fcntl( fd, F_GETFL ) & O_NONBLOCK ) != O_NONBLOCK )
		return( 0 );

	switch( errno )
	{
#if defined EAGAIN
	case EAGAIN:
#endif
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
	case EWOULDBLOCK:
#endif
		return( 1 );
	}
	return( 0 );
}

/*********************************/
/*******ssl_print_cipher_list*****/
/*********************************/
void ssl_print_cipher_list()
{
	const int *list;
	char mbedtls_ssl_version_string[STRING_50_B_LENGTH];
	mbedtls_version_get_string_full(mbedtls_ssl_version_string);
	PRINTF_VZ_N ("mbedtls version = %s\n",mbedtls_ssl_version_string);
	PRINTF_VZ_N ("----------------------------\n");
	list = mbedtls_ssl_list_ciphersuites();
	while( *list )
	{
		PRINTF_VZ_N("[0x%04x] %s\n",*list, mbedtls_ssl_get_ciphersuite_name( *list ) );
		list++;
	}
	PRINTF_VZ_N ("----------------------------\n");
	exit_vz(EXIT_SUCCESS, NULL);
}

