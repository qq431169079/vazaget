/* global.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  global.h is part of vazaget.
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

#ifndef GLOBAL_H_
#define GLOBAL_H_

#include <arpa/inet.h>
#include <signal.h>
#include "parsers.h"
#include "buf_manager.h"
#include <pthread.h>
#include <sys/epoll.h>
#include <inttypes.h>
#include "include_mbedtls/platform.h"
#include "include_mbedtls/ssl.h"
#include "include_mbedtls/net.h"

#if 0 // seems like not in use any more
# if __WORDSIZE == 64
#include "/usr/lib/gcc/x86_64-linux-gnu/4.8/include/stddef.h"
#else
#include "/usr/lib/gcc/i686-linux-gnu/4.8/include/stddef.h"
#endif
#endif //if 0

#define VAZAGET_VERSION 				"0.39w"

# if __WORDSIZE == 64
#define BUILD_PLATFORM 				"_x64"
#else
#define BUILD_PLATFORM 				""
#endif

typedef enum {
	FALSE_0 = 	0,
	TRUE_1
}STATUS;
//#define TRUE_1  					(1)
//#define FALSE_0 					(0)

#define FALSE_100_NO_MORE_RANGES_TO_GET	(100)

#define HDR_STRING_LENGTH		500
#define MAX_FILE_NAME_LENGTH	500
#define MAX_COOKIE_LENGTH		1000
#define MAX_TX_BUF_LENGTH		2000
#define MAX_HTTP_PROTO_LENGTH	10
#define MAX_HTTP_PROTO_LENGTH	10
#define MAX_SSLID_LENGTH		1000
#define MAX_REAL_DST_SERVERS	50

#define MAXEVENTS 				64
#define DEFAULT_PORT			80
#define DEFAULT_SRC_PORT		0
#define DEFAULT_SSL_PORT		443
#define DEFAULT_TX_NUM_OF_THREADS 	10
#define DEFAULT_RX_NUM_OF_THREADS 	1
#define DEFAULT_TH_ACTIVE_SESS 	5
#define DEFAULT_NUM_OF_SESSIONS	1
#define DEFAULT_BW_RX_LIMIT		0
#define DEFAULT_BW_TX_LIMIT		0
#define DEFAULT_POST_UPLOAD		0
#define DEFAULT_TX_DELAY		0
#define DEFAULT_GET_DELAY		0
#define DEFAULT_CLOSE_DELAY		0
#define RCV_BUF_SIZE			10000

#define	NUM_OF_TIME_SLICES		10 /*10 stands for 10 * 100 msec slice = 1 sec */

#define INT_STRING_LENGTH		8
#define BOUNDERY_NUM_STRING_LENGTH	27
#define BOUNDERY_FULL_STRING_LENGTH	100

#define IPV4					AF_INET
#define IPV6					AF_INET6
#define	LOG_FILE_NAME			"vazaget_log.txt"
#define EOL_PRINT 				"\r\n"
#define PORT_STRING_LENGTH		10
#define SESSION_FINISH			0
#define SESSION_CONTINUE		1
#define NOTHING_TO_SEND			1

#define READ_NOT_DONE			0
#define READ_DONE				1

#define PR_STAT_READY			0
#define PR_STAT_FILLED			1

#define EPOLL_IN_ADDED			0
#define EPOLL_IN_REMOVED		1

#define BUF_GUARD_NUM			0xa1B2c3D4 /*use to verify we don't overflow on TX and RX BUFs*/

#define CUR_CHUNK_NOT_DONE_MORE_TO_BUFFER_2				2
#define CUR_CHUNK_DONE_CONTINUE_TO_NEXT_CHUNK_3			3
#define SUCCESS_FOUND_LAST_CHUNK_4						4

#define CHUNK_OPEN_CR_MAX_OFFSET						20

#define STRING_50_B_LENGTH 		50
#define STRING_100_B_LENGTH 	100
#define STRING_200_B_LENGTH 	200
#define STRING_500_B_LENGTH 	500
#define EXIT_BUF_LEN	STRING_500_B_LENGTH

#define WHILE_RET_NOTHING		0
#define WHILE_RET_CONTINUE		1
#define WHILE_RET_BREAK			2

#define CLEAR_DB_FULL			1
#define CLEAR_DB_PARTIAL		2

#define INIT_IDX				0xffffffff

#define CLOSE_SOCKET_CLEAR_DB	1
#define CLEAER_DB_ONLY			2
#define STOP_CLOSE_FLOW			3

/*** close ***/
#define THREAD_QUEUE_NAME		"/thread_queue"
#define LINUX_MAX_FD			100000
//#define CLOSE_THREAD_SHUTDOWN	0xffffffff

/*********MACROS*******/
#define FUNC_LINE	__FUNCTION__,__LINE__
/*macro for printf debug prints*/
#define DEBUG_PRINTVZ 1
#if defined (DEBUG_PRINTVZ) && (DEBUG_PRINTVZ > 0)
 #define PRINTF_VZ(fmt, args...) fprintf (stderr, "%s(%d):" fmt, FUNC_LINE, ##args)
#else
 #define PRINTF_VZ(fmt, args...) /* Don't do anything in release builds */
#endif

/*macro for printf normal prints*/
#define NORMAL_PRINTVZ 1
#if defined (NORMAL_PRINTVZ) && (NORMAL_PRINTVZ > 0)
 #define PRINTF_VZ_N(fmt, args...) fprintf(stderr, fmt, ##args)
#else
 #define PRINTF_VZ_N(fmt, args...) /* Don't do anything in release builds */
#endif

#define PENDING_TX_LEN(_fd_idx_) \
		(fd_db[_fd_idx_].tx.buf_length - fd_db[_fd_idx_].tx.buf_cur_position)

#define CUR_ACTIVE_SESSION	(cntr.stat.open_sockets - cntr.stat.close_sockets)

#define PANIC(_value_) ((_value_) ? (backtrace_disp((char *)__FUNCTION__ , __LINE__ , 1)) : (void) 0)
#define PANIC_NO_DUMP(_value_) ((_value_) ? (backtrace_disp((char *)__FUNCTION__ , __LINE__ , 0)) : (void) 0)

#define IS_STRING_SET(_ptr_) ((_ptr_) && (_ptr_[0]))
#define IS_PROXY(_fd_idx_) (IS_STRING_SET(fd_db[_fd_idx_].gen.dst_proxy.ip_addr_isolate_string))

#define ALIGN_8 __attribute__((aligned(8)))


/*********EXTERN*******/
extern char exit_buf[];

/*********GLOBALS*******/
uint  	max_active_sessions;
uint	tx_threshold;
uint	avg_bytes_per_slice;
int 	vaza_server_found;
char 	*elapse_time; /*pointer to the elapsed time string*/
char 	elapse_time_1[50];
char 	elapse_time_2[50];
uint 	shut_down_now;

/****params****/
uint 	ip_ver; /*need to be removed...*/

/****DEBUG**************/
/*DEBUG_FLAG */
#define DEBUG_FLAG_PARSER		0x0001
#define DEBUG_FLAG_CONFIG		0x0002
#define DEBUG_FLAG_TX			0x0004
#define DEBUG_FLAG_RX			0x0008
#define DEBUG_FLAG_DS			0x0010
#define DEBUG_FLAG_LISTENER		0x0020
#define DEBUG_FLAG_RANGE		0x0040
#define DEBUG_FLAG_CLOSE		0x0080
#define DEBUG_FLAG_SSL			0x0100
#define DEBUG_FLAG_BUF			0x0200



/*DEBUG_MACROS */
#define DBG 					if (cfg.dbg_v.dbg)
#define DBG_RX_PARSER			if ((cfg.dbg_v.dbg & DEBUG_FLAG_RX) || (cfg.dbg_v.dbg & DEBUG_FLAG_PARSER))
#define DBG_RX_TX				if ((cfg.dbg_v.dbg & DEBUG_FLAG_RX) || (cfg.dbg_v.dbg & DEBUG_FLAG_TX))
#define DBG_PARSER				if (cfg.dbg_v.dbg & DEBUG_FLAG_PARSER)
#define DBG_CONF				if (cfg.dbg_v.dbg & DEBUG_FLAG_CONFIG)
#define DBG_TX					if (cfg.dbg_v.dbg & DEBUG_FLAG_TX)
#define DBG_RX					if (cfg.dbg_v.dbg & DEBUG_FLAG_RX)
#define DBG_DS					if (cfg.dbg_v.dbg & DEBUG_FLAG_DS)
#define DBG_LISTEN				if (cfg.dbg_v.dbg & DEBUG_FLAG_LISTENER)
#define DBG_RANGE				if (cfg.dbg_v.dbg & DEBUG_FLAG_RANGE)
#define DBG_CLOSE				if (cfg.dbg_v.dbg & DEBUG_FLAG_CLOSE)
#define DBG_SSL					if (cfg.dbg_v.dbg & DEBUG_FLAG_SSL)
#define DBG_BUF					if (cfg.dbg_v.dbg & DEBUG_FLAG_BUF)
#define DBG_ALL					if (cfg.dbg_v.dbg & DEBUG_FLAG_ALL)

/*debug flag to send some prints to file */
#define DBG_TO_FILE				1
#define DBG_FILE				if(DBG_TO_FILE)
#define	CHUNK_DBG_FILE			"chunk_dbg"
#define DEBUG_BUF_SIZE			1000



/***********COUNTERS - START****************/
typedef struct
{
	sig_atomic_t last_rx_th_idx;
	sig_atomic_t close_sockets;
	sig_atomic_t open_sockets;
	sig_atomic_t TX_threads;
	sig_atomic_t TX_bytes;
	sig_atomic_t TX_M_bytes;
	sig_atomic_t RX_bytes;
	sig_atomic_t RX_M_bytes;
	sig_atomic_t http_chunks;

	sig_atomic_t srcIP_diff;
	sig_atomic_t srcPort_diff;
	sig_atomic_t dstPort_diff;
	sig_atomic_t http_proto_diff;

	sig_atomic_t cookie_2_real_match;
	sig_atomic_t cookie_2_real_non_match;

	sig_atomic_t post_upload_susscess;
	sig_atomic_t post_upload_fail;

	sig_atomic_t get_requests;
	sig_atomic_t post_requests;
	sig_atomic_t gzip_reply;
	sig_atomic_t http_1xx;
	sig_atomic_t http_2xx;
	sig_atomic_t http_3xx;
	sig_atomic_t http_4xx;
	sig_atomic_t http_5xx;
	sig_atomic_t http_unknown_ret_value;
	sig_atomic_t http_replies_total;

	sig_atomic_t range_pending_bufs;
}cntr_stat_t;


typedef struct
{
	sig_atomic_t closing_upon_http_connection_close;
	sig_atomic_t range_pending_to_write_in_close;
	sig_atomic_t skip_read_from_socket_due_to_mutex_lock;
	sig_atomic_t range_repending_buf_via_timer;
	sig_atomic_t range_pending_move_to_timer_handle;
	sig_atomic_t range_config_disabled;
	sig_atomic_t server_close_by_FIN;
	sig_atomic_t server_close_by_RST;
	sig_atomic_t range_restart;
	sig_atomic_t range_restart_unfinished_range;
	sig_atomic_t range_rx_restart;
	sig_atomic_t close_skip_shutdown;
	sig_atomic_t rcv_buf_full_write_to_disk;
	sig_atomic_t http_parser_line_start_with_tab;
	sig_atomic_t http_parser_reached_html;
	sig_atomic_t http_parser_unknon_header_line;
	sig_atomic_t range_wrote_buf_to_disk;
	sig_atomic_t server_not_support_range;

	sig_atomic_t tmp_range_select_restart;
	sig_atomic_t tmp_remove_fd_from_epoll;
	sig_atomic_t tmp_failed_tx_mutex_lock;
	sig_atomic_t tmp_rearm_tx_from_queue_thread;
	sig_atomic_t tmp_rcv_bytes_0;
	sig_atomic_t tmp_close_content_complete;
	sig_atomic_t tmp_finish_but_more_to_read;
	sig_atomic_t tmp_clsoe_fd_db_start;
	sig_atomic_t tmp_wake_up_tx;
	sig_atomic_t tmp_result_sess_finish;
	sig_atomic_t tmp_finished_read_from_sock;
	sig_atomic_t tmp_range_wrote_to_disk_via_rx;
	sig_atomic_t tmp_range_write_pending_buf_via_timer;
	sig_atomic_t tmp_range_stuck_socket;
	sig_atomic_t tmp_delay_range_tx;
	sig_atomic_t tmp_read_err_eAgain;
	sig_atomic_t tmp_large_slice_delta;
	sig_atomic_t tmp_clsoe_clear_db_full;
	sig_atomic_t tmp_clsoe_clear_db_partial;

}cntr_info_t;


typedef struct
{
	sig_atomic_t align_close_cntr;
	sig_atomic_t range_unknown_close_action;
	sig_atomic_t failed_writing_to_disk;
	sig_atomic_t unknow_close_reason;
	sig_atomic_t dst_ip_match_not_found;
	sig_atomic_t dst_port_match_not_found;
	sig_atomic_t max_chunks_on_single_buf;
	sig_atomic_t chunk_failed_parse_open_CR_long_offset;
	sig_atomic_t chunk_failed_parse_close_CR_offsset;
	sig_atomic_t chunk_failed_parse_illegal_strtoul;
	sig_atomic_t chunk_failed_malloc;
	sig_atomic_t chunk_buf_reached_max_size;
	sig_atomic_t chunk_first_char_is_not_digit;
	sig_atomic_t chunk_stop_processing;
	sig_atomic_t parser_reached_max_lines;
	sig_atomic_t parser_reached_max_cookies;
	sig_atomic_t max_saved_cookies;
	sig_atomic_t html_parser_reached_max_tags;
	sig_atomic_t cookie_string_too_long;
	sig_atomic_t try_remove_fd_which_not_in_use;
	sig_atomic_t failed_to_read_content_length;
	sig_atomic_t gzip_inflate_error;
	sig_atomic_t Illegal_cur_slice;
	sig_atomic_t Illegal_rcv_size_per_slice;
	sig_atomic_t reached_max_dst_ips;
	sig_atomic_t reached_max_dst_ports;
	sig_atomic_t calc_snd_size_larger_then_pending_tx;
	sig_atomic_t try_to_read_write_from_closing_socket;
	sig_atomic_t send_new_pkt_while_pending_tx;
	sig_atomic_t range_stuck_force_restart;
	sig_atomic_t double_close;
	sig_atomic_t epoll_hangup_on_unused_fd_in_state_ready;
	sig_atomic_t epoll_hangup_on_unused_fd_in_state_close;
	sig_atomic_t close_by_server;
	sig_atomic_t post_not_found_in_200OK;
	sig_atomic_t epoll_add_ret_errno;
}cntr_warning_t;


typedef struct
{
	sig_atomic_t failed_to_match_fd_to_fd_idx;
	sig_atomic_t fd_idx_already_in_use;
	sig_atomic_t try_to_add_illegal_fd;
	sig_atomic_t try_to_read_illegal_fd;
	sig_atomic_t Illegal_fd_idx;
	sig_atomic_t failed_to_add_fd_idx;

	sig_atomic_t create_new_fd_db;
	sig_atomic_t create_new_fd_db_sock_reuse;
	sig_atomic_t failed_establish_connection;
	sig_atomic_t tx_create_new_request;
	sig_atomic_t Illegal_fd_to_close;
	sig_atomic_t unknown_clear_db_level;

	sig_atomic_t sock_error;
	sig_atomic_t connect_error;
	sig_atomic_t close_error;
	sig_atomic_t send_error;
	sig_atomic_t inet_pton_error;
	sig_atomic_t read_error;
	sig_atomic_t epoll_error;
	sig_atomic_t illegal_fd_to_close;
	sig_atomic_t failed_to_send_data_to_queue_thread;
	sig_atomic_t failed_to_update_range_priority;
	sig_atomic_t unknown_msg_q_code;
}cntr_error_t;


typedef struct
{
	cntr_stat_t stat;
	cntr_info_t info;
	cntr_warning_t warning;
	cntr_error_t error;
}cntr_t;
cntr_t cntr;

/***********COUNTERS - END****************/
typedef struct
{
	uint	sec_to_wait;
	uint	expire_sec;
	uint	expire_100m_slice;
}ds_cmd_wait_t;

typedef struct
{
	uint			cur_cmd;
	uint			new_cmd;
	char 			*phrase_start;
	uint			phrase_length;
	uint			cur_line;
	uint 			cur_position;
	ds_cmd_wait_t 	ds_cmd_wait;
}fd_ds_db_t;

/****Timer**************/
typedef struct
{
	uint	sec;
	uint 	slice_10_msec;
	uint 	slice_100_msec;
}time_struct_t;
time_struct_t run_time;

/****URI parser struct**************/
typedef struct
{
	char	orig_full_uri[HDR_STRING_LENGTH+1];
	char	trashed_uri[HDR_STRING_LENGTH+1];
	char 	ip_addr_isolate_string[INET6_ADDRSTRLEN+1];
	char 	ip_addr_isolate_binary[sizeof(struct in6_addr)];
	uint	ip_ver;
	uint	port;
	char 	*protocol_ptr;
	char 	*www_addr_ptr;
	char 	*ip_addr_ptr;
	char 	*port_ptr;
	char 	*path_ptr;
	char 	*file_name_ptr;
}uri_parser;



/************DST_IP**************/
typedef struct
{
	char ip_string[INET6_ADDRSTRLEN+1];
	sig_atomic_t dstIP_diff_cntr;
}srv_dst_ip_struct;
srv_dst_ip_struct srv_dst_ip[MAX_REAL_DST_SERVERS+1];

/************DST_PORT**************/
typedef struct
{
	char port_string[PORT_STRING_LENGTH+1];
	sig_atomic_t dstPort_diff_cntr;
}srv_dst_port_struct;
srv_dst_port_struct srv_dst_port[MAX_REAL_DST_SERVERS+1];

/*********BWR*********/

typedef struct
{
	uint				slice_limit;
	uint				slice_usage;
}bw_Rx_limit;
bw_Rx_limit global_default_bwR[NUM_OF_TIME_SLICES];

/*********BWT*********/
typedef struct
{
	uint				slice_limit;
	uint				slice_usage;
}bw_Tx_limit;
bw_Tx_limit global_default_bwT[NUM_OF_TIME_SLICES];


/*********FD_DB - START*********/
typedef struct
{
	bw_Rx_limit		bwR[NUM_OF_TIME_SLICES];	/*holding the BW RX limitations and useage per slice of 100msec*/
	uint			last_second;
	uint				last_slice;
}fd_bwRx_t;

typedef struct
{
	bw_Tx_limit		bwT[NUM_OF_TIME_SLICES];	/*holding the BW RX limitations and useage per slice of 100msec*/
	uint			last_second;
	uint				last_slice;
}fd_bwTx_t;

typedef struct
{
	uint 			rcv_buf_usage; /*Bytes, we cannot use strlen since we parser insert \0 which terminate  the lines, and strlen then give false length*/
	parser_struct 	parsed_msg;
}fd_parser_t;

typedef struct
{
	uint			buf_length; /*holds the length of the packet to be send*/
	uint			buf_cur_position; /*holds the current TX position, mainly in use in case we didn't managed to send all packet*/
	uint			tx_th_idx;
	uint			tx_state;
	uint 			lock_failure_slice; /*keep the last lock failure slice, so we try take lock again in the next slice only*/
}fd_tx_t;

typedef struct
{
	uint 			size_of_buf; /*size of malloced buf*/
	uint 			buf_usage; /*how much bytes on the buf are used , IMPORTANT - this is 1 base, to get the real offset on buf you need to -1*/
	uint 			last_parsed_ch; /*index of the last parsed ch*/
	uint 			cur_chunk_length; /*the cur chunk length*/
	uint 			cur_chunk_parse_state; /*parsing chunk state*/
	uint 			cur_chunk_data_start_offset;
	uint			cur_chunk_data_end_offset;
	uint 			cur_chunk_trailer_end_offset;
}chunk_t;

typedef struct
{
	uint 			extracted_bytes;
}gzip_t;

typedef struct
{
	uint64_t 		*range_start; /*range_start offset*/
	uint64_t		*range_end; /*range_end offset*/
	uint 			local_range_block_size; /*requires for dynamic block allocations*/
	uint 			range_cur_length; /*the cur range length - or in other words - how much bytes did we receive on range so far*/
	uint 			pending_range_to_write; /*All range collected and wait to be written*/
	char 			wrote_first_payload_from_http_end; /*mark that forst payload wrote from http end, so next payloads should be written as is*/
	char			new_get_request;
	uint 			last_1_sec_rx_bytes; /*count how much bytes did we received on this range in the last sec. required to verify the range is not stuck from some reason*/
	uint 			last_2_sec_rx_bytes; /*count how much bytes did we received on this range in the last sec. required to verify the range is not stuck from some reason*/
	uint 			last_3_sec_rx_bytes; /*count how much bytes did we received on this range in the last sec. required to verify the range is not stuck from some reason*/
	uint 			displayed_last_KBytes_per_sec;
	time_struct_t	start_rx_time; /*keep the time we started recieve data, so we can calculate the bit rate*/
	time_struct_t	finish_rx_time; /*keep the time we started recieve data, so we can calculate the bit rate*/
}range_t;

typedef struct
{
	uint 			rx_th_idx; /*associated RX thread*/
	uint64_t		bytes_to_rcv;
	uint64_t		rcv_bytes; /*counting the received Bytes on socket, remember it can be compressed, so after decompress it rcv_buf_usage will grow */
	char 			respone_fully_rcv;
	char			buffer_full;
	char			wrote_buf_to_disk; /*flag to mark that we wrote buf to disk*/
	char 			wrote_buf_from_http_end;/*flag to mark that we wrote the first buf from http->end, the rest of the buffers will be concatenated completely*/
	uint			close_time; /*set the close time in sec., once arrived it will be close*/
	uint 			epoll_state;
	uint			epoll_arm_events;
	chunk_t			chunk;
	range_t			range;
	gzip_t			gzip;
}fd_rx_t;

typedef struct
{
	uint			buf_guard_1;
	char 			tx_buf[MAX_TX_BUF_LENGTH+1];
	uint			buf_guard_2;
	char 			rcv_buf[RCV_BUF_SIZE+1];
	uint			buf_guard_3;
	char 			*rcv_buf_untouched; /*keep the untouched rcv payload, before parser trashes it, for now it's in use for the DS only, so only then it'll be calloced*/
	uint			buf_guard_4;
	char 			*extract_buf; /*extract_buf - will be allocated only for gzip sessions, to extract payload (maybe will need use it to ssl also) */
	uint			buf_guard_5;
	char			*file_name_rcv_buf/*[MAX_FILE_NAME_LENGTH+1]*/; /*write the rcv payload to disk, will be in use only in case the rcv_buf is full receive data*/
	uint			buf_guard_6;
	char 			*chunk_buf; /*chunk_buf , allocated OTF, upon receiving chunks - will be allocated only for chunked buffers, where need to strip the start and end of every buf */
	uint			buf_guard_7;
	char 			*range_buf; /*range buf is used for tmp buffering of the range recevied buffer */
	uint			buf_guard_8;
}fd_buf_t;

typedef struct
{
	char 			client_src_ip[INET6_ADDRSTRLEN+1];
	char 			client_src_port[PORT_STRING_LENGTH+1];
	char 			client_dst_ip[INET6_ADDRSTRLEN+1];
	char 			client_dst_port[PORT_STRING_LENGTH+1];
	char 			client_http_proto[MAX_HTTP_PROTO_LENGTH+1];
}fd_client_t;

typedef struct
{
	char				is_ssl;
	mbedtls_ssl_context	ssl;
	mbedtls_net_context server_fd;
}fd_ssl_db_t;

typedef struct
{
	sig_atomic_t 	fd;
	uint			state;
	sig_atomic_t 	in_use; /*keep the in_use as the last value in the struct, so memset will zero it last*/
	pthread_mutex_t tx_rx_mutex; /*this mutex uses to synchronize between RX and TX threads, required due to race conditions between RX and TX*/
	ushort			src_port;
	ushort			dst_port;
	uint				ip_ver;
	struct sockaddr_in server_v4;
	struct sockaddr_in6 server_v6;
	uri_parser		dst_direct;
	uri_parser 		dst_proxy;
}fd_gen_t;

typedef struct
{
	char 			*cookie_ptr;
	uint 			cookie_alloc_length;
}cookie_struct_t;

typedef struct
{
	char 			last_real_srv_dst_ip[INET6_ADDRSTRLEN+1];
	cookie_struct_t cookie_struct[MAX_PARSED_COOKIES];
	uint			session_cntr;
}fd_non_delete_t;

typedef struct
{
	fd_gen_t		gen; /*general fd values*/
	fd_buf_t		buf;
	fd_tx_t			tx;
	fd_rx_t			rx;
	fd_client_t		client;
	fd_bwRx_t		bwRx;
	fd_bwTx_t		bwTx;
	fd_parser_t		parser;
	fd_ssl_db_t		ssl_db;
	fd_ds_db_t			ds_db;
	fd_non_delete_t	non_del;
}fd_db_t;
fd_db_t *fd_db;

/*********FD_DB - END*********/

/****CONFIGURATION - START**************/
typedef struct
{
	int val;
	int config_mode;
}param_int_struct;

typedef struct
{
	param_int_struct 	display_counters;
	param_int_struct 	port;
	param_int_struct 	src_port;
	param_int_struct 	num_of_session;
	param_int_struct 	tx_num_of_threads;
	param_int_struct 	tx_th_active_sessions;
	param_int_struct 	rx_num_of_threads;
	param_int_struct 	bw_rx_limit;
	param_int_struct 	bw_TX_limit;
	param_int_struct 	post_upload;
	param_int_struct 	delay_tx_sec;
	param_int_struct 	delay_get_sec;
	param_int_struct 	delay_close_sec;
	param_int_struct 	range_size;
	param_int_struct    ssl_verify_cert;
	param_int_struct 	ssl_debug_flag;
	param_int_struct 	ssl_min_ver;
	param_int_struct 	ssl_max_ver;
	param_int_struct 	debug;
}int_val;


typedef struct
{
	char 	note_string[MAX_FILE_NAME_LENGTH+1];
	char 	cookie_string_cli[MAX_COOKIE_LENGTH+1];
	char 	proxy_addr[INET6_ADDRSTRLEN+1];
	char 	data_sender[MAX_FILE_NAME_LENGTH+1];
	char 	ua[MAX_FILE_NAME_LENGTH+1]; /*ua = user agent*/
	char 	ssl_ciphers[STRING_100_B_LENGTH]; /*ssl ciphers list*/
	char 	ca_file[MAX_FILE_NAME_LENGTH + 1]; /*CAs file*/
	char 	ca_path[MAX_FILE_NAME_LENGTH + 1]; /*CAs path */
}str_val;


typedef struct
{
	int val;
	int config_mode;
}param_flag_struct;

typedef struct
{
	param_flag_struct 	version;
	param_flag_struct 	ssl;
	param_flag_struct 	encoding_gzip;
	param_flag_struct 	close_by_rst;
	param_flag_struct 	close_by_server;
	param_flag_struct 	cookie_from_reply;
	param_flag_struct 	cookie_reply_2;
	param_flag_struct 	cookie_wait;
	param_flag_struct 	http_parse_test;
	param_flag_struct 	socket_resue;
	param_flag_struct   chunks_dis;
	param_flag_struct 	save_to_file;
	param_flag_struct 	range;
	param_flag_struct 	range_on_mem;
	param_flag_struct 	close_thread_dis;
	param_flag_struct 	ssl_cipher_list;
	param_flag_struct	php_file;
	param_flag_struct 	help_menu;
	param_flag_struct 	help_ds;
}flags_val;

typedef struct
{
	int 	dbg;
}debug;

typedef struct
{
	char 	ip_addr[INET6_ADDRSTRLEN+1];
	char 	www_addr[HDR_STRING_LENGTH+1];
}dest_proxy_val;

typedef struct
{
	int_val 		int_v;
	str_val 		str_v;
	flags_val 		flag;
	debug			dbg_v;
	uri_parser		dest_params;
	uri_parser		dest_proxy_params;
}configuration_params;
configuration_params cfg;

/****CONFIGURATION - END**************/

/*States*/
typedef enum {
	STATE_READY,
	STATE_CONNECTION_ESTABLISHED,
	STATE_SENT_GET,
	STATE_SENT_POST,
	STATE_CLOSE,
	STATE_MAX
}STATES;

typedef struct
{
	int state;
	char *name;
}state_description;

/**********FUNCTIONS*************/
/*Global*/
void shutdown_now();
void set_my_thread_to_highes_priority();
uint fd_to_fd_idx(uint fd);
void timer_threads_creator();
void exit_vz(int exit_code, char* string_to_print);
void backtrace_disp(char *func , int line, int create_core_dump);

/**********buf_manager*************/
#define BUF_TRACE_SIZE	5

typedef struct buf_element_t
{
	uint64_t				*buf;
	uint64_t				max_size;
	uint64_t				cur_size;
	uint32_t				trace[BUF_TRACE_SIZE];
	char 					trace_extra_info[BUF_TRACE_SIZE][STRING_100_B_LENGTH];
	uint32_t				cur_trace_idx;
	struct buf_element_t 	*before;
	struct buf_element_t 	*next;
}buf_element_t;

void buf_free_alloc_all_buffers();
STATUS buf_return(buf_element_t *buf, char *file, uint line);
buf_element_t *buf_get(uint64_t required_buf_size , char *file, uint line);

#endif

/* GLOBAL_H_ */

