/* prints.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  prints.c is part of vazaget.
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
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include "global.h"
#include "config.h"
#include "rx.h"
#include "rx_range.h"
#include "prints.h"

#define SLIDE_BAR_LENGTH	/*75*/ 65
#define MAX_BPS_STRING_LEN	20
#define GIGA_BYTE	1000000000
#define MEGA_BYTE	1000000
#define KILO_BYTE	1024

uint ip_length_display = 0;
uint cntr_length_display = 0;
uint cps_avg_total = 0;
uint cps_1_sec = 0;
uint cps_5_sec = 0;

uint64_t rx_Bps_1_sec = 0;
uint64_t rx_Bps_5_sec = 0;
uint rx_Bps_total = 0;

uint64_t tx_Bps_1_sec = 0;
uint64_t tx_Bps_5_sec = 0;
uint tx_Bps_total = 0;

extern time_t starting_time;
extern time_t ending_time;
extern struct timespec start_time;
extern char original_full_command[];
extern char errno_exit_buf[EXIT_BUF_LEN];
/*********************************/
void calc_print_columns_length()
{
	uint ip_length = 0 , i;
	uint cntr_length = 0;
	char cntr_string[20] = {0};
	ip_length = (uint)strlen (last.client_src_ip);
	if (ip_length > ip_length_display)
	{
		ip_length_display = ip_length;
	}

	ip_length = (uint)strlen(last.client_dst_ip);
	if (ip_length > ip_length_display)
	{
		ip_length_display = ip_length;
	}

	sprintf (cntr_string , "%d" , cntr.stat.srcIP_diff);
	cntr_length = (uint)strlen(cntr_string);
	if (cntr_length > cntr_length_display)
	{
		cntr_length_display = cntr_length;
	}

	sprintf (cntr_string , "%d" , cntr.stat.srcPort_diff);
	cntr_length = (uint)strlen(cntr_string);
	if (cntr_length > cntr_length_display)
	{
		cntr_length_display = cntr_length;
	}

	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (!(srv_dst_ip[i].ip_string[0]))
			break;

		sprintf (cntr_string , "%d" , srv_dst_ip[i].dstIP_diff_cntr);
		cntr_length = (uint)strlen(cntr_string);
		if (cntr_length > cntr_length_display)
		{
			cntr_length_display = cntr_length;
		}
	}

	sprintf (cntr_string , "%d" , cntr.stat.dstPort_diff);
	cntr_length = (uint)strlen(cntr_string);
	if (cntr_length > cntr_length_display)
	{
		cntr_length_display = cntr_length;
	}
	return;
}

/*********************************/
/*calc_cps()*/
/*called every 1 sec*/
/*********************************/
void calc_cps()
{
	static uint cntr_5_sec = 0 ;
	uint i;


	static uint last_1_sec_close_sockets = 0;
	static uint last_5_sec_close_sockets[5] = {0,0,0,0,0};
	uint cps_tot_5_sec = 0;

	static uint last_1_sec_RX_Bytes = 0;
	static uint last_1_sec_RX_M_Bytes = 0;
	static uint64_t last_5_sec_RX_Bytes[5] = {0,0,0,0,0};
	uint64_t rx_Bytes_tot_5_sec = 0;

	static uint last_1_sec_TX_Bytes = 0;
	static uint last_1_sec_TX_M_Bytes = 0;
	static uint64_t last_5_sec_TX_Bytes[5] = {0,0,0,0,0};
	uint64_t tx_Bytes_tot_5_sec = 0;

	if (run_time.sec)
	{
		/***CPS***/
		/*avg total*/
		cps_avg_total =(uint)cntr.stat.close_sockets / run_time.sec;

		/*1 sec*/
		cps_1_sec = (uint)cntr.stat.close_sockets - last_1_sec_close_sockets;
		last_1_sec_close_sockets = (uint)cntr.stat.close_sockets;

		/*5 sec avg*/
		last_5_sec_close_sockets[cntr_5_sec] = cps_1_sec;

		for (i=0 ; i<5 ; i++)
		{
			cps_tot_5_sec += last_5_sec_close_sockets[i];
		}
		cps_5_sec = cps_tot_5_sec / 5;

		/*** RX BPS ***/
		/*RX_bytes_per_sec*/

		rx_Bps_1_sec = ((((uint)cntr.stat.RX_M_bytes - last_1_sec_RX_M_Bytes) * 1000000) + ((uint)cntr.stat.RX_bytes - last_1_sec_RX_Bytes));
		last_1_sec_RX_Bytes = (uint)cntr.stat.RX_bytes;
		last_1_sec_RX_M_Bytes = (uint)cntr.stat.RX_M_bytes;

		/*5 sec avg*/
		last_5_sec_RX_Bytes[cntr_5_sec] = rx_Bps_1_sec;
		for (i=0 ; i<5 ; i++)
		{
			rx_Bytes_tot_5_sec += last_5_sec_RX_Bytes[i];
		}
		rx_Bps_5_sec = rx_Bytes_tot_5_sec / 5;

		/*** TX BPS ***/
		/*TX_bytes_per_sec*/
		tx_Bps_1_sec = ((((uint)cntr.stat.TX_M_bytes - last_1_sec_TX_M_Bytes) * 1000000) + ((uint)cntr.stat.TX_bytes - last_1_sec_TX_Bytes));
		last_1_sec_TX_Bytes = (uint)cntr.stat.TX_bytes;
		last_1_sec_TX_M_Bytes = (uint)cntr.stat.TX_M_bytes;

		/*5 sec avg*/
		last_5_sec_TX_Bytes[cntr_5_sec] = tx_Bps_1_sec;
		for (i=0 ; i<5 ; i++)
		{
			tx_Bytes_tot_5_sec += last_5_sec_TX_Bytes[i];
		}
		tx_Bps_5_sec = tx_Bytes_tot_5_sec / 5;

		/*update the 5 sec counter*/
		cntr_5_sec++;
		if (cntr_5_sec == 5)
		{
			cntr_5_sec = 0;
		}
	}
}

/*********************************/
void create_slide_bar_with_string(char *dst_buf , char *src_buf , char *string , uint buf_length)
{
	uint middle_bar = (buf_length / 2);
	uint string_length = (uint)strlen(string);
	if (((middle_bar + string_length) < buf_length) && (string_length > 0))
	{/*verify we not overflow*/
		sprintf(dst_buf , "%s" , src_buf);
		memcpy (&dst_buf[middle_bar - (string_length/2)], string  , string_length); /*do this trick in order to remove the terminated null*/
	}
	else
	{
		sprintf(dst_buf , "%s" , src_buf);
	}
}

/*********************************/
void create_slide_bar(char *buf , int cur_prcent , int buf_length)
{
	int i;
	//    int cur_prcent = (cur_val * 100) / max_val;

	int print_sign = (buf_length * cur_prcent) / 100;
	for (i=0 ; i<buf_length ; i++)
	{
		if (i < print_sign)
		{
			sprintf (&buf[i] , ">");
		}
		else
		{
			sprintf (&buf[i] , "-");
		}
	}
}

//char ret_string[MAX_BPS_STRING_LEN + 1];
/*********************************/
char *create_bytes_string(char *ret_string , uint gb , uint mb ,uint kb , uint b , uint len_limit, char *base_unit)
{
	uint disp_gb = gb;
	uint disp_mb = mb;
	uint disp_kb = kb;
	uint disp_b = b;

	char tmp[MAX_BPS_STRING_LEN + 1] = {'\0'};
	char tmp_2[MAX_BPS_STRING_LEN + 1] = {'\0'};
	char tmp_after_point[MAX_BPS_STRING_LEN + 1] = {'\0'}; /*seems like snprintf cannot trim the uint length, use this string to trim length after point...*/


	if (len_limit > MAX_BPS_STRING_LEN)
	{
		len_limit = MAX_BPS_STRING_LEN;
	}

	/*B*/
	if (disp_b >= KILO_BYTE)
	{
		disp_kb += (disp_b / KILO_BYTE);
		disp_b = (disp_b % KILO_BYTE);
	}

	/*KB*/
	if (disp_kb >= 1000)
	{
		disp_mb += (disp_kb / 1000);
		disp_kb = (disp_kb % 1000);
	}

	/*MB*/
	if (disp_mb > 1000)
	{
		disp_gb += (disp_mb / 1000);
		disp_mb = (disp_mb % 1000);
	}

	/*build the string*/
	if (disp_gb)
	{
		snprintf(tmp_after_point , 3 , "%u" , disp_mb);
		snprintf(tmp , MAX_BPS_STRING_LEN , "%u.%s" , disp_gb , tmp_after_point);
		snprintf(tmp_2 , MAX_BPS_STRING_LEN , "G%s",base_unit);
	}
	else if (disp_mb)
	{
		snprintf(tmp_after_point , 3 , "%u" , disp_kb);
		snprintf(tmp , MAX_BPS_STRING_LEN , "%u.%s" , disp_mb , tmp_after_point);
		snprintf(tmp_2 , MAX_BPS_STRING_LEN , "M%s",base_unit);
	}
	else if (disp_kb)
	{
		snprintf(tmp_after_point , 3 , "%u" , disp_b);
		snprintf(tmp , MAX_BPS_STRING_LEN , "%u.%s" , disp_kb , tmp_after_point);
		snprintf(tmp_2 , MAX_BPS_STRING_LEN , "K%s",base_unit);
	}
	else
	{
		snprintf(tmp , MAX_BPS_STRING_LEN , "%u" , disp_b);
		snprintf(tmp_2 , MAX_BPS_STRING_LEN , " %s",base_unit);
	}

	snprintf(ret_string , len_limit , "%-6s %s" , tmp , tmp_2);

	return ret_string;
}

/*********************************/
void create_TX_bytes_string(char *TX_bytes_string , uint length)
{
	char sec_1_string[MAX_BPS_STRING_LEN + 1];
	char sec_5_string[MAX_BPS_STRING_LEN + 1];
	char tot_string[MAX_BPS_STRING_LEN + 1];

	snprintf(TX_bytes_string , length , "1sec=%s | 5sec=%s | Tot=%s",
			create_bytes_string(sec_1_string,0,0,0,(uint)tx_Bps_1_sec,length , "Bps") ,
			create_bytes_string(sec_5_string,0,0,0,(uint)tx_Bps_5_sec,length , "Bps") ,
			create_bytes_string(tot_string,0,(uint)cntr.stat.TX_M_bytes,0,(uint)cntr.stat.TX_bytes,length , "Byte"));
}

/*********************************/
void create_RX_bytes_string(char *RX_bytes_string , uint length)
{
	char sec_1_string[MAX_BPS_STRING_LEN + 1];
	char sec_5_string[MAX_BPS_STRING_LEN + 1];
	char tot_string[MAX_BPS_STRING_LEN + 1];

	snprintf(RX_bytes_string , length , "1sec=%s | 5sec=%s | Tot=%s" ,
			create_bytes_string(sec_1_string , 0,0,0,(uint)rx_Bps_1_sec,length , "Bps") ,
			create_bytes_string(sec_5_string , 0,0,0,(uint)rx_Bps_5_sec,length , "Bps") ,
			create_bytes_string(tot_string,0,(uint)cntr.stat.RX_M_bytes,0,(uint)cntr.stat.RX_bytes,length , "Byte"));
}

/*********************************/
void create_CPS_string(char *CPS_string , uint length)
{
	snprintf(CPS_string , length , "1sec=%-6d  CPS | 5sec=%-6d  CPS | avg=%-6d  CPS" , cps_1_sec , cps_5_sec , cps_avg_total);
}

/*********************************/
void create_Con_string(char *Con_string , uint length)
{
	snprintf(Con_string , length , "Open=%-6d      | Close=%-6d     | active=%-6d" , cntr.stat.open_sockets , cntr.stat.close_sockets , CUR_ACTIVE_SESSION);
}

/***********is_mutex_lock**********************/
uint is_mutex_lock(pthread_mutex_t *mutex)
{
	uint range_mutex_lock = FALSE_0;

	if (pthread_mutex_trylock(mutex) == 0)
	{ /* Success!  This thread now owns the lock. */
		range_mutex_lock = FALSE_0;
		pthread_mutex_unlock(mutex);
	}
	else
	{/* Fail!  someone else hold the mutex.*/
		range_mutex_lock = TRUE_1;
	}
	return range_mutex_lock;
}


/***********handle_rx_range_buf**********************/
void print_range_table(void* dst_output , char *slide_bar , int cur_prcent)
{
	uint 	fd_idx;
	char	slide_bar_with_ranges[SLIDE_BAR_LENGTH + 1];

	create_slide_bar_with_string(slide_bar_with_ranges , slide_bar , "Ranges", SLIDE_BAR_LENGTH);

	fprintf(dst_output ,"%s\n",slide_bar_with_ranges);

	fprintf(dst_output , "File:%s , range_block_size=%d\n" ,
			range_global.final_file_name , range_global.global_range_block_size);

	fprintf(dst_output , "so far(%d%%):%"PRIu64"/%"PRIu64"/%"PRIu64" , pending_bufs=%d\n" ,
			cur_prcent ,
			range_global.cur_file_size , (range_global.last_range_fatch + 1) , range_global.expected_file_size,
			cntr.stat.range_pending_bufs);

	fprintf(dst_output , "%s\n",slide_bar);
	fprintf(dst_output , "id|sec|start       |%%   |end         |cntr|KBps\n");
	fprintf(dst_output , "%s\n",slide_bar);
	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if (fd_idx < max_active_sessions)
		{
			range_t *range_local = &fd_db[fd_idx].rx.range;
			uint percent = 0;
			char *color;
			if (range_local->local_range_block_size)
			{
				percent = ((range_local->range_cur_length * 100) / range_local->local_range_block_size);
			}
			else
			{
				percent = 0;
			}
			if (range_global.cur_file_size == range_global.range_table[fd_idx].range_start)
			{
				if (range_global.range_table[fd_idx].priority != 1)
				{
					color = YELLOW;
				}
				else
				{
					color = MAGENTA;
				}
			}
			else if (range_local->pending_range_to_write)
			{
				color = GREEN;
			}
			else
			{
				color = RESET;
			}
#ifdef RANGE_EXTEND_PRINTS
			fprintf(dst_output , "%s%d[%d,rx=%d,tx=%d,fd=%d,st=%d,p=%d,LK=%d,pr=%d,ep=%x]|%dsec.|start(%d)|end(%d)|cur(%d)(rx=%d)(ses=%d)%s\n",
					color,
					fd_idx,
					fd_idx ,
					fd_db[fd_idx].rx.rx_th_idx,
					fd_db[fd_idx].tx.tx_th_idx,
					fd_db[fd_idx].gen.fd,
					range_global.range_table[fd_idx].state ,
					range_local->pending_range_to_write,
					is_mutex_lock(&fd_db[fd_idx].gen.tx_rx_mutex),
					range_global.range_table[fd_idx].priority ,
					fd_db[fd_idx].rx.epoll_arm_events ,

					range_global.range_table[fd_idx].sec ,
					range_global.range_table[fd_idx].range_start ,
					range_global.range_table[fd_idx].range_end ,
					range_local->range_cur_length,
					fd_db[fd_idx].rx.rcv_bytes ,
					fd_db[fd_idx].non_del.session_cntr,
					RESET);
#else
			fprintf(dst_output , "%s%-2d|%-3d|%-12"PRIu64"|%-3d%%|%-12"PRIu64"|%-4d|%-4d%s\n",
					color,
					fd_idx,
					range_global.range_table[fd_idx].sec ,
					range_global.range_table[fd_idx].range_start ,
					percent,
					range_global.range_table[fd_idx].range_end ,
					fd_db[fd_idx].non_del.session_cntr,
					range_local->displayed_last_KBytes_per_sec,
					RESET);
#endif
		}
	}
	fprintf(dst_output ,"%s\n",slide_bar);
}


/*********************************/
void print_rx_threads_counters(void* dst_output)
{
	int rx_th_idx;

	for (rx_th_idx=0 ; rx_th_idx<cfg.int_v.rx_num_of_threads.val ; rx_th_idx++)
	{
		if (rx_th_db[rx_th_idx].cntr.closed_sockets) fprintf(dst_output , "RX[%d].closed_sockets=%d\n", rx_th_idx , rx_th_db[rx_th_idx].cntr.closed_sockets);
	}
}


/*********************************/
static void print_counters_error(void* dst_output)
{
	/*cntr.ERROR*/
	if (cntr.error.create_new_fd_db) fprintf(dst_output , "cntr.error.create_new_fd_db = %d\n",cntr.error.create_new_fd_db);
	if (cntr.error.create_new_fd_db_sock_reuse) fprintf(dst_output , "cntr.error.create_new_fd_db_sock_reuse = %d\n",cntr.error.create_new_fd_db_sock_reuse);
	if (cntr.error.failed_establish_connection) fprintf(dst_output , "cntr.error.failed_establish_connection = %d\n",cntr.error.failed_establish_connection);
	if (cntr.error.tx_create_new_request) fprintf(dst_output , "cntr.error.tx_create_new_request = %d\n",cntr.error.tx_create_new_request);
	if (cntr.error.Illegal_fd_to_close) fprintf(dst_output , "cntr.error.Illegal_fd_to_close = %d\n",cntr.error.Illegal_fd_to_close);
	if (cntr.error.failed_to_match_fd_to_fd_idx) fprintf(dst_output , "cntr.error.failed_to_match_fd_to_fd_idx = %d\n",cntr.error.failed_to_match_fd_to_fd_idx);
	if (cntr.error.fd_idx_already_in_use) fprintf(dst_output , "cntr.error.fd_idx_already_in_use = %d\n",cntr.error.fd_idx_already_in_use);
	if (cntr.error.Illegal_fd_idx) fprintf(dst_output , "cntr.error.Illegal_fd_idx = %d\n",cntr.error.Illegal_fd_idx);
	if (cntr.error.failed_to_add_fd_idx) fprintf(dst_output , "cntr.error.failed_to_add_fd_idx = %d\n",cntr.error.failed_to_add_fd_idx);
	if (cntr.error.try_to_add_illegal_fd) fprintf(dst_output , "cntr.error.try_to_add_illegal_fd = %d\n",cntr.error.try_to_add_illegal_fd);
	if (cntr.error.try_to_read_illegal_fd) fprintf(dst_output , "cntr.error.try_to_read_illegal_fd = %d\n",cntr.error.try_to_read_illegal_fd);
	if (cntr.error.unknown_clear_db_level) fprintf(dst_output , "cntr.error.unknown_clear_db_level = %d\n",cntr.error.unknown_clear_db_level);
	if (cntr.error.sock_error) fprintf(dst_output , "cntr.error.sock_error = %d\n",cntr.error.sock_error);
	if (cntr.error.connect_error) fprintf(dst_output , "cntr.error.connect_error = %d\n",cntr.error.connect_error);
	if (cntr.error.send_error) fprintf(dst_output , "cntr.error.send_error = %d\n",cntr.error.send_error);
	if (cntr.error.close_error) fprintf(dst_output , "cntr.error.close_error = %d\n",cntr.error.close_error);
	if (cntr.error.read_error) fprintf(dst_output , "cntr.error.read_error = %d\n",cntr.error.read_error);
	if (cntr.error.epoll_error) fprintf(dst_output , "cntr.error.epoll_error = %d\n",cntr.error.epoll_error);
	if (cntr.error.inet_pton_error) fprintf(dst_output , "cntr.error.inet_pton_error = %d\n",cntr.error.inet_pton_error);
	if (cntr.error.illegal_fd_to_close) fprintf(dst_output , "cntr.error.illegal_fd_to_close = %d\n",cntr.error.illegal_fd_to_close);
	if (cntr.error.failed_to_send_data_to_queue_thread) fprintf(dst_output , "cntr.error.failed_to_send_data_to_queue_thread = %d\n",cntr.error.failed_to_send_data_to_queue_thread);
	if (cntr.error.failed_to_update_range_priority) fprintf(dst_output , "cntr.error.failed_to_update_range_priority = %d\n",cntr.error.failed_to_update_range_priority);
	if (cntr.error.unknown_msg_q_code) fprintf(dst_output , "cntr.error.unknown_msg_q_code = %d\n",cntr.error.unknown_msg_q_code);
}

/*********************************/
static void print_counters_warning(void* dst_output)
{
	/*cntr.WARNING*/
	if (cntr.warning.align_close_cntr) fprintf(dst_output , "cntr.warning.align_close_cntr = %d\n",cntr.warning.align_close_cntr);
	if (cntr.warning.range_unknown_close_action) fprintf(dst_output , "cntr.warning.range_unknown_close_action = %d\n",cntr.warning.range_unknown_close_action);
	if (cntr.warning.failed_writing_to_disk) fprintf(dst_output , "cntr.warning.failed_writing_to_disk = %d\n",cntr.warning.failed_writing_to_disk);
	if (cntr.warning.unknow_close_reason) fprintf(dst_output , "cntr.warning.unknow_close_reason = %d\n",cntr.warning.unknow_close_reason);
	if (cntr.warning.dst_ip_match_not_found) fprintf(dst_output , "cntr.warning.dst_ip_match_not_found = %d\n",cntr.warning.dst_ip_match_not_found);
	if (cntr.warning.dst_port_match_not_found) fprintf(dst_output , "cntr.warning.dst_port_match_not_found = %d\n",cntr.warning.dst_port_match_not_found);
	if (cntr.warning.max_chunks_on_single_buf) fprintf(dst_output , "cntr.warning.max_chunks_on_single_buf = %d\n",cntr.warning.max_chunks_on_single_buf);
	if (cntr.warning.chunk_buf_reached_max_size) fprintf(dst_output , "cntr.warning.chunk_buf_reached_max_size = %d\n",cntr.warning.chunk_buf_reached_max_size);
	if (cntr.warning.chunk_failed_malloc) fprintf(dst_output , "cntr.warning.chunk_failed_malloc = %d\n",cntr.warning.chunk_failed_malloc);
	if (cntr.warning.chunk_failed_parse_close_CR_offsset) fprintf(dst_output , "cntr.warning.chunk_failed_parse_close_CR_offsset = %d\n",cntr.warning.chunk_failed_parse_close_CR_offsset);
	if (cntr.warning.chunk_failed_parse_illegal_strtoul) fprintf(dst_output , "cntr.warning.chunk_failed_parse_illegal_strtoul = %d\n",cntr.warning.chunk_failed_parse_illegal_strtoul);
	if (cntr.warning.chunk_failed_parse_open_CR_long_offset) fprintf(dst_output , "cntr.warning.chunk_failed_parse_open_CR_long_offset = %d\n",cntr.warning.chunk_failed_parse_open_CR_long_offset);
	if (cntr.warning.chunk_first_char_is_not_digit) fprintf(dst_output , "cntr.warning.chunk_first_char_is_not_digit = %d\n",cntr.warning.chunk_first_char_is_not_digit);
	if (cntr.warning.chunk_stop_processing) fprintf(dst_output , "cntr.warning.chunk_stop_processing = %d\n",cntr.warning.chunk_stop_processing);
	if (cntr.warning.reached_max_dst_ips) fprintf(dst_output , "cntr.warning.reached_max_dst_ips = %d\n",cntr.warning.reached_max_dst_ips);
	if (cntr.warning.reached_max_dst_ports) fprintf(dst_output , "cntr.warning.reached_max_dst_ports = %d\n",cntr.warning.reached_max_dst_ports);
	if (cntr.warning.try_to_read_write_from_closing_socket) fprintf(dst_output , "cntr.warning.try_to_read_write_from_closing_socket = %d\n",cntr.warning.try_to_read_write_from_closing_socket);
	if (cntr.warning.send_new_pkt_while_pending_tx) fprintf(dst_output , "cntr.warning.send_new_pkt_while_pending_tx = %d\n",cntr.warning.send_new_pkt_while_pending_tx);
	if (cntr.warning.range_stuck_force_restart) fprintf(dst_output , "cntr.warning.range_stuck_force_restart = %d\n",cntr.warning.range_stuck_force_restart);
	if (cntr.warning.cookie_string_too_long) fprintf(dst_output , "cntr.warning.cookie_string_too_long = %d\n",cntr.warning.cookie_string_too_long);
	if (cntr.warning.parser_reached_max_lines) fprintf(dst_output , "cntr.warning.parser_reached_max_lines = %d\n",cntr.warning.parser_reached_max_lines);
	if (cntr.warning.parser_reached_max_cookies) fprintf(dst_output , "cntr.warning.parser_reached_max_cookies = %d\n",cntr.warning.parser_reached_max_cookies);
	if (cntr.warning.html_parser_reached_max_tags) fprintf(dst_output , "cntr.warning.html_parser_reached_max_tags = %d\n",cntr.warning.html_parser_reached_max_tags);
	if (cntr.warning.max_saved_cookies) fprintf(dst_output , "cntr.warning.max_saved_cookies = %d\n",cntr.warning.max_saved_cookies);
	if (cntr.warning.failed_to_read_content_length) fprintf(dst_output , "cntr.warning.failed_to_read_content_length = %d\n",cntr.warning.failed_to_read_content_length);
	if (cntr.warning.gzip_inflate_error) fprintf(dst_output , "cntr.warning.gzip_inflate_error = %d\n",cntr.warning.gzip_inflate_error);
	if (cntr.warning.Illegal_cur_slice) fprintf(dst_output , "cntr.warning.Illegal_cur_slice = %d\n",cntr.warning.Illegal_cur_slice);
	if (cntr.warning.Illegal_rcv_size_per_slice) fprintf(dst_output , "cntr.warning.Illegal_rcv_size_per_slice = %d\n",cntr.warning.Illegal_rcv_size_per_slice);
	if (cntr.warning.try_remove_fd_which_not_in_use) fprintf(dst_output , "cntr.warning.try_remove_fd_which_not_in_use = %d\n",cntr.warning.try_remove_fd_which_not_in_use);
	if (cntr.warning.double_close) fprintf(dst_output , "cntr.warning.double_close = %d\n",cntr.warning.double_close);
	if (cntr.warning.epoll_hangup_on_unused_fd_in_state_close) fprintf(dst_output , "cntr.warning.epoll_hangup_on_unused_fd_in_state_close = %d\n",cntr.warning.epoll_hangup_on_unused_fd_in_state_close);
	if (cntr.warning.epoll_hangup_on_unused_fd_in_state_ready) fprintf(dst_output , "cntr.warning.epoll_hangup_on_unused_fd_in_state_ready = %d\n",cntr.warning.epoll_hangup_on_unused_fd_in_state_ready);
	if (cntr.warning.close_by_server) fprintf(dst_output , "cntr.warning.close_by_server = %d\n",cntr.warning.close_by_server);
	if (cntr.warning.post_not_found_in_200OK) fprintf(dst_output , "cntr.warning.post_not_found_in_200OK = %d\n",cntr.warning.post_not_found_in_200OK);
	if (cntr.warning.epoll_add_ret_errno) fprintf(dst_output , "cntr.warning.epoll_add_ret_errno = %d\n",cntr.warning.epoll_add_ret_errno);
}

/*********************************/
static void print_counters_info(void* dst_output)
{
	/*cntr.INFO*/
	if (cntr.info.closing_upon_http_connection_close) fprintf(dst_output , "cntr.info.closing_upon_http_connection_close = %d\n",cntr.info.closing_upon_http_connection_close);
	if (cntr.info.server_close_by_FIN) fprintf(dst_output , "cntr.info.server_close_by_FIN = %d\n",cntr.info.server_close_by_FIN);
	if (cntr.info.server_close_by_RST) fprintf(dst_output , "cntr.info.server_close_by_RST = %d\n",cntr.info.server_close_by_RST);
	if (cntr.info.rcv_buf_full_write_to_disk) fprintf(dst_output , "cntr.info.rcv_buf_full_write_to_disk = %d\n",cntr.info.rcv_buf_full_write_to_disk);
	if (cntr.info.http_parser_reached_html) fprintf(dst_output , "cntr.info.warning.http_parser_reached_html = %d\n",cntr.info.http_parser_reached_html);
	if (cntr.info.http_parser_line_start_with_tab) fprintf(dst_output , "cntr.info.warning.http_parser_line_start_with_tab = %d\n",cntr.info.http_parser_line_start_with_tab);
//	if (cntr.info.http_parser_unknon_header_line) fprintf(dst_output , "cntr.info.http_parser_unknon_header_line = %d\n",cntr.info.http_parser_unknon_header_line);
	if (cntr.info.server_not_support_range) fprintf(dst_output , "cntr.info.server_not_support_range = %d\n",cntr.info.server_not_support_range);
	if (cntr.info.range_config_disabled) fprintf(dst_output , "cntr.info.range_config_disabled = %d\n",cntr.info.range_config_disabled);

	/*cntr.INFO.extra...*/
#if 0
	if (cntr.info.skip_read_from_socket_due_to_mutex_lock) fprintf(dst_output , "cntr.info.skip_read_from_socket_due_to_mutex_lock = %d\n",cntr.info.skip_read_from_socket_due_to_mutex_lock);
	if (cntr.info.close_skip_shutdown) fprintf(dst_output , "cntr.info.close_skip_shutdown = %d\n",cntr.info.close_skip_shutdown);
#endif
	/*cntr.INFO.range*/
#ifdef RANGE_EXTEND_PRINTS
	if (cntr.info.range_pending_to_write_in_close) fprintf(dst_output , "cntr.info.range_pending_to_write_in_close = %d\n",cntr.info.range_pending_to_write_in_close);

	if (cntr.info.range_repending_buf_via_timer) fprintf(dst_output , "cntr.info.range_repending_buf_via_timer = %d\n",cntr.info.range_repending_buf_via_timer);
	if (cntr.info.range_pending_move_to_timer_handle) fprintf(dst_output , "cntr.info.range_pending_move_to_timer_handle = %d\n",cntr.info.range_pending_move_to_timer_handle);

	if (cntr.info.range_restart) fprintf(dst_output , "cntr.info.range_restart = %d\n",cntr.info.range_restart);
	if (cntr.info.range_restart_unfinished_range) fprintf(dst_output , "cntr.info.range_restart_unfinished_range = %d\n",cntr.info.range_restart_unfinished_range);
	if (cntr.info.range_rx_restart) fprintf(dst_output , "cntr.info.range_rx_restart = %d\n",cntr.info.range_rx_restart);
#endif
	if (cntr.info.range_wrote_buf_to_disk) fprintf(dst_output , "cntr.info.range_wrote_buf_to_disk = %d\n",cntr.info.range_wrote_buf_to_disk);

	/*cntr.INFO.tmp*/
#if 0
	if (cntr.info.tmp_range_select_restart) fprintf(dst_output , "cntr.info.tmp_range_select_restart = %d\n",cntr.info.tmp_range_select_restart);
	if (cntr.info.tmp_remove_fd_from_epoll) fprintf(dst_output , "cntr.info.tmp_remove_fd_from_epoll = %d\n",cntr.info.tmp_remove_fd_from_epoll);
	if (cntr.info.tmp_failed_tx_mutex_lock) fprintf(dst_output , "cntr.info.tmp_failed_tx_mutex_lock = %d\n",cntr.info.tmp_failed_tx_mutex_lock);
	if (cntr.info.tmp_rearm_tx_from_queue_thread) fprintf(dst_output , "cntr.info.tmp_rearm_tx_from_queue_thread = %d\n",cntr.info.tmp_rearm_tx_from_queue_thread);
	if (cntr.info.tmp_rcv_bytes_0) fprintf(dst_output , "cntr.info.tmp_rcv_bytes_0 = %d\n",cntr.info.tmp_rcv_bytes_0);
	if (cntr.stat.close_sockets) fprintf(dst_output , "cntr.stat.close_sockets = %d\n",cntr.stat.close_sockets);

	if (cntr.info.tmp_finish_but_more_to_read) fprintf(dst_output , "cntr.info.tmp_finish_but_more_to_read = %d\n",cntr.info.tmp_finish_but_more_to_read);
	if (cntr.info.tmp_clsoe_fd_db_start) fprintf(dst_output , "cntr.info.tmp_clsoe_fd_db_start = %d\n",cntr.info.tmp_clsoe_fd_db_start);
	if (cntr.info.tmp_wake_up_tx) fprintf(dst_output , "cntr.info.tmp_wake_up_tx = %d\n",cntr.info.tmp_wake_up_tx);
	if (cntr.info.tmp_result_sess_finish) fprintf(dst_output , "cntr.info.tmp_result_sess_finish = %d\n",cntr.info.tmp_result_sess_finish);
	if (cntr.info.tmp_finished_read_from_sock) fprintf(dst_output , "cntr.info.tmp_finished_read_from_sock = %d\n",cntr.info.tmp_finished_read_from_sock);
	if (cntr.info.tmp_close_content_complete) fprintf(dst_output , "cntr.info.tmp_close_content_complete = %d\n",cntr.info.tmp_close_content_complete);
	if (cntr.info.tmp_clsoe_fd_db_start) fprintf(dst_output , "cntr.info.tmp_clsoe_fd_db_start = %d\n",cntr.info.tmp_clsoe_fd_db_start);
	if (cntr.info.tmp_clsoe_clear_db_full) fprintf(dst_output , "cntr.info.tmp_clsoe_clear_db_full = %d\n",cntr.info.tmp_clsoe_clear_db_full);
	if (cntr.info.tmp_clsoe_clear_db_partial) fprintf(dst_output , "cntr.info.tmp_clsoe_clear_db_partial = %d\n",cntr.info.tmp_clsoe_clear_db_partial);
#endif
	if (cntr.info.tmp_delay_range_tx) fprintf(dst_output , "cntr.info.tmp_delay_range_tx = %d\n",cntr.info.tmp_delay_range_tx);
	if (cntr.info.tmp_range_wrote_to_disk_via_rx) fprintf(dst_output , "cntr.info.tmp_range_wrote_to_disk_via_rx = %d\n",cntr.info.tmp_range_wrote_to_disk_via_rx);
	if (cntr.info.tmp_range_write_pending_buf_via_timer) fprintf(dst_output , "cntr.info.tmp_range_write_pending_buf_via_timer = %d\n",cntr.info.tmp_range_write_pending_buf_via_timer);
	if (cntr.info.tmp_range_stuck_socket) fprintf(dst_output , "cntr.info.tmp_range_stuck_socket = %d\n",cntr.info.tmp_range_stuck_socket);
	if (cntr.info.tmp_read_err_eAgain) fprintf(dst_output , "cntr.info.tmp_read_err_eAgain = %d\n",cntr.info.tmp_read_err_eAgain);
	if (cntr.info.tmp_large_slice_delta) fprintf(dst_output , "cntr.info.tmp_large_slice_delta = %d\n",cntr.info.tmp_large_slice_delta);

}
/*********************************/
void print_counters(void* dst_output)
{
	if ((cfg.int_v.display_counters.val) & (DEBUG_COUNTER_ERROR))
	{
		print_counters_error(dst_output);
	}

	if ((cfg.int_v.display_counters.val) & (DEBUG_COUNTER_WARNING))
	{
		print_counters_warning(dst_output);
	}

	if ((cfg.int_v.display_counters.val) & (DEBUG_COUNTER_INFO))
	{
		print_counters_info(dst_output);
	}
}


/*********************************/
void print_overlap_values_WITHOUT_vazaget_server_values(void* dst_output , char *slide_bar)
{
	int cookie_idx;
	char	slide_bar_with_cookie[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_socket[SLIDE_BAR_LENGTH + 1];

	create_slide_bar_with_string(slide_bar_with_cookie , slide_bar , "[Cookies]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_socket , slide_bar , "[L3 + L4]", SLIDE_BAR_LENGTH);

	fprintf(dst_output , "%s\n",slide_bar_with_socket);
	if (cntr.stat.http_replies_total)
	{/*print it only after receive the first reply*/
		fprintf(dst_output , "%sWant to see IP & port values on server side?\nload index.php (./vazaget -php) to your web server...%s\n",YELLOW , RESET);
	}
	fprintf(dst_output , "Client:SrcIP  =%s%-*s%s (%-*d) Server:SrcIP   =???\n",
			cntr.stat.srcIP_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_ip  ,
					cntr.stat.srcIP_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcIP_diff);

	fprintf(dst_output , "Client:SrcPort=%s%-*s%s (%-*d) Server:SrcPort =???\n",
			cntr.stat.srcPort_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_port  ,
					cntr.stat.srcPort_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcPort_diff);

	fprintf(dst_output , "Client:DstIP  =%s%-*s%s (%-*d) Server:DstIP   =???\n",
			srv_dst_ip[0].dstIP_diff_cntr ? YELLOW : "" ,
					ip_length_display,
					last.client_dst_ip  ,
					srv_dst_ip[0].dstIP_diff_cntr ? RESET : "" ,
							cntr_length_display ,
							srv_dst_ip[0].dstIP_diff_cntr);

	fprintf(dst_output , "Client:DstPort=%s%-*s%s (%-*d) Server:DstPort =???\n",
			cntr.stat.dstPort_diff ? YELLOW : "" ,
					ip_length_display,last.client_dst_port,
					cntr.stat.dstPort_diff ? RESET : "" ,
							cntr_length_display ,cntr.stat.dstPort_diff);

	if (cntr.stat.http_proto_diff)
	{
		fprintf(dst_output , "Client:Proto  =%-*s (%-*d) Server:proto   =???\n",ip_length_display,last.client_http_proto, cntr_length_display ,cntr.stat.http_proto_diff);
	}

	if (last.cookie_rcv_from_reply[0][0])
	{
		/****slide_bar_with_cookie*****/
		fprintf(dst_output , "%s\n",slide_bar_with_cookie);
		for (cookie_idx=0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
		{
			if(last.cookie_rcv_from_reply[cookie_idx][0])
				fprintf(dst_output ,"200OK Set-Cookie[%d]:=???\n",cookie_idx);
		}

		if (last.cookie_parsed_from_html[0])
		{
			fprintf(dst_output , "GET cookie=???\n");
		}
	}
	if (cfg.flag.cookie_reply_2.val)
	{
		fprintf(dst_output , "Cookie 2 real:  %smatch=%d%s , %sNON match=%d%s\n",
				cntr.stat.cookie_2_real_match    ? BOLDGREEN : ""  , cntr.stat.cookie_2_real_match     , cntr.stat.cookie_2_real_match ? RESET    : "",
						cntr.stat.cookie_2_real_non_match? BOLDRED   : ""  , cntr.stat.cookie_2_real_non_match , cntr.stat.cookie_2_real_non_match? RESET : "");
	}

}


/*********************************/
static void print_overlap_values_vazaget_server_values(void* dst_output , char *slide_bar)
{
	int i , cookie_idx;
	char	slide_bar_with_cookie[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_socket[SLIDE_BAR_LENGTH + 1];

	create_slide_bar_with_string(slide_bar_with_cookie , slide_bar , "[L7 - Cookies]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_socket , slide_bar , "[L3 + L4]", SLIDE_BAR_LENGTH);

	fprintf(dst_output , "%s\n",slide_bar_with_socket);
	fprintf(dst_output , "Client:SrcIP  =%s%-*s%s (%-*d) Server:SrcIP   =%s%s%s\n",
			cntr.stat.srcIP_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_ip  ,
					cntr.stat.srcIP_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcIP_diff ,
							cntr.stat.srcIP_diff ? YELLOW : "" , last.srv_src_ip ,
									cntr.stat.srcIP_diff ? RESET : "");
	fprintf(dst_output , "Client:SrcPort=%s%-*s%s (%-*d) Server:SrcPort =%s%s%s\n",
			cntr.stat.srcPort_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_port  ,
					cntr.stat.srcPort_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcPort_diff ,
							cntr.stat.srcPort_diff ? YELLOW : "" ,
									last.srv_src_port,
									cntr.stat.srcPort_diff ? RESET : "");
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (srv_dst_ip[i].ip_string[0])
		{
			fprintf(dst_output , "Client:DstIP  =%s%-*s%s (%-*d) Server:DstIP[%d]=%s%s%s\n",
					srv_dst_ip[i].dstIP_diff_cntr ? YELLOW : "" ,
							ip_length_display,last.client_dst_ip  ,
							srv_dst_ip[i].dstIP_diff_cntr ? RESET : "" ,
									cntr_length_display ,srv_dst_ip[i].dstIP_diff_cntr ,i ,
									srv_dst_ip[i].dstIP_diff_cntr ? YELLOW : "" ,
											srv_dst_ip[i].ip_string,
											srv_dst_ip[i].dstIP_diff_cntr ? RESET : "" );
		}
		else
		{
			break;
		}
	}


	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (srv_dst_port[i].port_string[0])
		{
			fprintf(dst_output , "Client:DstPort=%s%-*s%s (%-*d) Server:DstPort[%d]=%s%s%s\n",
					srv_dst_port[i].dstPort_diff_cntr ? YELLOW : "" ,
							ip_length_display , last.client_dst_port  ,
							srv_dst_port[i].dstPort_diff_cntr ? RESET : "" ,
									cntr_length_display , srv_dst_port[i].dstPort_diff_cntr ,i ,
									srv_dst_port[i].dstPort_diff_cntr ? YELLOW : "" ,
											srv_dst_port[i].port_string,
											srv_dst_port[i].dstPort_diff_cntr ? RESET : "" );
		}
		else
		{
			break;
		}
	}

	if (cntr.stat.http_proto_diff)
	{
		fprintf(dst_output , "Client:Proto  =%-*s (%-*d) Server:proto   =%s\n",ip_length_display,last.client_http_proto, cntr_length_display ,cntr.stat.http_proto_diff , last.srv_http_proto);
	}

	if (last.cookie_rcv_from_reply[0][0])
	{
		/****slide_bar_with_cookie*****/
		fprintf(dst_output , "%s\n",slide_bar_with_cookie);
		for (cookie_idx=0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
		{
			if(last.cookie_rcv_from_reply[cookie_idx][0])
				fprintf(dst_output ,"200OK Set-Cookie[%d]:=%s\n",cookie_idx,last.cookie_rcv_from_reply[cookie_idx]);
		}

		if (last.cookie_parsed_from_html[0])
		{
			fprintf(dst_output , "GET cookie=%s\n",last.cookie_parsed_from_html);
		}
	}
	if (cfg.flag.cookie_reply_2.val)
	{
		fprintf(dst_output , "Cookie 2 real:  %smatch=%d%s , %sNON match=%d%s\n",
				cntr.stat.cookie_2_real_match    ? BOLDGREEN : ""  , cntr.stat.cookie_2_real_match     , cntr.stat.cookie_2_real_match ? RESET    : "",
						cntr.stat.cookie_2_real_non_match? BOLDRED   : ""  , cntr.stat.cookie_2_real_non_match , cntr.stat.cookie_2_real_non_match? RESET : "");
	}
}


/*********************************/
void print_overlap_values_for_donwnload_file(void* dst_output , char *slide_bar)
{

	int cookie_idx;
	char	slide_bar_with_cookie[SLIDE_BAR_LENGTH + 1];


	create_slide_bar_with_string(slide_bar_with_cookie , slide_bar , "[L7 - Cookies]", SLIDE_BAR_LENGTH);
#if 0
	char	slide_bar_with_socket[SLIDE_BAR_LENGTH + 1];
	create_slide_bar_with_string(slide_bar_with_socket , slide_bar , "[L3 + L4]", SLIDE_BAR_LENGTH);

	fprintf(dst_output , "%s\n",slide_bar_with_socket);
	fprintf(dst_output , "Client:SrcIP  =%s%-*s%s (%-*d) Server:SrcIP   =%s%s%s\n",
			cntr.stat.srcIP_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_ip  ,
					cntr.stat.srcIP_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcIP_diff ,
							cntr.stat.srcIP_diff ? YELLOW : "" , last.srv_src_ip ,
									cntr.stat.srcIP_diff ? RESET : "");
	fprintf(dst_output , "Client:SrcPort=%s%-*s%s (%-*d) Server:SrcPort =%s%s%s\n",
			cntr.stat.srcPort_diff ? YELLOW : "" ,
					ip_length_display,
					last.client_src_port  ,
					cntr.stat.srcPort_diff ? RESET : "" ,
							cntr_length_display ,
							cntr.stat.srcPort_diff ,
							cntr.stat.srcPort_diff ? YELLOW : "" ,
									last.srv_src_port,
									cntr.stat.srcPort_diff ? RESET : "");
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (srv_dst_ip[i].ip_string[0])
		{
			fprintf(dst_output , "Client:DstIP  =%s%-*s%s (%-*d) Server:DstIP[%d]=%s%s%s\n",
					srv_dst_ip[i].dstIP_diff_cntr ? YELLOW : "" ,
							ip_length_display,last.client_dst_ip  ,
							srv_dst_ip[i].dstIP_diff_cntr ? RESET : "" ,
									cntr_length_display ,srv_dst_ip[i].dstIP_diff_cntr ,i ,
									srv_dst_ip[i].dstIP_diff_cntr ? YELLOW : "" ,
											srv_dst_ip[i].ip_string,
											srv_dst_ip[i].dstIP_diff_cntr ? RESET : "" );
		}
		else
		{
			break;
		}
	}


	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (srv_dst_port[i].port_string[0])
		{
			fprintf(dst_output , "Client:DstPort=%s%-*s%s (%-*d) Server:DstPort[%d]=%s%s%s\n",
					srv_dst_port[i].dstPort_diff_cntr ? YELLOW : "" ,
							ip_length_display , last.client_dst_port  ,
							srv_dst_port[i].dstPort_diff_cntr ? RESET : "" ,
									cntr_length_display , srv_dst_port[i].dstPort_diff_cntr ,i ,
									srv_dst_port[i].dstPort_diff_cntr ? YELLOW : "" ,
											srv_dst_port[i].port_string,
											srv_dst_port[i].dstPort_diff_cntr ? RESET : "" );
		}
		else
		{
			break;
		}
	}

	if (cntr.stat.http_proto_diff)
	{
		fprintf(dst_output , "Client:Proto  =%-*s (%-*d) Server:proto   =%s\n",ip_length_display,last.client_http_proto, cntr_length_display ,cntr.stat.http_proto_diff , last.srv_http_proto);
	}
#endif

	if (last.cookie_rcv_from_reply[0][0])
	{
		/****slide_bar_with_cookie*****/
		fprintf(dst_output , "%s\n",slide_bar_with_cookie);
		for (cookie_idx=0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
		{
			if(last.cookie_rcv_from_reply[cookie_idx][0])
				fprintf(dst_output ,"200OK Set-Cookie[%d]:=%s\n",cookie_idx,last.cookie_rcv_from_reply[cookie_idx]);
		}

		if (last.cookie_parsed_from_html[0])
		{
			fprintf(dst_output , "GET cookie=%s\n",last.cookie_parsed_from_html);
		}
	}
	if (cfg.flag.cookie_reply_2.val)
	{
		fprintf(dst_output , "Cookie 2 real:  %smatch=%d%s , %sNON match=%d%s\n",
				cntr.stat.cookie_2_real_match    ? BOLDGREEN : ""  , cntr.stat.cookie_2_real_match     , cntr.stat.cookie_2_real_match ? RESET    : "",
						cntr.stat.cookie_2_real_non_match? BOLDRED   : ""  , cntr.stat.cookie_2_real_non_match , cntr.stat.cookie_2_real_non_match? RESET : "");
	}

}

/*********************************/
void print_overlap_values(void* dst_output)
{
	char 	flags[500] = {0};
	char 	int_val[500] = {0};
	char 	tmp[20];
	char 	vazaget_arg_string[STRING_100_B_LENGTH];
	char	slide_bar[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_vazaget[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_L1[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_counters[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_other[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_usage[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_L7[SLIDE_BAR_LENGTH + 1];
	char	slide_bar_with_connections[SLIDE_BAR_LENGTH + 1];
	char	TX_bytes_string[STRING_100_B_LENGTH + 1] = {0};
	char	RX_bytes_string[STRING_100_B_LENGTH + 1] = {0};
	char	CPS_string[STRING_100_B_LENGTH + 1] = {0};
	char	Con_string[STRING_100_B_LENGTH + 1] = {0};
	int 	cur_prcent = 0;
	char 	percent_string[10];
	char	gzip_replies[20] = {""};
	char	post_requests[20];
	char	http_chunks[30] = {""};
	char 	proxy_ip_address[HDR_STRING_LENGTH+1] = {0};
	char 	dst_ip_address[HDR_STRING_LENGTH+1] = {0};


	/***int_values***/

	sprintf(tmp , "n=%d",cfg.int_v.num_of_session.val);
	strcat(int_val , tmp);

	if (cfg.int_v.tx_num_of_threads.val)
	{
		sprintf(tmp , ":tx=%d",cfg.int_v.tx_num_of_threads.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.rx_num_of_threads.val)
	{
		sprintf(tmp , ":rx=%d",cfg.int_v.rx_num_of_threads.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.bw_rx_limit.val)
	{
		sprintf(tmp , ":br=%d",cfg.int_v.bw_rx_limit.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.bw_TX_limit.val)
	{
		sprintf(tmp , ":bt=%d",cfg.int_v.bw_TX_limit.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.post_upload.val)
	{
		sprintf(tmp , ":up=%d",cfg.int_v.post_upload.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.delay_get_sec.val)
	{
		sprintf(tmp , ":wg=%d",cfg.int_v.delay_get_sec.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.delay_close_sec.val)
	{
		sprintf(tmp , ":wc=%d",cfg.int_v.delay_close_sec.val);
		strcat(int_val , tmp);
	}
	if (cfg.int_v.ssl_verify_cert.val)
	{
		sprintf(tmp , ":sv=%d",cfg.int_v.ssl_verify_cert.val);
		strcat(int_val , tmp);
	}


	/***flags***/
	if (cfg.str_v.cookie_string_cli[0])
		strcat(flags , "+cc");
	if (cfg.flag.cookie_from_reply.val)
		strcat(flags , "+cr");
	if (cfg.flag.cookie_reply_2.val)
		strcat(flags , "+cr2");
	if (cfg.flag.cookie_wait.val)
		strcat(flags , "+cw");
	if (cfg.flag.encoding_gzip.val)
		strcat(flags , "+gz");
	if (cfg.flag.close_by_rst.val)
		strcat(flags , "+fr");
	if (cfg.flag.close_by_server.val)
		strcat(flags , "+fs");
	if (cfg.flag.socket_resue.val)
		strcat(flags , "+rs");
	if (cfg.flag.save_to_file.val)
		strcat(flags , "+k");
	if (cfg.flag.chunks_dis.val)
		strcat(flags , "+ch");
	if (cfg.flag.range.val)
		strcat(flags , "+r");
	if (cfg.flag.close_thread_dis.val)
		strcat(flags , "+ct");
	if (cfg.flag.range_on_mem.val)
		strcat(flags , "+rm");


	calc_print_columns_length();
	if ((!cfg.dbg_v.dbg)
			&& (!cfg.int_v.ssl_debug_flag.val)
			&& (dst_output==stdout))
	{
		printf("\033c"); /*required to clean screen*/
		fflush(dst_output); /*required to clean screen*/
	}

	if (cfg.flag.range.val)
	{
		if (range_global.expected_file_size)
		{/*percentage*/
			if (range_global.cur_file_size ==  range_global.expected_file_size)
			{
				cur_prcent = 100;
			}
			else if (range_global.expected_file_size > 40000000)
			{/*verify that it will not overflow beyond sizeof uint*/
				cur_prcent = (int)(range_global.cur_file_size / (range_global.expected_file_size / 100));
			}
			else
			{
				cur_prcent = (int)((range_global.cur_file_size * 100) / range_global.expected_file_size);
			}
		}
	}
	else if(IS_STRING_SET(cfg.dest_params.file_name_ptr))
	{/*download file without range - will always done by single fd_idx = 0*/
		if (file_download_global.file_size)
		{
			if (fd_db[0].rx.rcv_bytes >= file_download_global.file_size)
			{
				cur_prcent = 100;
			}
			else if (file_download_global.file_size > 40000000)
			{/*verify that it will not overflow beyond sizeof uint*/
				cur_prcent = (int)((fd_db[0].rx.rcv_bytes) / (file_download_global.file_size / 100));
			}
			else if (file_download_global.file_size)
			{
				cur_prcent = (int)((fd_db[0].rx.rcv_bytes * 100) / file_download_global.file_size);
			}
			else
			{
				cur_prcent = 0;
			}
		}
	}
	else
	{
		cur_prcent = (int)((cntr.stat.close_sockets * 100) / cfg.int_v.num_of_session.val);
	}
	sprintf	(percent_string , "[%d%%]" , cur_prcent);

	snprintf(vazaget_arg_string ,SLIDE_BAR_LENGTH, "[VazaGet (%s%s) arguments]" , VAZAGET_VERSION, BUILD_PLATFORM);
	create_slide_bar(slide_bar , cur_prcent , SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_usage , slide_bar , percent_string , SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_vazaget , slide_bar , vazaget_arg_string , SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_L1 , slide_bar , "[L1]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_connections , slide_bar , "[Connections]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_counters , slide_bar , "[Counters]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_other , slide_bar , "[Others]", SLIDE_BAR_LENGTH);
	create_slide_bar_with_string(slide_bar_with_L7 , slide_bar , "[L7 - HTTP]", SLIDE_BAR_LENGTH);
	create_TX_bytes_string(TX_bytes_string , STRING_100_B_LENGTH);
	create_RX_bytes_string(RX_bytes_string , STRING_100_B_LENGTH);
	create_CPS_string(CPS_string , STRING_100_B_LENGTH);
	create_Con_string(Con_string , STRING_100_B_LENGTH);

	/****slide_bar_with_vazaget*****/
	if (IS_STRING_SET(cfg.dest_proxy_params.ip_addr_isolate_string))
	{
		sprintf(proxy_ip_address , " , Proxy=%s",cfg.dest_proxy_params.orig_full_uri);
		sprintf(dst_ip_address , "Dst=%s",cfg.dest_params.orig_full_uri);
	}
	else
	{
		sprintf(dst_ip_address , "Dst=%s",cfg.dest_params.orig_full_uri);
	}
	fprintf(dst_output , "%s\n",slide_bar_with_vazaget);
	fprintf(dst_output , "%s%s , %s, %s\n",
			dst_ip_address ,
			proxy_ip_address ,
			int_val,
			flags);
	if (cfg.str_v.note_string[0] != '\0')
		fprintf(dst_output , "note=%s\n",cfg.str_v.note_string);

	if (cntr.stat.get_requests)
	{
		/****slide_bar_with_total*****/
		fprintf(dst_output , "%s\n",slide_bar_with_L1);
		fprintf(dst_output , "TX : %s\n",TX_bytes_string);
		fprintf(dst_output , "RX : %s\n",RX_bytes_string);


		if (cfg.flag.socket_resue.val)
		{
			fprintf(dst_output , "%s\n",slide_bar_with_connections);
			fprintf(dst_output , "current active sessions=%d\n", CUR_ACTIVE_SESSION);
		}
		else
		{
			fprintf(dst_output , "%s\n",slide_bar_with_connections);
			/*CPS*/
			if ((cfg.int_v.num_of_session.val > 1) && (!cfg.flag.range.val || !cfg.flag.save_to_file.val))
			{
				fprintf(dst_output , "CPS: %s\n",CPS_string);
			}
			fprintf(dst_output , "Con: %s\n",Con_string);
		}

		/****slide_bar_with_socket*****/
		if (cfg.flag.range.val)
		{
			print_range_table(dst_output , slide_bar , cur_prcent);
		}
		else if (vaza_server_found)
		{
			print_overlap_values_vazaget_server_values(dst_output , slide_bar);
		}
		else if (IS_STRING_SET(cfg.dest_params.file_name_ptr))
		{/*downloading file not via range*/
			//			print_overlap_values_for_donwnload_file(dst_output , slide_bar);
		}
		else
		{
			print_overlap_values_WITHOUT_vazaget_server_values(dst_output , slide_bar);
		}

		/****slide_bar_with_L7-HTTP*****/
		fprintf(dst_output , "%s\n",slide_bar_with_L7);
		if (cntr.stat.gzip_reply) sprintf(gzip_replies , "(gzip=%d) " , cntr.stat.gzip_reply);
		if (cntr.stat.post_requests) sprintf(post_requests , "| POST=%-6d" , cntr.stat.post_requests);
		if (cntr.stat.http_chunks) sprintf(http_chunks , "(http.chunks=%d) " , cntr.stat.http_chunks);

		if (cntr.stat.get_requests) fprintf(dst_output , "Requests: GET=%-6d%s\n",cntr.stat.get_requests, cntr.stat.post_requests ? post_requests : "");
		if (cntr.stat.get_requests) fprintf(dst_output , "Replies : %s%s[ %s1xx=%d%s | %s2xx=%d%s | %s3xx=%d%s | %s4xx=%d%s | %s5xx=%d%s ]\n"
				, gzip_replies, http_chunks,
				cntr.stat.http_1xx? BOLDBLUE : ""  , cntr.stat.http_1xx , cntr.stat.http_1xx? RESET : "",
						cntr.stat.http_2xx? BOLDGREEN : "" , cntr.stat.http_2xx , cntr.stat.http_2xx? RESET : "",
								cntr.stat.http_3xx? BOLDBLUE : ""  , cntr.stat.http_3xx , cntr.stat.http_3xx? RESET : "",
										cntr.stat.http_4xx? BOLDRED : ""   , cntr.stat.http_4xx , cntr.stat.http_4xx? RESET : "",
												cntr.stat.http_5xx? BOLDBLUE : ""  , cntr.stat.http_5xx , cntr.stat.http_5xx? RESET : "");
#if 0
		if (cntr.get_requests) fprintf(dst_output , "GET's=%-6d%s | Replies%s%s [ %s1xx=%d%s | %s2xx=%d%s | %s3xx=%d%s | %s4xx=%d%s | %s5xx=%d%s ]\n"
				,cntr.get_requests, cntr.post_requests ? post_requests : "" , gzip_replies, http_chunks,
						cntr.http_1xx? BOLDBLUE : ""  , cntr.http_1xx , cntr.http_1xx? RESET : "",
								cntr.http_2xx? BOLDGREEN : "" , cntr.http_2xx , cntr.http_2xx? RESET : "",
										cntr.http_3xx? BOLDBLUE : ""  , cntr.http_3xx , cntr.http_3xx? RESET : "",
												cntr.http_4xx? BOLDRED : ""   , cntr.http_4xx , cntr.http_4xx? RESET : "",
														cntr.http_5xx? BOLDBLUE : ""  , cntr.http_5xx , cntr.http_5xx? RESET : "");
#endif
		if (cntr.stat.http_unknown_ret_value) fprintf(dst_output , "Total: Reply unknown = %d\n",cntr.stat.http_unknown_ret_value);

		/****slide_bar_with_other*****/
		fprintf(dst_output , "%s\n",slide_bar_with_other);
		if (cfg.int_v.post_upload.val)
		{
			fprintf(dst_output , "Post upload results: %sSuccess=%d%s ,%sFailed=%d%s \n",
					cntr.stat.post_upload_susscess? BOLDGREEN : ""  , cntr.stat.post_upload_susscess , cntr.stat.post_upload_susscess? RESET : "",
							cntr.stat.post_upload_fail    ? BOLDRED   : ""  , cntr.stat.post_upload_fail     , cntr.stat.post_upload_fail ? RESET    : "");
		}
		if (last.http_via[0])
		{
			fprintf(dst_output , "Server HTTP VIA=%s\n",last.http_via);
		}
		if (last.x_forwarded_for[0])
		{
			fprintf(dst_output , "Server X-forwarded-for=%s\n",last.x_forwarded_for);
		}
		if (last.ssl_sess_id_from_html[0])
		{
			fprintf(dst_output , "SSL ID=%s\n",last.ssl_sess_id_from_html);
		}
		fprintf(dst_output , "Elapsed time=%d.%d sec.\n",run_time.sec , run_time.slice_100_msec );
	}

	//	if (cfg.flag.display_counters.val)
	{
		fprintf(dst_output , "%s\n",slide_bar_with_counters);
		print_counters(dst_output);
		//		print_rx_threads_counters(dst_output);
	}

	if (cntr.stat.open_sockets == 0)
	{
		char rotate_ch[2] = {0};
		static int cntr_local = 0;
		cntr_local++;
		if (cntr_local <= 2) /*200 msec*/
		{
			rotate_ch[0] = '\\';
		}
		else if ((cntr_local > 2) && (cntr_local <= 4)) /*200 msec*/
		{
			rotate_ch[0] = '|';
		}
		else if ((cntr_local > 4) && (cntr_local <= 6)) /*200 msec*/
		{
			rotate_ch[0] = '/';
		}
		else if ((cntr_local > 6) && (cntr_local <= 8)) /*200 msec*/
		{
			rotate_ch[0] = '-';
		}
		if (cntr_local == 8)
		{
			cntr_local = 0;
		}

		fprintf(dst_output , "connecting...\n%s\n", rotate_ch);
		if (errno_exit_buf[0])
		{
			fprintf(dst_output , "%s\n", errno_exit_buf);
		}
	}

	/****slide_bar_with_usage*****/
	fprintf(dst_output , "%s\n",slide_bar_with_usage);

	/*update printing status*/
	last.print_status = PR_STAT_READY;/*mark that it ready to be filled*/
}

/*********************************/
void print_final_summary()
{
	struct timespec final_time;
	/*get current time*/
	clock_gettime( CLOCK_REALTIME , &final_time);
	time (&ending_time);
	void* fp = fopen(LOG_FILE_NAME , "a");
	if (fp != NULL)
	{
		fprintf(fp , ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
		fprintf(fp , "Start time=%s",ctime(&starting_time));
		fprintf(fp , "%s\n",original_full_command);
		print_overlap_values(fp);
		fprintf(fp , "Total running time=%lu sec.\n",(final_time.tv_sec - start_time.tv_sec));
		fprintf(fp , "End time=%s\n",ctime(&ending_time));
		fprintf(fp , "That's all!\n\n");
		fprintf(fp , "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n");
		fclose(fp);
	}

	printf("Total running time=%lu sec.\n",(final_time.tv_sec - start_time.tv_sec));
	printf("That's all!\n\n");
}


/*********************************/
void print_to_file(char *string)
{
	void* fp = fopen(LOG_FILE_NAME , "a");
	if (fp != NULL)
	{
		fprintf(fp , "%s\n",string);
		fclose(fp);
	}
}


/*********************************/
void print_to_file_name(char * file_name , char *buf_to_print)
{
	void* fp = fopen(file_name , "a");
	if (fp != NULL)
	{
		fprintf(fp , "%s\n",buf_to_print);
		fclose(fp);
	}
}

/*********************************/
void get_tcp_info(uint fd_idx)
{
	socklen_t tcp_info_length;
	tcp_info_length = sizeof(struct tcp_info);
	struct tcp_info tcpi = {'\0'};
	int fd = fd_db[fd_idx].gen.fd;
	char print_buf[DEBUG_BUF_SIZE+1];

	if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, (void *)&tcpi, &tcp_info_length) < 0)
	{
		fprintf(stderr , "%s(%d):getsockopt error - %s\n",FUNC_LINE, strerror(errno));
		PANIC_NO_DUMP(1);
	}
	else
	{
		snprintf(print_buf ,DEBUG_BUF_SIZE, "fd=%d:\nlast_sent=%u , last_recv=%u , lost=%u , retrans=%u , retransmits=%u , total_retrans=%u , reorder=%u\n"
				,fd , tcpi.tcpi_last_data_sent , tcpi.tcpi_last_data_recv, tcpi.tcpi_lost , tcpi.tcpi_retrans , tcpi.tcpi_retransmits , tcpi.tcpi_total_retrans , tcpi.tcpi_reordering);
		print_to_file_name("tmp.txt" , print_buf);
	}
}

/*********************************/
/*see below example to use timestamp*/
#ifdef TIMER_TEST
struct timespec start , stop;
clock_gettime(CLOCK_REALTIME, &start);
clock_gettime(CLOCK_REALTIME, &stop);
char buf[500 + 1] , buf2[500 + 1];

sprintf(buf , "start:%ld.%ld , stop:%ld:%ld , delta:%s\n" ,
		start.tv_sec , start.tv_nsec ,
		stop.tv_sec , stop.tv_nsec ,
		calc_time_diff(buf2 , 500 , start , stop));
print_to_file_name("timer_test.txt" , buf);
#endif
char* calc_time_diff(char *buf , uint size_of_buf , struct timespec start , struct timespec stop)
{
	long int nanosec_diff = 0 , sec_diff = 0;

	if (stop.tv_nsec > start.tv_nsec)
	{
		nanosec_diff = stop.tv_nsec - start.tv_nsec;
		sec_diff = stop.tv_sec - start.tv_sec;
	}
	else
	{
		nanosec_diff = (stop.tv_nsec + 1000000000) - start.tv_nsec;
		sec_diff = stop.tv_sec - start.tv_sec + 1;
	}
	snprintf(buf , size_of_buf , "%ld.%ld" ,
			sec_diff ,
			nanosec_diff);

	return buf;
}


