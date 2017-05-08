/*
 * rx_range.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  rx_range.h is part of vazaget.
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

#ifndef RX_RANGE_H_
#define RX_RANGE_H_

/** Range **/
#define RANGE_DEFAULT_SIZE		700000
#define RANGE_WROTE_TO_DISK		0
#define RANGE_PENDING			1
#define RANGE_PENDING_VIA_RX	2
#define RANGE_PENDING_VIA_TIMER	3

#define RANGE_TX_PRIORITY_ENA
#define __RANGE_RX_PRIORITY_ENA
#define __RANGE_EXTEND_PRINTS

/**********Range Global values*************/

typedef struct
{
	char 		*range_tmp_file_name;
	uint 		state;
	uint64_t	range_start; /*range_start offset*/
	uint64_t	range_end; /*range_end offset*/
	uint 		sec;	/*time in sec*/
	uint 		priority; /*for now use only 0 and 1, where 1 is the highest priority of the cur range */
#ifdef RANGE_WRITE_TEST
	int			range_file_fd;
#endif

}range_table_t;

typedef struct
{
	char			*final_file_name; /*This will be the final full payload, after all ranges arrived and concutenated*/
	char			*tmp_file_name; /*This is the temp range collector, will be deleted after all ranges fully received*/
	uint64_t 		expected_file_size; /*expected full file size*/
	uint64_t 		cur_file_size; /*how much collected so far*/
	uint 			global_range_block_size; /*single chunk size - every RX thread  will fetch it at it's iteration*/
	uint64_t 		last_range_fatch; /*keep the highest range end, instead of looping over all the table every time*/
	uint64_t 		next_start_to_send; /*hold the next start to send, in order to prioritize TX*/
	char			get_sent_in_last_100msec_slice;
	char			range_pending_on_timer;
	pthread_mutex_t range_table_mutex; /*mutex control writing to range table*/
	range_table_t	*range_table; /*the array of range table*/
}range_global_t;
range_global_t range_global;

/*RX-RANGE States*/
typedef enum {
	RANGE_NOT_IN_USE = 0,
	RANGE_IN_USE,
	RANGE_RESTART_ON_NEW_FD, /*close the socket, but don't delete the start and end, so it will ask this rangew again.*/
	RANGE_HTTP_CLOSE,
	RANGE_MAX
}RANGE_STATES;

/**********FUNCTIONS*************/
uint is_session_range(uint fd_idx);
uint handle_rx_range_buf(uint fd_idx, uint recv_bytes, char *tmp_buf);
uint init_range_fd_idx(uint fd_idx);
void init_range_global(uint max_active_sessions);
uint init_range_buf(uint fd_idx);
void init_range_table(uint max_active_sessions);
uint range_write_to_disk(uint fd_idx);
void range_table_remove_fd(uint fd_idx);
uint more_ranges_to_fetch();
char *found_valid_file_name(char *original_filename);
uint range_validate_retrun_code(uint fd_idx);
void range_global_1_sec_timer();
uint rx_range_handle_pending_buf_from_timer();
uint is_more_to_receive(uint fd_idx);
void range_check_stuck_sockets(uint my_RX_th_idx);
uint validate_rx_range_idx(uint fd_idx);
char *http_parse(char *buf, parser_struct *parsed_msg, uint max_chars_to_parse);
void http_status_code_counters(parser_struct *parsed_msg);
uint decompress_gzip( uint fd_idx ,parser_struct *parsed_msg , char *extract_buf);
uint rx_analyze_payload_content(uint fd_idx);
void save_cookie_from_reply(parser_struct *parsed_msg, uint fd_idx);
uint append_src_file_to_dst_file(char *src_file , char *dst_file , uint del_src_after_copy);
char *range_get_range_file_name(uint fd_idx);
uint range_can_I_send_now(uint fd_idx);
void range_update_next_get_to_send(uint fd_idx);

#endif /* RX_RANGE_H_ */
