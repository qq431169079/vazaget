/*
 * tx.h
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  tx.h is part of vazaget.
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

#ifndef TX_H_
#define TX_H_

typedef struct
{
	pthread_mutex_t tx_now; /*this mutex uses to synchronize between RX and TX threads, it will keep the TX thread block as long as the RX didn't finish processing all required data*/
	uint 			active; /*mark that this is active thread*/
	uint 			local_th_idx;
	uint			sess_per_th;
	uint			thread_open_sockets;
	pthread_t 		tx_th_id;
	uint 			fd_idx_start;
	uint 			fd_idx_span;
	sig_atomic_t 	th_active_sessions;
	sig_atomic_t 	go_down_now;
}TX_thread_db_t;
TX_thread_db_t *tx_th_db;

/*States*/
typedef enum {
	TX_STATE_READY,
	TX_STATE_SOCKET_CREATED,
	TX_STATE_SOCKET_CONNECTED,
	TX_STATE_PKT_SENT,
	TX_STATE_MAX
}TX_STATES;

/*TX*/
void TX_threads_creator();
void tx_now(uint th_idx);
void tx_add_pending_buf(uint fd_idx);
void wake_up_tx_thread(uint tx_th_idx);
void wake_up_all_tx_thread();
void check_and_wake_tx_threads();
void zero_tx_buf(uint fd_idx);
void verify_buf_guards(uint fd_idx);
void init_default_bwT_values_per_fd(uint fd_idx);
void build_http_get_request(char *http_get_request, parser_struct *parsed_msg, uint fd_idx);
void build_http_post_request(char *http_post_request, parser_struct *parsed_msg, uint fd_idx, char *boundary_string, int content_length);
uint get_available_fd_and_tx_thread(uint *th_idx , uint *fd_idx);
uint accept_new_fd(int new_fd);
uint create_new_fd_db(uint fd_idx , uint th_idx , uri_parser	*dst_direct ,  uri_parser	*dst_proxy);
uint tx_create_new_socket(uint fd_idx , int fd);
uint update_fd_db_values(uint fd_idx);
uint make_socket_non_blocking (int fd);
uint rearm_tx_now(uint fd_idx);

#endif /* TX_H_ */
