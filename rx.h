/*
 * rx.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  rx.h is part of vazaget.
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

#ifndef RX_H_
#define RX_H_

typedef struct
{
	int 			active; /*mark that this is active thread*/
	int 			local_RX_th_idx;
	pthread_t 		RX_th_id;
}RX_gen_t;

typedef struct
{
	int 			efd; /*epoll fd*/
	struct epoll_event event;
	struct epoll_event *events;
}RX_epoll_t;

typedef struct
{
	uint	closed_sockets;
}RX_counters_t;

typedef struct
{
	RX_gen_t		gen;
	RX_epoll_t		epoll;
	RX_counters_t	cntr;
}RX_thread_db_t;
RX_thread_db_t *rx_th_db;

typedef struct
{
	uint64_t file_size;
}file_download_global_t;
file_download_global_t file_download_global;

/*********LAST_DB*********/
/*last struct - hold last recevied values, use for compare and print*/
typedef struct
{
	char srv_src_ip[INET6_ADDRSTRLEN+1];
	char srv_src_port[PORT_STRING_LENGTH+1];
	char srv_dst_port[PORT_STRING_LENGTH+1];
	char srv_http_proto[MAX_HTTP_PROTO_LENGTH+1];

	char client_src_ip[INET6_ADDRSTRLEN+1];
	char client_src_port[PORT_STRING_LENGTH+1];
	char client_dst_ip[INET6_ADDRSTRLEN+1];
	char client_dst_port[PORT_STRING_LENGTH+1];
	char client_http_proto[MAX_HTTP_PROTO_LENGTH+1];

	char http_via[MAX_SSLID_LENGTH+1];
	char x_forwarded_for[MAX_SSLID_LENGTH+1];

	char ssl_sess_id_from_html[MAX_SSLID_LENGTH+1];
	char cookie_parsed_from_html[MAX_COOKIE_LENGTH+1];
	int  cookie_copy_done; /*this is like mutex, to verify we finish copy cookie, and only then use it*/
	char cookie_rcv_from_reply[MAX_PARSED_COOKIES][MAX_COOKIE_LENGTH+1];
	char print_status; /*this flag will save the copy time to values that only printed, so they will be done only once in 100msec*/
}last_rcv;
last_rcv last;

/**********FUNCTIONS*************/
void *thread_RX();
void *thread_RX_listener();
void add_fd_to_epoll(int fd , uint fd_idx);
void epoll_modify_remove_EPOLLIN(uint fd_idx);
void epoll_modify_add_EPOLLIN(uint fd_idx);
void RX_threads_creator();
void remove_fd_from_epoll(uint fd_idx);
uint rx_to_disk(uint fd_idx, uint recv_bytes, char *tmp_buf);
void clear_fd_db(uint fd_idx , uint clear_db_level);
void clear_parser_data(uint fd_idx);
char *remove_quotes(char *input, uint max_length);
void init_default_bwR_values_per_fd(uint fd_idx);
void close_fd_db(uint fd_idx , uint reason);
void close_socket(uint fd_idx, uint skip_shutdown);
uint add_fd_to_db (uint fd_idx , int fd);
int analyze_http_reply(char *buf, uint fd_idx , char *tmp_buf , uint recv_bytes);
void test_http_parse();
void parse_http_pkt(char *buf, uint fd_idx , char *tmp_buf , uint recv_bytes);
uint update_fd_db_dst_values(uint fd_idx);
void delete_file_from_disk(char *file_to_del);
int is_content_length_fully_received(uint fd_idx);
void erase_all_chunk_data(uint fd_idx, uint stop_procsess_chunks);
uint write_to_binary_file(char* file_name , char *buf , uint length);
uint is_session_chunk(uint fd_idx);
uint handle_rx_chunk_buf(uint fd_idx, uint recv_bytes, char *tmp_buf);

#endif /* RX_H_ */
