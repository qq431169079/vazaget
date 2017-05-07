/* tx.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  tx.c is part of vazaget.
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
#include <errno.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include "global.h"
#include "ssl_mbedtls.h"
#include "data_sender.h"
#include "rx_range.h"
#include "rx.h"
#include "ssl_vazaget.h"
#include "tx.h"
#include "prints.h"
#include "config.h"
#include "timer.h"
#include "close.h"

extern sig_atomic_t th_rx_up;
extern sig_atomic_t watchdog_event_timer;
extern char errno_exit_buf[EXIT_BUF_LEN];

#define TCP_CA_NAME_MAX 16


/**********************************************************/
/*get_available_fd_and_tx_thread*/
/**********************************************************/
uint get_available_fd_idx_per_tx(uint th_idx , uint *fd_idx)
{
	uint th_start_fd_idx = tx_th_db[th_idx].fd_idx_start;
	uint th_end_fd_idx = tx_th_db[th_idx].fd_idx_start + tx_th_db[th_idx].fd_idx_span;

	for ((*fd_idx)=th_start_fd_idx ; (*fd_idx)<th_end_fd_idx ; (*fd_idx)++)
	{
		if ((fd_db[(*fd_idx)].gen.in_use == 0) && (fd_db[(*fd_idx)].gen.fd == 0) && (tx_th_db[th_idx].thread_open_sockets < tx_th_db[th_idx].sess_per_th))
		{
			return TRUE_1;
		}
	}
	return FALSE_0;
}

/**********************************************************/
/*get_available_tx_thread*/
/**********************************************************/
uint get_available_fd_and_tx_thread(uint *th_idx , uint *fd_idx)
{
	for ((*th_idx)=0 ; (*th_idx)<(uint)cfg.int_v.tx_num_of_threads.val ;(*th_idx)++)
	{
		if ((tx_th_db[(*th_idx)].active) &&
				(tx_th_db[(*th_idx)].th_active_sessions < cfg.int_v.tx_th_active_sessions.val) &&
				(tx_th_db[(*th_idx)].thread_open_sockets < tx_th_db[(*th_idx)].sess_per_th))
		{
			if (get_available_fd_idx_per_tx((*th_idx) , fd_idx) == TRUE_1)
			{
				return TRUE_1;
			}
		}
	}
	DBG_LISTEN PRINTF_VZ_N( "**FAIL** to found available TX thread...\n");
	return FALSE_0;
}


/**********************************************************/
/*create_new_fd_on_tx_thread*/
/**********************************************************/
uint accept_new_fd(int new_fd)
{
	uint th_idx = 0xffffffff , fd_idx = 0xffffffff;
	if (get_available_fd_and_tx_thread(&th_idx , &fd_idx) != TRUE_1)
	{
		return FALSE_0;
	}
	/*sanity check*/
	PANIC_NO_DUMP(th_idx >= (uint)cfg.int_v.tx_num_of_threads.val);
	PANIC_NO_DUMP(fd_idx >= max_active_sessions);

	create_new_fd_db(fd_idx , th_idx , &cfg.dest_params , &cfg.dest_proxy_params);
	if (tx_create_new_socket(fd_idx , new_fd) != TRUE_1)
		return FALSE_0;/*should return FAIL*/

	if (update_fd_db_values(fd_idx) != TRUE_1)
		return FALSE_0;/*should return FAIL*/

	if (update_fd_db_dst_values(fd_idx) != TRUE_1)
		return FALSE_0;/*should return FAIL*/

	add_fd_to_epoll(fd_db[fd_idx].gen.fd , fd_idx);

#if 0
	/*want to pull content of highest priority only...*/
	if ((cfg.flag.range.val) && (range_global.range_table[fd_idx].priority == 0))
	{
		epoll_modify_remove_EPOLLIN(fd_idx);
	}
#endif

	if (make_socket_non_blocking(fd_db[fd_idx].gen.fd) != TRUE_1)
		return FALSE_0;/*should return FAIL*/

	fd_db[fd_idx].tx.tx_state = TX_STATE_SOCKET_CONNECTED;
	tx_th_db[th_idx].thread_open_sockets++;
	DBG_LISTEN PRINTF_VZ("(fd_idx=%d,fd=%d) remote=%x:%d ,src=%s:%s, dst=%s:%s\n",
			fd_idx ,fd_db[fd_idx].gen.fd , fd_db[fd_idx].gen.server_v4.sin_addr.s_addr , ntohs(fd_db[fd_idx].gen.server_v4.sin_port) ,
			fd_db[fd_idx].client.client_src_ip , fd_db[fd_idx].client.client_src_port , fd_db[fd_idx].client.client_dst_ip , fd_db[fd_idx].client.client_dst_port);
	return TRUE_1;
}
/**********************************************************/
/*remove_quotes*/
/**********************************************************/
char *remove_quotes(char *input, uint max_length)
{
	char *return_string;
	uint string_length;
	if (input == NULL)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): input cannot be NULL\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	return_string = &input[0];
	if (input[0] == '"')
	{
		return_string = &input[1];
	}
	string_length = (uint)strnlen(input , max_length);
	if (input[string_length-1] == '"')
	{
		input[string_length-1] = '\0';
	}
	return return_string;
}


/**********************************************************/
/*build_http_post_line_post_proxy*/
/**********************************************************/
void build_http_post_line_post_proxy(char *hdr_get, parser_struct *parsed_msg, uint fd_idx)
{
	char protocol[10] = {0};
	char host[HDR_STRING_LENGTH+1] = {0};
	char path[HDR_STRING_LENGTH+1] = {0};
	char http_ver[HDR_STRING_LENGTH+1] = {0};
	uri_parser *direct = &fd_db[fd_idx].gen.dst_direct;

	/****PROTOCOL****/
	/*protocol - proxy*/

	if ((!IS_STRING_SET(direct->protocol_ptr)) || (parsed_msg))
	{
		sprintf (protocol , "%s" , "http://");
	}


	/****HOST****/
	if (IS_STRING_SET(direct->www_addr_ptr))
	{
		sprintf (host , "%s" , direct->www_addr_ptr);
	}
	else if (IS_STRING_SET(direct->ip_addr_ptr))
	{
		if (direct->ip_ver == IPV6)
		{
			sprintf (host , "[%s]" , direct->ip_addr_ptr);
		}
		else
		{
			sprintf (host , "%s" , direct->ip_addr_ptr);
		}
	}

	if (IS_STRING_SET(direct->port_ptr))
	{
		strcat(host , ":");
		strcat(host , direct->port_ptr);
	}

	/****PATH****/
	if (IS_STRING_SET(parsed_msg->html.form_action))
	{
		sprintf(path , "%s" , remove_quotes(parsed_msg->html.form_action , HDR_STRING_LENGTH));
	}

	sprintf(http_ver ,  "%s" , fd_db[fd_idx].client.client_http_proto);

	snprintf(hdr_get , HDR_STRING_LENGTH , "POST %s%s%s %s\r\n", protocol , host , path , http_ver );
}



/**********************************************************/
/*build_http_post_request*/
//example: GET / HTTP/1.1\r\nUser-Agent: VazaGet\r\nAccept: */*\r\nHost: 127.0.0.1\r\nConnection: Keep-Alive\r\n\r\n
/**********************************************************/
void build_http_post_request(char *http_post_request, parser_struct *parsed_msg, uint fd_idx, char *boundary_string, int content_length)
{
	int i;
	char hdr_post[HDR_STRING_LENGTH+1]={0};
	char hdr_user_agent[HDR_STRING_LENGTH+1]={0};
	char hdr_accept[HDR_STRING_LENGTH+1]={"Accept: */*\r\n"};
	char hdr_host[HDR_STRING_LENGTH+1]={0};
	char hdr_connection[HDR_STRING_LENGTH+1]={0};
	char hdr_encoding_gzip[HDR_STRING_LENGTH+1]={"Accept-Encoding: gzip\r\n"};
	char hdr_X_vazaget[MAX_COOKIE_LENGTH+1]={0};
	char hdr_referer[MAX_COOKIE_LENGTH+1]={0};
	char hdr_cookie[MAX_COOKIE_LENGTH+1]={0};
	char hdr_end[HDR_STRING_LENGTH+1]={EOL_PRINT};
	char hdr_content_type[HDR_STRING_LENGTH+1]={0};
	char hdr_content_length[HDR_STRING_LENGTH+1]={0};
	uri_parser *direct = &fd_db[fd_idx].gen.dst_direct;

	if (parsed_msg == NULL)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): parsed_msg cannot be NULL\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}


	/*PATH*/
	/*e.g. --> POST /upload_file.php HTTP/1.1*/
	if (IS_PROXY(fd_idx))
	{/*Proxy connection*/
		build_http_post_line_post_proxy(hdr_post , parsed_msg , fd_idx);
	}
	else
	{
		sprintf(hdr_post ,  "POST %s %s\r\n" , remove_quotes((parsed_msg->html.form_action) , HDR_STRING_LENGTH), fd_db[fd_idx].client.client_http_proto /*"HTTP/1.0"*/);
	}


	/*HOST*/
	if (IS_STRING_SET(direct->www_addr_ptr))
	{
		if ((parsed_msg) && (IS_STRING_SET(parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: %s\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			sprintf(hdr_host , "Host: %s%s%s\r\n" , direct->www_addr_ptr,
					(IS_STRING_SET(direct->port_ptr)) ? ":" : "" ,
							(IS_STRING_SET(direct->port_ptr)) ? direct->port_ptr : "" );
		}
	}
	else if (fd_db[fd_idx].gen.ip_ver == IPV6)
	{
		if ((parsed_msg) && (IS_STRING_SET(parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: [%s]\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			sprintf(hdr_host , "Host: [%s]%s%s\r\n" , direct->ip_addr_ptr,
					(IS_STRING_SET(direct->port_ptr)) ? ":" : "" ,
							(IS_STRING_SET(direct->port_ptr)) ? direct->port_ptr : "" );
		}
	}
	else
	{
		if ((parsed_msg) && IS_STRING_SET((parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: %s\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			sprintf(hdr_host , "Host: %s\r\n" , direct->ip_addr_ptr);
		}
	}

	/*User-Agent*/
	sprintf(hdr_user_agent ,  "User-Agent: VazaGet/%s%s\r\n" , VAZAGET_VERSION , BUILD_PLATFORM);

	/*Referer*/
	if ( IS_STRING_SET(direct->www_addr_ptr))
	{
		sprintf(hdr_referer , "Referer: http://%s%s%s%s\r\n" , direct->www_addr_ptr ,
				(IS_STRING_SET(direct->port_ptr)) ? ":" : "" ,
						(IS_STRING_SET(direct->port_ptr)) ? direct->port_ptr : "" ,
								remove_quotes(parsed_msg->html.form_action , HDR_STRING_LENGTH));
	}
	else
	{
		if (direct->ip_ver == IPV6)
		{
			sprintf(hdr_referer , "Referer: http://[%s]%s%s%s\r\n" , direct->ip_addr_isolate_string ,
					(IS_STRING_SET(direct->port_ptr)) ? ":" : "" ,
							(IS_STRING_SET(direct->port_ptr)) ? direct->port_ptr : "" ,
									remove_quotes(parsed_msg->html.form_action , HDR_STRING_LENGTH));
		}
		else
		{
			sprintf(hdr_referer , "Referer: http://%s%s%s%s\r\n" , direct->ip_addr_isolate_string ,
					(IS_STRING_SET(direct->port_ptr)) ? ":" : "" ,
							(IS_STRING_SET(direct->port_ptr)) ? direct->port_ptr : "" ,
									remove_quotes(parsed_msg->html.form_action , HDR_STRING_LENGTH));
		}
	}

	/*Cookie*/
	if (cfg.str_v.cookie_string_cli[0])
	{
		sprintf(hdr_cookie,"Cookie: %s\r\n" , cfg.str_v.cookie_string_cli);
	}
	else if ((cfg.flag.cookie_from_reply.val) && (last.cookie_copy_done) && (last.cookie_rcv_from_reply[0][0]))
	{
		sprintf(hdr_cookie,"Cookie: ");
		for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
		{
			if (last.cookie_rcv_from_reply[i][0])
			{
				char tmp[MAX_COOKIE_LENGTH]={0};
				sprintf(tmp,"%s;", last.cookie_rcv_from_reply[i]);
				strncat(hdr_cookie, tmp , MAX_COOKIE_LENGTH);
			}
		}
		strncat(hdr_cookie, hdr_end , strlen(hdr_end));
	}

	/*hdr_connection*/
	if (IS_PROXY(fd_idx))
	{/*send to proxy*/
		sprintf(hdr_connection , "Proxy-Connection: Keep-Alive\r\n");
	}
	else
	{ /*send to dst IP*/
		sprintf(hdr_connection , "Connection: Keep-Alive\r\n");
	}


	sprintf(hdr_content_type ,"Content-Type: multipart/form-data; boundary=%s\r\n" , boundary_string);

	/*hdr_X_vazaget*/
	sprintf(hdr_X_vazaget , "X-vazaget: ID=%d\r\n" , cntr.stat.open_sockets);

	/*hdr_content_length*/
	sprintf(hdr_content_length , "Content-Length: %d\r\n\r\n" , content_length);

	/*Copy all parts into the http_post_request*/
	sprintf(http_post_request , "%s", hdr_post); /*start with sprintf in order to start write to beginning of buffer*/
	strncat(http_post_request , hdr_host 		, HDR_STRING_LENGTH);
	strncat(http_post_request , hdr_user_agent 	, HDR_STRING_LENGTH);
	strncat(http_post_request , hdr_accept 		, HDR_STRING_LENGTH);
	if (cfg.flag.encoding_gzip.val)
	{
		strncat(http_post_request , hdr_encoding_gzip	, HDR_STRING_LENGTH);
	}
	strncat(http_post_request , hdr_X_vazaget		, HDR_STRING_LENGTH);
	strncat(http_post_request , hdr_referer		, HDR_STRING_LENGTH);
	if (hdr_cookie[0])
	{
		strncat(http_post_request , hdr_cookie 	, MAX_COOKIE_LENGTH);
	}
	strncat(http_post_request , hdr_connection 	, HDR_STRING_LENGTH);
	strncat(http_post_request , hdr_content_type , HDR_STRING_LENGTH);
	strncat(http_post_request , hdr_content_length 	, HDR_STRING_LENGTH);
	//	strncat(http_post_request , hdr_end 		, strlen(hdr_end));

	return;
}

/**********************************************************/
/*build_http_get_line_get_direct*/
/**********************************************************/
void build_http_get_line_get_direct(char *hdr_get, parser_struct *parsed_msg, uint fd_idx)
{
	char host[HDR_STRING_LENGTH+1] = {0};
	char path[HDR_STRING_LENGTH+1] = {0};
	char http_ver[HDR_STRING_LENGTH+1] = {0};
	uri_parser *direct = &fd_db[fd_idx].gen.dst_direct;


	/****HOST****/
	/*host - parsed_msg (301)*/
	if (parsed_msg)
	{
		sprintf (host , "/");
	}
	/*host - direct*/
	else
	{
		/*none - for direct will be filled in the path*/
	}

	/****PATH****/
	/*path - parsed_msg (301)*/
	if (parsed_msg)
	{
		if (IS_STRING_SET(parsed_msg->http.location_path))
		{
			sprintf (path , "%s" , parsed_msg->http.location_path);
		}
	}
	/*path - direct*/
	else
	{
		if ((!IS_STRING_SET(direct->path_ptr)) && (!IS_STRING_SET(direct->file_name_ptr)))
		{/*no path and no file name*/
			sprintf (path , "/");
		}
		else
		{
			if (IS_STRING_SET(direct->path_ptr))
			{
				sprintf (path , "/%s",direct->path_ptr);
			}

			if (direct->file_name_ptr)
			{
				char tmp[HDR_STRING_LENGTH+1] = {0};
				sprintf (tmp , "/%s",direct->file_name_ptr);
				strcat (path , tmp);
			}
		}
	}

	sprintf(http_ver ,  "%s" , fd_db[fd_idx].client.client_http_proto);

	snprintf(hdr_get , HDR_STRING_LENGTH , "GET %s%s %s\r\n" , host , path , http_ver );
}

/**********************************************************/
/*build_http_get_line_get_proxy*/
/**********************************************************/
void build_http_get_line_get_proxy(char *hdr_get, parser_struct *parsed_msg, uint fd_idx)
{
	char protocol[10] = {0};
	char host[HDR_STRING_LENGTH+1] = {0};
	char path[HDR_STRING_LENGTH+1] = {0};
	char http_ver[HDR_STRING_LENGTH+1] = {0};
	uri_parser *direct = &fd_db[fd_idx].gen.dst_direct;

	/****PROTOCOL****/
	/*protocol - proxy*/

	if ((!IS_STRING_SET(direct->protocol_ptr)) || (parsed_msg))
	{
		sprintf (protocol , "%s" , "http://");
	}


	/****HOST****/
	/*host - parsed_msg (301)*/
	if (!parsed_msg)
	{/*NOT proxy*/
		/* copy from the direct->orig_full_uri */
		sprintf (host , "%s" , direct->orig_full_uri);
	}

	/****PATH****/
	/*path - parsed_msg (301)*/
	if (parsed_msg)
	{
		if ((IS_STRING_SET(parsed_msg->http.location_host)) && (IS_STRING_SET(parsed_msg->http.location_path)))
		{
			sprintf (path , "%s/%s" , parsed_msg->http.location_host , parsed_msg->http.location_path);
		}
	}
	/*path - proxy*/
	else
	{
		/*none, in this case, using the host = direct->orig_full_uri*/
	}


	sprintf(http_ver ,  "%s" , fd_db[fd_idx].client.client_http_proto);

	snprintf(hdr_get , HDR_STRING_LENGTH , "GET %s%s%s %s\r\n", protocol , host , path , http_ver );
}

/**********************************************************/
/*build_http_get_line_get_proxy*/
/**********************************************************/
void build_http_get_line_host(char *hdr_host, parser_struct *parsed_msg, uint fd_idx)
{
	uri_parser *direct = &fd_db[fd_idx].gen.dst_direct;

	/*HOST - www address*/
	if (IS_STRING_SET(direct->www_addr_ptr))
	{
		if ((parsed_msg) && (IS_STRING_SET(parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: %s\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			char *port_ptr = direct->port_ptr;
			sprintf(hdr_host , "Host: %s%s%s\r\n" , direct->www_addr_ptr,
					(cfg.int_v.port.val==DEFAULT_PORT || cfg.int_v.port.val==DEFAULT_SSL_PORT) ? "" : ":",
							(cfg.int_v.port.val==DEFAULT_PORT || cfg.int_v.port.val==DEFAULT_SSL_PORT) ? "" : ((port_ptr && port_ptr[0]) ? port_ptr : ""));
		}
	}
	/*HOST - v6*/
	else if (direct->ip_ver == IPV6)
	{
		if ((parsed_msg) && (IS_STRING_SET(parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: %s\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			char *port_ptr = direct->port_ptr;
			if (direct->www_addr_ptr)
			{
				sprintf(hdr_host , "Host: %s%s%s\r\n" , direct->www_addr_ptr,
						((IS_STRING_SET(port_ptr))) ? ":" : "",
								((IS_STRING_SET(port_ptr)) ? port_ptr : ""));
			}
			else
			{
				sprintf(hdr_host , "Host: [%s]%s%s\r\n" , direct->ip_addr_ptr,
						((IS_STRING_SET(port_ptr))) ? ":" : "",
								((IS_STRING_SET(port_ptr)) ? port_ptr : ""));
			}
		}
	}
	else
	{
		if ((parsed_msg) && (IS_STRING_SET(parsed_msg->http.location_host)))
		{
			sprintf(hdr_host , "Host: %s\r\n" , parsed_msg->http.location_host);
		}
		else
		{
			char *port_ptr = direct->port_ptr;
			sprintf(hdr_host , "Host: %s%s%s\r\n" , direct->ip_addr_ptr,
					((IS_STRING_SET(port_ptr))) ? ":" : "",
							((IS_STRING_SET(port_ptr)) ? port_ptr : ""));
		}
	}
}


/**********************************************************/
/*build_http_get_line_cookie*/
/**********************************************************/
void build_http_get_line_cookie(char *hdr_cookie, char* hdr_end, uint fd_idx)
{
	uint cookie_idx = 0;
	if (cfg.flag.range.val)
	{
		uint max_cookie_len_to_copy = MAX_COOKIE_LENGTH;

		if (IS_STRING_SET(fd_db[fd_idx].non_del.cookie_struct[0].cookie_ptr))
		{
			sprintf(hdr_cookie,"Cookie: ");
			for (cookie_idx = 0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
			{
				if (IS_STRING_SET(fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_ptr))
				{
					strncat(hdr_cookie, fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_ptr , max_cookie_len_to_copy);
					max_cookie_len_to_copy = max_cookie_len_to_copy - (uint)strlen(fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_ptr);
				}
			}
			strncat(hdr_cookie, hdr_end , strlen(hdr_end));
		}
	}
	else

		if (cfg.str_v.cookie_string_cli[0])
		{
			sprintf(hdr_cookie,"Cookie: %s\r\n" , cfg.str_v.cookie_string_cli);
		}
		else if ((cfg.flag.cookie_from_reply.val) && (last.cookie_copy_done) && (last.cookie_rcv_from_reply[0][0]))
		{
			sprintf(hdr_cookie,"Cookie: ");
			for (cookie_idx = 0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
			{
				if (last.cookie_rcv_from_reply[cookie_idx][0])
				{
					char tmp[MAX_COOKIE_LENGTH]={0};
					sprintf(tmp,"%s;", last.cookie_rcv_from_reply[cookie_idx]);
					strncat(hdr_cookie, tmp , MAX_COOKIE_LENGTH);
				}
			}
			strncat(hdr_cookie, hdr_end , strlen(hdr_end));
		}
}

/**********************************************************/
/*build_http_get_request*/
//example: GET / HTTP/1.1\r\nUser-Agent: VazaGet\r\nAccept: */*\r\nHost: 127.0.0.1\r\nConnection: Keep-Alive\r\n\r\n
/**********************************************************/
void build_http_get_request(char *http_get_request, parser_struct *parsed_msg, uint fd_idx)
{
	char hdr_get[HDR_STRING_LENGTH+1]/*=			{0}*/;
	char hdr_user_agent[HDR_STRING_LENGTH+1]/*=	{0}*/;
	char hdr_accept[]=							{"Accept: */*\r\n"};
	char hdr_host[HDR_STRING_LENGTH+1]/*=			{0}*/;
	char hdr_connection[HDR_STRING_LENGTH+1]/*=	{0}*/;
	char hdr_encoding_gzip[]=					{"Accept-Encoding: gzip\r\n"};
	char hdr_range[HDR_STRING_LENGTH+1]/*=		{0}*/;
	char hdr_X_vazaget[MAX_COOKIE_LENGTH+1]/*=	{0}*/;
	char hdr_cookie[MAX_COOKIE_LENGTH+1]/*=		{0}*/;
	char hdr_end[]=								{EOL_PRINT};

	/*init headrs*/
	hdr_get[0] = '\0';
	hdr_user_agent[0] = '\0';
	hdr_host[0] = '\0';
	hdr_connection[0] = '\0';
	hdr_range[0] = '\0';
	hdr_X_vazaget[0] = '\0';
	hdr_cookie[0] = '\0';


	/*User-Agent*/
	if (IS_STRING_SET(cfg.str_v.ua))
	{
		sprintf(hdr_user_agent ,  "User-Agent: %s\r\n" , cfg.str_v.ua);
	}
	else
	{
		sprintf(hdr_user_agent ,  "User-Agent: vazaGet/%s%s\r\n" , VAZAGET_VERSION , BUILD_PLATFORM);

		/*hdr_X_vazaget*/
		if (cfg.flag.range.val)
		{
			sprintf(hdr_X_vazaget , "X-vazaGet: ID=%d_%d_%d_%d\r\n" ,
					cntr.stat.open_sockets , fd_idx, fd_db[fd_idx].non_del.session_cntr, fd_db[fd_idx].tx.tx_th_idx);
		}
		else
		{
			sprintf(hdr_X_vazaget , "X-vazaGet: ID=%d_%d_%d\r\n" , cntr.stat.open_sockets, fd_idx, fd_db[fd_idx].tx.tx_th_idx);
		}
	}
	/*GET*/
	if (IS_PROXY(fd_idx))
	{
		build_http_get_line_get_proxy(hdr_get , parsed_msg , fd_idx);
	}
	else
	{
		build_http_get_line_get_direct(hdr_get , parsed_msg , fd_idx);
	}

	/*HOST*/
	build_http_get_line_host(hdr_host , parsed_msg , fd_idx);

	/*Cookie*/
	build_http_get_line_cookie(hdr_cookie , hdr_end , fd_idx);
#if 0
	if (cfg.flag.range.val)
	{
		uint max_cookie_len_to_copy = MAX_COOKIE_LENGTH;

		if (IS_STRING_SET(fd_db[fd_idx].non_del.cookie_struct[0].cookie_ptr))
		{
			sprintf(hdr_cookie,"Cookie: ");
			for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
			{
				if (IS_STRING_SET(fd_db[fd_idx].non_del.cookie_struct[i].cookie_ptr))
				{
					strncat(hdr_cookie, fd_db[fd_idx].non_del.cookie_struct[i].cookie_ptr , max_cookie_len_to_copy);
					max_cookie_len_to_copy = max_cookie_len_to_copy - (uint)strlen(fd_db[fd_idx].non_del.cookie_struct[i].cookie_ptr);
				}
			}
			strncat(hdr_cookie, hdr_end , strlen(hdr_end));
		}
	}
	else

		if (cfg.str_v.cookie_string_cli[0])
		{
			sprintf(hdr_cookie,"Cookie: %s\r\n" , cfg.str_v.cookie_string_cli);
		}
		else if ((cfg.flag.cookie_from_reply.val) && (last.cookie_copy_done) && (last.cookie_rcv_from_reply[0][0]))
		{
			sprintf(hdr_cookie,"Cookie: ");
			for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
			{
				if (last.cookie_rcv_from_reply[i][0])
				{
					char tmp[MAX_COOKIE_LENGTH]={0};
					sprintf(tmp,"%s;", last.cookie_rcv_from_reply[i]);
					strncat(hdr_cookie, tmp , MAX_COOKIE_LENGTH);
				}
			}
			strncat(hdr_cookie, hdr_end , strlen(hdr_end));
		}
#endif

	/*hdr_connection*/
	if (IS_PROXY(fd_idx))
	{/*send to proxy*/
		sprintf(hdr_connection , "Proxy-Connection: Keep-Alive\r\n");
	}
	else
	{ /*send to dst IP*/
		sprintf(hdr_connection , "Connection: Keep-Alive\r\n");
	}

	/*hdr_range*/
	if (cfg.flag.range.val)
	{
		sprintf(hdr_range , "Range: bytes=%"PRIu64"-%"PRIu64"\r\n" , *fd_db[fd_idx].rx.range.range_start , *fd_db[fd_idx].rx.range.range_end );
	}



	/*****Copy all parts into the http_get_request*****/
	sprintf(http_get_request, "%s", hdr_get); /*start with sprintf in order to start write to beginning of buffer*/
	strncat(http_get_request, hdr_user_agent 	, HDR_STRING_LENGTH);
	strncat(http_get_request, hdr_accept 		, HDR_STRING_LENGTH);
	strncat(http_get_request, hdr_host 			, HDR_STRING_LENGTH);
	if (cfg.flag.encoding_gzip.val)
	{
		strncat(http_get_request, hdr_encoding_gzip	, HDR_STRING_LENGTH);
	}
	if (!(IS_STRING_SET(cfg.str_v.ua)))
	{
		strncat(http_get_request, hdr_X_vazaget		, HDR_STRING_LENGTH);
	}
	if (hdr_cookie[0])
	{
		strncat(http_get_request, hdr_cookie 	, MAX_COOKIE_LENGTH);
	}
	strncat(http_get_request, hdr_connection 	, HDR_STRING_LENGTH);
	strncat(http_get_request, hdr_range	, HDR_STRING_LENGTH);
	strncat(http_get_request, hdr_end 		, strlen(hdr_end));

	return;
}

/*********************************/
void v6_get_src_ip_and_port_from_fd_idx(uint fd_idx)
{
	struct sockaddr_in6 addr6;
	socklen_t len = sizeof(struct sockaddr_in6);

	if (getsockname(fd_db[fd_idx].gen.fd , (struct sockaddr *)&addr6 , &len) == -1)
	{
		DBG_TX PRINTF_VZ(":getsockname error - %s\n", strerror(errno));
		exit_vz (EXIT_FAILURE , NULL);
	}

	if (inet_ntop(AF_INET6 , &(addr6.sin6_addr) , fd_db[fd_idx].client.client_src_ip , INET6_ADDRSTRLEN) == NULL)
	{
		DBG_TX PRINTF_VZ(":inet_ntop error - %s\n", strerror(errno));
		exit_vz(EXIT_FAILURE , NULL);
	}
	fd_db[fd_idx].gen.src_port = ntohs(addr6.sin6_port);
	sprintf(fd_db[fd_idx].client.client_src_port , "%d", fd_db[fd_idx].gen.src_port);


	return;
}

/*********************************/
void get_src_ip_and_port_from_fd_idx(uint fd_idx)
{
	struct sockaddr_in addr;

	socklen_t len = sizeof(struct sockaddr);
	if (getsockname(fd_db[fd_idx].gen.fd , (struct sockaddr *)&addr , &len) == -1)
	{
		PRINTF_VZ(":fd_idx=%d , fd=%d **ERROR** getsockname(),error - %s \n", fd_idx , fd_db[fd_idx].gen.fd , strerror(errno));
		PANIC(1);
	}
	strncpy(fd_db[fd_idx].client.client_src_ip , inet_ntoa(addr.sin_addr) , INET6_ADDRSTRLEN);
	fd_db[fd_idx].gen.src_port = ntohs(addr.sin_port);
	sprintf(fd_db[fd_idx].client.client_src_port , "%d", fd_db[fd_idx].gen.src_port);


	return;
}



/*********************************/
void v6_get_dst_ip_and_port_from_fd_idx(uint fd_idx)
{
	struct sockaddr_in6 addr6;
	socklen_t len = sizeof(struct sockaddr_in6);

	if (getpeername(fd_db[fd_idx].gen.fd , (struct sockaddr *)&addr6 , &len) == -1)
	{
		DBG_TX PRINTF_VZ(":getpeername error - %s\n", strerror(errno));
		exit_vz (EXIT_FAILURE , NULL);
	}

	if (inet_ntop(AF_INET6 , &(addr6.sin6_addr) , fd_db[fd_idx].client.client_dst_ip , INET6_ADDRSTRLEN) == NULL)
	{
		DBG_TX PRINTF_VZ(":v6_get_dst_ip_and_port_from_fd, inet_ntop() error - %s\n", strerror(errno));
		exit_vz (EXIT_FAILURE , NULL);
	}
	memcpy(&fd_db[fd_idx].gen.server_v6 , &addr6 , sizeof(addr6));
	strncpy(fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , fd_db[fd_idx].client.client_dst_ip , INET6_ADDRSTRLEN);
	fd_db[fd_idx].gen.dst_port = ntohs(addr6.sin6_port);
	sprintf(fd_db[fd_idx].client.client_dst_port , "%d", fd_db[fd_idx].gen.dst_port);

	return;
}

/*********************************/
void get_dst_ip_and_port_from_fd_idx(uint fd_idx)
{
	struct sockaddr_in addr;

	socklen_t len = sizeof(struct sockaddr);
	if (getpeername(fd_db[fd_idx].gen.fd , (struct sockaddr *)&addr , &len) == -1)
	{
		DBG_TX PRINTF_VZ(":getpeername error - %s\n", strerror(errno));
		exit_vz (EXIT_FAILURE , NULL);
	}

	memcpy(&fd_db[fd_idx].gen.server_v4 , &addr , sizeof(addr));
	strncpy(fd_db[fd_idx].client.client_dst_ip , inet_ntoa(addr.sin_addr) , INET6_ADDRSTRLEN);
	strncpy(fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , fd_db[fd_idx].client.client_dst_ip , INET6_ADDRSTRLEN);
	fd_db[fd_idx].gen.dst_port = ntohs(addr.sin_port);
	sprintf(fd_db[fd_idx].client.client_dst_port , "%d", fd_db[fd_idx].gen.dst_port);

	return;
}
/*********************************/
void setcockopt_per_socket(int sock)
{

	int result;
	uint  optval = 1 , len = sizeof(optval);
	struct linger SocketOptionLinger;
	uint iSocketOptionLingerLen = sizeof(struct linger);


	/*Reuse address*/
	result = setsockopt(sock , SOL_SOCKET, SO_REUSEADDR ,&optval , sizeof(optval));
	if (result == -1)
	{
		DBG_TX PRINTF_VZ(":setsockopt SO_REUSEADDR() error - %s\n", strerror(errno));
		exit_vz(EXIT_FAILURE , NULL);
	}
	/*make fewer SYN retransmitiona - couldn't still eliminate it to 1 SYN...*/
	result = setsockopt(sock , IPPROTO_TCP, TCP_SYNCNT ,&optval , len);
	if (result == -1)
	{
		DBG_TX PRINTF_VZ(":setsockopt TCP_SYNCNT error - %s\n", strerror(errno));
		exit_vz(EXIT_FAILURE , NULL);
	}

	/*Very important!!! - The socket will not stuck on FIN_WAIT state, but close immediatly...*/
	SocketOptionLinger.l_onoff = 1;
	if (cfg.flag.close_by_rst.val == 1)
	{	/*close socket by RST*/
		SocketOptionLinger.l_linger = 0;
	}
	else
	{	/*close socket by FIN*/
		SocketOptionLinger.l_linger = 1;
	}
	result = setsockopt(sock , SOL_SOCKET, SO_LINGER ,&SocketOptionLinger , iSocketOptionLingerLen);
	if (result == -1)
	{
		DBG_TX PRINTF_VZ(":setsockopt SO_LINGER error - %s\n", strerror(errno));
		exit_vz(EXIT_FAILURE , NULL);
	}

	/*change the life time of FIN_WAIT-2 state*/
	optval=1;
	result = setsockopt(sock , IPPROTO_TCP, TCP_LINGER2 ,&optval , len);
	if (result == -1)
	{
		DBG_TX PRINTF_VZ(":setsockopt TCP_LINGER2 error - %s\n", strerror(errno));
		exit_vz(EXIT_FAILURE , NULL);
	}

	/*SO_RCVBUF*/
	if (cfg.int_v.bw_rx_limit.val)
	{
		optval = avg_bytes_per_slice * 2; /*assuming the other side works is standard TCP stack, sending every packet after 200 msec, and our slice is per 100msec*/
		result = setsockopt(sock , SOL_SOCKET, SO_RCVBUF ,&optval , sizeof(optval));
		if (result == -1)
		{
			DBG_TX PRINTF_VZ(":setsockopt SO_RCVBUF error - %s\n", strerror(errno));
			exit_vz(EXIT_FAILURE , NULL);
		}
	}


	/*change the TCP_NODELAY to eliminate buffering on sending, the default can buffer up to 500msec before sending...*/
	if (cfg.flag.range.val)
	{
		optval=1;
		result = setsockopt(sock , IPPROTO_TCP, TCP_NODELAY ,&optval , len);
		if (result == -1)
		{
			DBG_TX PRINTF_VZ(":setsockopt TCP_NODELAY error - %s\n", strerror(errno));
			exit_vz(EXIT_FAILURE , NULL);
		}
	}

#if 0
	/*TCP_CONGESTION*/
	char opt_string[TCP_CA_NAME_MAX + 1];

	DBG_TX
	{
		len = TCP_CA_NAME_MAX;
		opt_string[0] = '\0';
		getsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, opt_string, &len);
		printf("setsockopt TCP_CONGESTION before change = %s\n" , opt_string);
	}

	strncpy(opt_string, "reno" , TCP_CA_NAME_MAX);
	len = strlen(opt_string);
	result = setsockopt(sock , IPPROTO_TCP, TCP_CONGESTION, opt_string, len);
	if (result == -1)
	{
		perror("setsockopt TCP_CONGESTION");
		exit(EXIT_FAILURE);
	}

	DBG_TX
	{
		len = TCP_CA_NAME_MAX;
		opt_string[0] = '\0';
		getsockopt(sock, IPPROTO_TCP, TCP_CONGESTION, opt_string, &len);
		printf("setsockopt TCP_CONGESTION after change = %s\n" , opt_string);
	}
#endif

#if 0
	int iSocketOption = 0;
	int iSocketOptionLen = sizeof(int);

	getsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&iSocketOption, &iSocketOptionLen);

	printf("Socket TCP_NODELAY = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_MAXSEG = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_CORK, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_CORK = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_KEEPIDLE = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_KEEPINTVL = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_KEEPCNT = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_SYNCNT = %d\n", iSocketOption);

	getsockopt(sock, IPPROTO_TCP, TCP_LINGER2, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket TCP_LINGER2 = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_REUSEADDR = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_ERROR = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_BROADCAST = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_KEEPALIVE = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_SNDBUF, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_SNDBUF = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_RCVBUF, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_RCVBUF = %d\n", iSocketOption);

	getsockopt(sock, SOL_SOCKET, SO_LINGER, (char *)&SocketOptionLinger, &iSocketOptionLingerLen);
	printf("Socket SO_LINGER = %d  time = %d\n", SocketOptionLinger.l_onoff, SocketOptionLinger.l_linger);

	getsockopt(sock, SOL_SOCKET, SO_RCVLOWAT, (char *)&iSocketOption, &iSocketOptionLen);
	printf("Socket SO_RCVLOWAT = %d\n", iSocketOption);
	exit (1);
#endif
}

/*********************************/
uint make_socket_non_blocking (int fd)
{
	int flags, s;

	flags = fcntl (fd, F_GETFL, 0);
	if (flags == -1)
	{
		DBG_TX PRINTF_VZ(":fcntl error - %s\n", strerror(errno));
		return FALSE_0;
	}

	flags |= O_NONBLOCK;
	s = fcntl (fd, F_SETFL, flags);
	if (s == -1)
	{
		DBG_TX PRINTF_VZ(":fcntl error - %s\n", strerror(errno));
		return FALSE_0;
	}

	return TRUE_1;
}


/*********************************/
uint tx_create_new_socket(uint fd_idx , int fd)
{
	if (fd == 0)
	{/*if fd == 0 then create new socket*/
		fd = socket((int)fd_db[fd_idx].gen.ip_ver , SOCK_STREAM, IPPROTO_TCP);
		if (fd <= 2)
		{
			DBG_TX PRINTF_VZ(":TCP socket error - %s\n", strerror(errno));
			cntr.error.sock_error++;
			cntr.stat.close_sockets++;
			return FALSE_0;
		}
	}

	if (add_fd_to_db(fd_idx , fd) == FALSE_0)
	{
		/*what to do in case of failure - close session???*/
		cntr.error.failed_to_add_fd_idx++;
		return FALSE_0;
	}

	PANIC(fd_db[fd_idx].gen.fd <= 2);

	setcockopt_per_socket(fd);
	fd_db[fd_idx].tx.tx_state = TX_STATE_SOCKET_CREATED;
	return TRUE_1;
}

/*********************************/
void zero_tx_buf(uint fd_idx)
{
	fd_db[fd_idx].buf.tx_buf[0] = '\0'; /*zero TX BUF*/
	fd_db[fd_idx].tx.buf_cur_position = 0;
	fd_db[fd_idx].tx.buf_length = 0;
}


/*********************************/
uint update_fd_db_values(uint fd_idx)
{
	if (cfg.flag.range.val)
	{
		return TRUE_1;
	}

	PANIC(fd_idx >= max_active_sessions);
	PANIC(fd_db[fd_idx].gen.fd <= 2);

	if (fd_db[fd_idx].gen.ip_ver == IPV6)
	{ /*IPv6*/
		v6_get_src_ip_and_port_from_fd_idx(fd_idx);
	}
	else
	{ /*IPv4*/
		get_src_ip_and_port_from_fd_idx(fd_idx);
	}


	return TRUE_1;
}


/*********************************/
uint update_fd_db_dst_values(uint fd_idx)
{
	PANIC(fd_idx >= max_active_sessions);
	if (fd_db[fd_idx].gen.ip_ver == IPV6)
	{ /*IPv6*/
		v6_get_dst_ip_and_port_from_fd_idx(fd_idx);
	}
	else
	{ /*IPv4*/
		get_dst_ip_and_port_from_fd_idx(fd_idx);
	}

	return TRUE_1;
}




/*********************************/
/*tx_socket_connect()*/
/*********************************/

uint tx_socket_connect(uint fd_idx)
{
	int fd = fd_db[fd_idx].gen.fd;
	int result = 0;

	PANIC(fd_db[fd_idx].gen.fd <= 2);

	if (fd_db[fd_idx].gen.ip_ver == IPV6)
	{/*IPv6*/
		memset((char *)&fd_db[fd_idx].gen.server_v6, 0, sizeof(fd_db[fd_idx].gen.server_v6));
		fd_db[fd_idx].gen.server_v6.sin6_family = (sa_family_t)fd_db[fd_idx].gen.ip_ver;
		fd_db[fd_idx].gen.server_v6.sin6_port = htons(fd_db[fd_idx].gen.dst_port);

		if (IS_PROXY(fd_idx))
		{/*send through proxy IP address*/
			result = inet_pton((int)fd_db[fd_idx].gen.ip_ver ,cfg.dest_proxy_params.ip_addr_isolate_string , &fd_db[fd_idx].gen.server_v6.sin6_addr);
		}
		else
		{/*send to dst IP*/
			result = inet_pton((int)fd_db[fd_idx].gen.ip_ver ,fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string, &fd_db[fd_idx].gen.server_v6.sin6_addr);
		}
		if (result == 0)
		{
			PRINTF_VZ_N("Illegal IPv6 address\n");
			usage();
		}
		else if (result < 0)
		{
			DBG_TX PRINTF_VZ(":inet_pton error - %s\n", strerror(errno));
			close_fd_db(fd_idx , REASON_TX_FAILED_RESOLVE_IP_ADDRESS);
			return FALSE_0;
		}
		/*set source port and bind*/
		if (cfg.int_v.src_port.val)
		{
			struct sockaddr_in6 client6_src_addr;
			bzero((char *) &client6_src_addr, sizeof(client6_src_addr));

			client6_src_addr.sin6_family = (sa_family_t)ip_ver;
			//			client_src_addr.sin6_addr = INADDR_ANY;
			client6_src_addr.sin6_port = htons((ushort)cfg.int_v.src_port.val);

			/*Bind*/
			if (bind(fd, (struct sockaddr *) &client6_src_addr, sizeof(client6_src_addr)) < 0)
			{
				char bind_ip_addr[INET6_ADDRSTRLEN+1] = {'\0'};
				inet_ntop(client6_src_addr.sin6_family , &(client6_src_addr.sin6_addr) , bind_ip_addr , INET6_ADDRSTRLEN);
				snprintf(exit_buf, EXIT_BUF_LEN, "**FAIL** bind new socket(%d) with src values: %s : %d, probably socket src port already in use...\n",fd , bind_ip_addr , cfg.int_v.src_port.val);
				DBG_TX PRINTF_VZ(":bind error - %s\n", strerror(errno));
				exit_vz(EXIT_FAILURE, exit_buf);
			}
		}

		if (connect(fd,(struct sockaddr *) &fd_db[fd_idx].gen.server_v6,sizeof(fd_db[fd_idx].gen.server_v6)) < 0)
		{
			DBG_TX PRINTF_VZ(":connect error - %s\n", strerror(errno));
			snprintf(errno_exit_buf, sizeof(errno_exit_buf), "%s", strerror(errno));
			close_fd_db(fd_idx , REASON_TX_CONNECT_ERROR);
			return FALSE_0;
		}
		else
		{
			DBG_TX PRINTF_VZ(":successfully connected to %s:%d, (fd=%d, fd_idx=%d) \n",fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , fd_db[fd_idx].gen.dst_port , fd , fd_idx);
		}
	}
	/*IPv4*/
	else
	{
		memset((char *) &fd_db[fd_idx].gen.server_v4, 0, sizeof(fd_db[fd_idx].gen.server_v4));
		fd_db[fd_idx].gen.server_v4.sin_family = (sa_family_t)fd_db[fd_idx].gen.ip_ver;
		fd_db[fd_idx].gen.server_v4.sin_port = htons(fd_db[fd_idx].gen.dst_port);
		if (IS_PROXY(fd_idx))
		{/*send through proxy IP address*/
			result = inet_pton((int)fd_db[fd_idx].gen.ip_ver ,/*cfg.dst_pr_v.ip_addr*/ cfg.dest_proxy_params.ip_addr_isolate_string , &fd_db[fd_idx].gen.server_v4.sin_addr);
		}
		else
		{/*send to dst IP*/
			result = inet_pton((int)fd_db[fd_idx].gen.ip_ver , fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , &fd_db[fd_idx].gen.server_v4.sin_addr);
		}

		if (result == 0)
		{
			PRINTF_VZ_N("Illegal IPv4 address\n");
			usage();
		}
		else if (result < 0)
		{
			DBG_TX PRINTF_VZ(":inet_pton error - %s\n", strerror(errno));
			close_fd_db(fd_idx , REASON_TX_FAILED_RESOLVE_IP_ADDRESS);
			return FALSE_0;
		}

		/*set source port and bind*/
		if (cfg.int_v.src_port.val)
		{
			struct sockaddr_in client_src_addr;
			bzero((char *) &client_src_addr, sizeof(client_src_addr));

			client_src_addr.sin_family = (sa_family_t)ip_ver;
			client_src_addr.sin_addr.s_addr = INADDR_ANY;
			client_src_addr.sin_port = htons((ushort)cfg.int_v.src_port.val);

			/*Bind*/
			if (bind(fd, (struct sockaddr *) &client_src_addr, sizeof(client_src_addr)) < 0)
			{
				char bind_ip_addr[INET6_ADDRSTRLEN+1] = {'\0'};
				inet_ntop(client_src_addr.sin_family , &(client_src_addr.sin_addr.s_addr) , bind_ip_addr , INET6_ADDRSTRLEN);
				snprintf(exit_buf, EXIT_BUF_LEN, "**FAIL** bind new socket(%d) with src values: %s : %d, probably socket src port already in use...\n",fd , bind_ip_addr , cfg.int_v.src_port.val);
				DBG_TX PRINTF_VZ("bind error - %s\n", strerror(errno));
				exit_vz(EXIT_FAILURE, exit_buf);
			}
		}

		/*connect...*/
		if (connect(fd,(struct sockaddr *) &fd_db[fd_idx].gen.server_v4 , sizeof(fd_db[fd_idx].gen.server_v4)) < 0)
		{
			DBG_TX PRINTF_VZ("connect error - %s\n", strerror(errno));
			snprintf(errno_exit_buf, sizeof(errno_exit_buf), "%s", strerror(errno));
			close_fd_db(fd_idx , REASON_TX_CONNECT_ERROR);
			return FALSE_0;
		}
		else
		{
			DBG_TX PRINTF_VZ(":successfully connected to %s:%d, (fd=%d, fd_idx=%d) \n",fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , fd_db[fd_idx].gen.dst_port , fd , fd_idx);
		}
	}

	/*SSL connection*/
	if (cfg.flag.ssl.val)
	{
		ssl_init_ssl_to_new_fd(fd_idx);
	}

	return TRUE_1;
}


/************tx_update_buf_length*********************/
void tx_update_buf_length(uint fd_idx, uint sent_bytes)
{
	cntr.stat.TX_bytes += (int)sent_bytes;
	fd_db[fd_idx].tx.buf_cur_position += sent_bytes;
	if (fd_db[fd_idx].tx.buf_cur_position >= fd_db[fd_idx].tx.buf_length)
	{
		zero_tx_buf(fd_idx);
	}
}

/************verify_buf_guards*********************/
void verify_buf_guards(uint fd_idx)
{
	PANIC(fd_db[fd_idx].buf.buf_guard_1 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_2 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_3 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_4 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_5 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_6 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_7 != BUF_GUARD_NUM);
	PANIC(fd_db[fd_idx].buf.buf_guard_8 != BUF_GUARD_NUM);
}

/*********************************/
void init_TX_slices_per_second(uint fd_idx)
{
	DBG_TX PRINTF_VZ("(fd_idx=%d)Zero TX slice usage, run_time.sec=%d,fd_db[fd_idx].bwTx.last_second=%d\n",fd_idx,run_time.sec,fd_db[fd_idx].bwTx.last_second);
	/*zero all the forward slice_usage in this sec*/
	int i;
	for (i = 0 ; i < NUM_OF_TIME_SLICES ; i++)
	{
		fd_db[fd_idx].bwTx.bwT[i].slice_usage = 0;
		DBG_TX PRINTF_VZ("fd_db[fd_idx=%d].bwTx.bwT[i=%d].slice_usage=%d, slice_limit=%d\n",fd_idx , i ,
				fd_db[fd_idx].bwTx.bwT[i].slice_usage, fd_db[fd_idx].bwTx.bwT[i].slice_limit);
	}
	/*and keep the last second*/
	fd_db[fd_idx].bwTx.last_second = run_time.sec;
}

/*********************************/
uint calc_snd_size_per_cur_slice(uint fd_idx)
{
	uint available_snd_size;

	if (run_time.sec != fd_db[fd_idx].bwTx.last_second)
	{
		init_TX_slices_per_second(fd_idx);
	}

	fd_db[fd_idx].bwTx.last_slice = run_time.slice_100_msec;
	available_snd_size = fd_db[fd_idx].bwTx.bwT[run_time.slice_100_msec].slice_limit - fd_db[fd_idx].bwTx.bwT[run_time.slice_100_msec].slice_usage;
	if ((available_snd_size > fd_db[fd_idx].bwTx.bwT[run_time.slice_100_msec].slice_limit) ||
			(available_snd_size >= MAX_TX_BUF_LENGTH))
	{
		cntr.warning.Illegal_rcv_size_per_slice++;
		return MAX_TX_BUF_LENGTH;
	}

	return available_snd_size;
}

/************tx_send_packet*********************/
void tx_send_packet(uint fd_idx)
{
	int sent_bytes = 0;
	int sock = fd_db[fd_idx].gen.fd;
	uint pending_tx = PENDING_TX_LEN(fd_idx);

	if (cfg.int_v.bw_TX_limit.val)
	{
		pending_tx = calc_snd_size_per_cur_slice(fd_idx);
		DBG_TX PRINTF_VZ("calc pending_tx = %d, fd_idx=%d\n",pending_tx, fd_idx);
		if (pending_tx > PENDING_TX_LEN(fd_idx))
		{
			DBG_TX PRINTF_VZ("**WARNING**:calc_snd_size(=%d)>pending_tx(=%d), fd_idx=%d\n",pending_tx, PENDING_TX_LEN(fd_idx) , fd_idx);
			cntr.warning.calc_snd_size_larger_then_pending_tx++;
			pending_tx = PENDING_TX_LEN(fd_idx);
		}
	}

	if (pending_tx > 0)
	{
		/*sanity check*/
		PANIC(fd_db[fd_idx].tx.buf_cur_position > MAX_TX_BUF_LENGTH);


		/*assign packet position*/
		char *pkt = &fd_db[fd_idx].buf.tx_buf[fd_db[fd_idx].tx.buf_cur_position];


		/*try to aquire lock here since had race conditions with RX thread, where I did send, and then RX thread woke up immidiattly, while TX didn't manage to update counters and state*/
		if (pthread_mutex_trylock(&fd_db[fd_idx].gen.tx_rx_mutex) == 0)
		{
			verify_buf_guards(fd_idx);

			DBG_TX PRINTF_VZ_N("----------TX----------\n");
			DBG_TX PRINTF_VZ("TX pending pkt (pending_tx=%d):\n%s\n", pending_tx ,pkt);
			DBG_TX PRINTF_VZ_N("--------------------\n");

			DS_PRINT PRINTF_VZ_N(BOLDGREEN "[%s]-->TX pending (%d Bytes)-->\n" RESET ,elapse_time ,pending_tx);

			if (fd_db[fd_idx].ssl_db.is_ssl)
			{
				DBG_TX PRINTF_VZ("SSL TX pending pkt (pending_tx=%d):\n%s\n", pending_tx ,pkt);
				//				while((sent_bytes = ssl_write(&fd_db[fd_idx].ssl_db.ssl , (unsigned char*)(pkt), pending_tx )) <= 0 )
				/*need to release mutex, since the ssl_net_send will ask for this mutex*/
				pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);
				sent_bytes = mbedtls_ssl_write(&fd_db[fd_idx].ssl_db.ssl , (unsigned char*)(pkt), pending_tx);
				{
					if(sent_bytes < 0 )
					{
						if ((sent_bytes != MBEDTLS_ERR_SSL_WANT_READ) && (sent_bytes != MBEDTLS_ERR_SSL_WANT_WRITE))
						{
							mbedtls_strerror( sent_bytes , exit_buf , EXIT_BUF_LEN);
							exit_vz(EXIT_FAILURE, exit_buf);
						}
					}
					else
					{
						DBG_TX PRINTF_VZ("SSL Success sent %d Bytes\n", sent_bytes);
						tx_update_buf_length(fd_idx , (uint)sent_bytes);
					}
					DBG_TX PRINTF_VZ("[%d]finished sending , sent_bytes=%d \n", fd_idx,sent_bytes);
				}
			}
			else
			{
				sent_bytes = (int)send(sock, pkt, pending_tx, 0);
				if (sent_bytes == -1)
				{
					DBG_TX PRINTF_VZ("send error - %s\n", strerror(errno));
					close_fd_db(fd_idx , REASON_TX_SEND_ERROR);
					return;
				}
				else
				{
					DS_PRINT PRINTF_VZ_N(GREEN "%.*s\n" RESET ,pending_tx ,pkt);
					DS_PRINT  PRINTF_VZ_N("[%s][Successfully sent=%d Bytes]\n",elapse_time , sent_bytes);
					tx_update_buf_length(fd_idx , (uint)sent_bytes);
				}
			}

			fd_db[fd_idx].tx.tx_state = TX_STATE_PKT_SENT;
			DS_PRINT PRINTF_VZ_N(BOLDGREEN "[%s]-->TX end (line=%d)-->" RESET "\n",elapse_time , fd_db[fd_idx].ds_db.cur_line);
			/*data sender - next command*/
			if ((cfg.str_v.data_sender[0]) && (PENDING_TX_LEN(fd_idx) == 0))
			{
				ds_move_to_next_command(fd_idx , FUNC_LINE);
			}

			if (!fd_db[fd_idx].ssl_db.is_ssl)
			{
				pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);
			}
			return;
		}
		else
		{/*rearm the tx_now mutex, to try the tx_loop again*/
			DBG_TX PRINTF_VZ("**FAIL** to acquire TX-RX lock for fd_idx=%d, TX sending pkt (pending_tx=%d)\n", fd_idx, pending_tx);
			cntr.info.tmp_failed_tx_mutex_lock++;
			/*handle case of need to resend, consider remove the else part to be handled every 100 msec*/
			//			if (cfg.flag.range.val)
			//			{
			//				rearm_tx_now(fd_idx);
			//			}
			//			else
			{
				if (fd_db[fd_idx].tx.lock_failure_slice != run_time.slice_100_msec)
				{/*try to aquire TX-RX lock every 100msec, so we don't get into dead locks.*/
					fd_db[fd_idx].tx.lock_failure_slice = run_time.slice_100_msec;
					tx_now(fd_db[fd_idx].tx.tx_th_idx); /*rearm the tx_now mutex, to try the tx_loop again*/
				}
			}
		}
	}
	return;
}

/*********************************/
void check_and_wake_tx_threads()
{
	uint fd_idx;

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if (PENDING_TX_LEN(fd_idx)/*fd_db[idx].tx.buf_length*/)
		{
			cntr.info.tmp_wake_up_tx++;
			wake_up_tx_thread(fd_db[fd_idx].tx.tx_th_idx);
		}
	}
}
/*********************************/
void wake_up_all_tx_thread()
{
	uint th_idx;

	for (th_idx=0 ; th_idx<(uint)cfg.int_v.tx_num_of_threads.val ; th_idx++)
	{
		tx_now(th_idx);
	}
}

/*********************************/
void wake_up_tx_thread(uint tx_th_idx)
{

	//	if ((uint)tx_th_db[tx_th_idx].th_active_sessions <= tx_threshold)
	{
		tx_now(tx_th_idx);
	}
}


/*********************************/
void tx_now(uint th_idx)
{
	PANIC(th_idx >= (uint)cfg.int_v.tx_num_of_threads.val);
	/*Block TX thread, until RX releases it*/
	pthread_mutex_unlock(&tx_th_db[th_idx].tx_now);
}

/*********************************/
void tx_add_pending_buf(uint fd_idx)
{
	fd_db[fd_idx].tx.buf_length = (uint)strlen(fd_db[fd_idx].buf.tx_buf);
	clear_parser_data(fd_idx); /*have to clear parser data, so next packet will be parsed*/
	DBG_RX_TX PRINTF_VZ("pending length=(%d-%d)%d:\n%s\n",PENDING_TX_LEN(fd_idx),fd_db[fd_idx].tx.buf_length, fd_db[fd_idx].tx.buf_cur_position ,fd_db[fd_idx].buf.tx_buf);
}

/*********************************/
void inc_open_sockets_cntrs(uint th_idx , uint fd_idx)
{
	cntr.stat.open_sockets++;
	if (tx_th_db[th_idx].th_active_sessions < cfg.int_v.tx_th_active_sessions.val)
		tx_th_db[th_idx].th_active_sessions++;
	tx_th_db[th_idx].thread_open_sockets++;
	fd_db[fd_idx].non_del.session_cntr++;
}

/*********************************/
uint create_new_fd_db(uint fd_idx , uint th_idx , uri_parser	*dst_direct ,  uri_parser	*dst_proxy)
{
	uint ret = TRUE_1;

	fd_db[fd_idx].gen.in_use = 1;
	fd_db[fd_idx].gen.ip_ver = ip_ver;
	fd_db[fd_idx].gen.dst_port = (ushort)cfg.int_v.port.val;
	fd_db[fd_idx].tx.tx_th_idx = th_idx;
	/*select the RX thread idx, if we already have fd (in case of socket reuse) don't change the rx_th_idx*/

	if (fd_db[fd_idx].gen.fd == 0)
		//			||(cfg.flag.range.val && range_global.range_table[fd_db[fd_idx].rx.range.global_range_idx].state == RANGE_RESTART))
	{
		fd_db[fd_idx].rx.rx_th_idx = ((uint)cntr.stat.last_rx_th_idx);

		if (cntr.stat.last_rx_th_idx >= (cfg.int_v.rx_num_of_threads.val-1))
		{
			cntr.stat.last_rx_th_idx = 0;
		}
		else
		{
			cntr.stat.last_rx_th_idx++;
		}
	}

	memcpy(&fd_db[fd_idx].gen.dst_direct , dst_direct , sizeof(fd_db[fd_idx].gen.dst_direct));
	memcpy(&fd_db[fd_idx].gen.dst_proxy  , dst_proxy  , sizeof(fd_db[fd_idx].gen.dst_proxy));

	strncpy(fd_db[fd_idx].client.client_dst_ip , fd_db[fd_idx].gen.dst_direct.ip_addr_isolate_string , INET6_ADDRSTRLEN);
	sprintf(fd_db[fd_idx].client.client_dst_port , "%d",fd_db[fd_idx].gen.dst_port);
	sprintf(fd_db[fd_idx].client.client_http_proto , "HTTP/%s" , DEFAULT_HTTP_VERSION);

	if (cfg.int_v.bw_rx_limit.val)
	{
		init_default_bwR_values_per_fd(fd_idx);
	}
	if (cfg.int_v.bw_TX_limit.val)
	{
		init_default_bwT_values_per_fd(fd_idx);
	}
	if (cfg.str_v.data_sender[0])
	{
		init_ds_db(fd_idx);
	}
	if (cfg.flag.range.val)
	{/*have to be done */
		ret = init_range_fd_idx(fd_idx);
	}
	watchdog_event_timer = WATCHDOG_TIMER_IN_SEC; /*ReArm watchdog*/
	/*TX delay*/
	if (cfg.int_v.delay_tx_sec.val)
	{
		sleep((uint)cfg.int_v.delay_tx_sec.val);
	}

	return ret;
}

/*********************************/
uint tx_create_new_request(uint fd_idx)
{
	/*build the TX pkt*/
	if (cfg.int_v.delay_get_sec.val)
	{/*delay creation of the get, it will cause delay to send the GET*/
		sleep((uint)(cfg.int_v.delay_get_sec.val));
	}
	zero_tx_buf(fd_idx);
	if (cfg.str_v.data_sender[0])
	{
		ds_build_TX_pkt(fd_db[fd_idx].buf.tx_buf , fd_idx);
	}
	else
	{
		build_http_get_request(fd_db[fd_idx].buf.tx_buf , NULL , fd_idx);
	}
	fd_db[fd_idx].tx.buf_length = (uint)strlen(fd_db[fd_idx].buf.tx_buf);
	cntr.stat.get_requests++;
	fd_db[fd_idx].gen.state = STATE_SENT_GET;
	return TRUE_1;
}

/*********************************/
uint tx_new_socket_connection(uint fd_idx)
{
	int skip_sock_create = (cfg.flag.socket_resue.val) && (fd_db[fd_idx].gen.fd);

	/*sanity - to verify we not got in here in case of socket reuse*/
	if (!skip_sock_create)
	{
		if (tx_create_new_socket(fd_idx , 0) != TRUE_1)
			return FALSE_0;

		if (tx_socket_connect(fd_idx) != TRUE_1)
			return FALSE_0;

		if (update_fd_db_values(fd_idx) != TRUE_1)
			return FALSE_0;

		add_fd_to_epoll(fd_db[fd_idx].gen.fd , fd_idx);

		if (make_socket_non_blocking(fd_db[fd_idx].gen.fd) != TRUE_1)
			exit_vz(EXIT_FAILURE , NULL);

		fd_db[fd_idx].tx.tx_state = TX_STATE_SOCKET_CONNECTED;
		fd_db[fd_idx].gen.state = STATE_CONNECTION_ESTABLISHED;
	}
	return TRUE_1;
}

uint is_pending_tx(uint my_th_idx)
{
	uint fd_idx = 0;
	uint th_start_fd_idx = tx_th_db[my_th_idx].fd_idx_start;
	uint th_end_fd_idx = tx_th_db[my_th_idx].fd_idx_start + tx_th_db[my_th_idx].fd_idx_span;

	for (fd_idx=th_start_fd_idx ; fd_idx<th_end_fd_idx ; fd_idx++)
	{
		if ((fd_db[fd_idx].gen.in_use != 0) && (fd_db[fd_idx].gen.fd > 2) && (PENDING_TX_LEN(fd_idx)))
		{
			return TRUE_1;
		}
	}
	return FALSE_0;
}

/*********************************/
void *thread_TX(void *arg)
{
	int tx_running = 1;
	TX_thread_db_t *my_tx_th_db = arg;
	uint my_th_idx = my_tx_th_db->local_th_idx;
	uint th_start_fd_idx = tx_th_db[my_th_idx].fd_idx_start;
	uint th_end_fd_idx = tx_th_db[my_th_idx].fd_idx_start + tx_th_db[my_th_idx].fd_idx_span;
	uint fd_idx = 0;
	uint tx_thread_done = 0 , ret = 0;

	pthread_mutex_init(&tx_th_db[my_th_idx].tx_now , NULL);
	cntr.stat.TX_threads++;
	DBG_TX	PRINTF_VZ_N("starting tx_th, sessions_per_th = %d, cntr.TX_threads=%d\n",tx_th_db[my_th_idx].sess_per_th, cntr.stat.TX_threads);

	while(tx_running)
	{
		/*Block TX thread, until RX releases it*/
		pthread_mutex_lock(&tx_th_db[my_th_idx].tx_now);

		DBG_TX PRINTF_VZ("thread[%d]:WakeUp, thread_open_sockets=%d, sess_per_th=%d\n"
				, my_th_idx, tx_th_db[my_th_idx].thread_open_sockets, tx_th_db[my_th_idx].sess_per_th);
		if ((shut_down_now) ||
				((cfg.flag.range.val) && (more_ranges_to_fetch() == FALSE_0) && (is_pending_tx(my_th_idx)==FALSE_0)) ||
				 (tx_th_db[my_th_idx].go_down_now))
		{
			DBG_TX PRINTF_VZ("thread[%d], TX going down, set flag tx_thread_done = 1\n", my_th_idx);
			tx_thread_done = 1;
		}


		if (!tx_thread_done)
		{
			DBG_TX PRINTF_VZ("thread[%d]=%lu, lock tx_now mutex, thread_open_sockets=%d/%d, th_active_sessions=%d\n", my_th_idx,
					tx_th_db[my_th_idx].tx_th_id, tx_th_db[my_th_idx].thread_open_sockets, tx_th_db[my_th_idx].sess_per_th, tx_th_db[my_th_idx].th_active_sessions);
			for (fd_idx=th_start_fd_idx ; fd_idx<th_end_fd_idx ; fd_idx++)
			{
				uint continue_in_process = 1;
				uint new_get_request = 0;
				/*Create new socket*/
				if ((fd_db[fd_idx].gen.in_use == 0) &&
						(fd_db[fd_idx].gen.fd == 0) &&
						(tx_th_db[my_th_idx].thread_open_sockets < tx_th_db[my_th_idx].sess_per_th))
				{
					/*Cookie WAIT*/
					if ((cfg.flag.cookie_wait.val) && (cntr.stat.open_sockets >= 1))
					{
						while(!last.cookie_copy_done)
						{
							usleep(10000);
						}
					}
					if (!ds_file.rcv_mode)
					{

						DBG_TX PRINTF_VZ("thread[%d]=%lu, Creating new socket, fd_idx=%d, thread_open_sockets=%d\n",
								 my_th_idx, tx_th_db[my_th_idx].tx_th_id,fd_idx, tx_th_db[my_th_idx].thread_open_sockets);
						if ((ret = create_new_fd_db(fd_idx , my_th_idx , &cfg.dest_params , &cfg.dest_proxy_params)) != TRUE_1)
						{
							if (ret == FALSE_100_NO_MORE_RANGES_TO_GET)
							{
								DBG_TX PRINTF_VZ("thread[%d]idx[%d], TX finish - no more ranges to get\n", my_th_idx  , fd_idx);
								close_fd_db(fd_idx , REASON_TX_NO_MORE_CONNECTIONS_REQUIRED);
								continue_in_process = 0;
							}
							else
							{
								DBG_TX PRINTF_VZ("thread[%d]idx[%d], **FAIL** create_new_fd_db()\n", my_th_idx  , fd_idx);
								close_fd_db(fd_idx , REASON_TX_FAILED_CREATING_NEW_FD);
								continue_in_process = 0;
							}
						}
						if ((continue_in_process) && (tx_new_socket_connection(fd_idx) == FALSE_0))
						{
							DBG_TX PRINTF_VZ("thread[%d]idx[%d], **FAIL** tx_new_socket_connection()\n", my_th_idx  , fd_idx);
							continue_in_process = 0;
							cntr.error.failed_establish_connection++;
							shutdown_now(); /*test*/
							break;/*test*/
						}

						if ((continue_in_process) && (tx_create_new_request(fd_idx) == FALSE_0))
						{
							DBG_TX PRINTF_VZ("thread[%d]idx[%d], **FAIL** tx_create_new_request()\n", my_th_idx  , fd_idx);
							continue_in_process = 0;
							cntr.error.tx_create_new_request++;
						}
						if (continue_in_process)
						{
							new_get_request = 1;
							inc_open_sockets_cntrs(my_th_idx , fd_idx);
						}
					}
				}

				/*socket reuse, will always use the 1st th_fd_idx*/
				else if((cfg.flag.socket_resue.val) &&
						/*(fd_idx == th_start_fd_idx) &&*/
						(tx_th_db[my_th_idx].thread_open_sockets < tx_th_db[my_th_idx].sess_per_th) &&
						(fd_db[fd_idx].gen.fd != 0) &&
						(fd_db[fd_idx].rx.respone_fully_rcv))
				{
					//					DBG_TX PRINTF_VZ("socket Reuse, thread_open_sockets=%d, fd_idx=%d, fd=%d\n",thread_open_sockets,fd_idx, fd_db[fd_idx].gen.fd);
					//					if ((fd_db[fd_idx].gen.fd != 0) && (fd_db[fd_idx].rx.respone_fully_rcv))
					if ((cfg.flag.range.val) &&
							(range_global.range_table[fd_idx].state == RANGE_NOT_IN_USE/*fd_db[fd_idx].rx.range.global_range_idx==INIT_IDX*/))
					{
						DBG_TX PRINTF_VZ("socket Reuse, thread_open_sockets=%d, fd_idx=%d, fd=%d\n",tx_th_db[my_th_idx].thread_open_sockets,fd_idx, fd_db[fd_idx].gen.fd);
						fd_db[fd_idx].rx.respone_fully_rcv = 0;
						if ((ret = create_new_fd_db(fd_idx , my_th_idx , &cfg.dest_params , &cfg.dest_proxy_params)) != TRUE_1)
						{
							if (ret == FALSE_100_NO_MORE_RANGES_TO_GET)
							{
								DBG_TX PRINTF_VZ("thread[%d]idx[%d], TX finish - no more ranges to get\n", my_th_idx  , fd_idx);
								close_fd_db(fd_idx , REASON_TX_NO_MORE_CONNECTIONS_REQUIRED);
								continue_in_process = 0;
							}
							else
							{
								DBG_TX PRINTF_VZ("thread[%d]idx[%d], **FAIL** create_new_fd_db() in socket reuse\n", my_th_idx  , fd_idx);
								close_fd_db(fd_idx , REASON_TX_FAILED_CREATING_NEW_FD);
								continue_in_process = 0;
							}
							if ((cfg.flag.range.val) && (!(more_ranges_to_fetch())))
							{
								tx_thread_done = 1;
							}
							else
							{
								cntr.error.create_new_fd_db_sock_reuse++;
							}
						}

						if ((continue_in_process) && (tx_create_new_request(fd_idx)==FALSE_0))
						{
							DBG_TX PRINTF_VZ("thread[%d]idx[%d], **FAIL** tx_create_new_request() in socket reuse\n", my_th_idx  , fd_idx);
							continue_in_process = 0;
						}

						if (continue_in_process)
						{

							new_get_request = 1;
							inc_open_sockets_cntrs(my_th_idx , fd_idx);
						}
					}
				}

				/*sending pending TX*/
				if ((fd_db[fd_idx].gen.in_use != 0) && (fd_db[fd_idx].gen.fd > 2) && (PENDING_TX_LEN(fd_idx)))
				{
#ifdef RANGE_TX_PRIORITY_ENA
					if ((cfg.flag.range.val) && (new_get_request || fd_db[fd_idx].rx.range.new_get_request))
					{
						fd_db[fd_idx].rx.range.new_get_request = 1;
						if (/*(!range_global.get_sent_in_last_100msec_slice) &&*/ (range_can_I_send_now(fd_idx)))
						{
							range_global.get_sent_in_last_100msec_slice = 1;
							DBG_TX PRINTF_VZ("thread[%d], range new GET, pending TX(%d-%d=%d) for fd_idx=%d, GET's=%d\n", my_th_idx,
									fd_db[fd_idx].tx.buf_length, fd_db[fd_idx].tx.buf_cur_position , PENDING_TX_LEN(fd_idx) , fd_idx, cntr.stat.get_requests);
							tx_send_packet(fd_idx);
							range_update_next_get_to_send(fd_idx);
							fd_db[fd_idx].rx.range.new_get_request = 0;
						}
						else
						{
							cntr.info.tmp_delay_range_tx++;
						}
					}
					else
#endif
					{
						DBG_TX PRINTF_VZ("thread[%d], pending TX(%d-%d=%d) for fd_idx=%d, GET's=%d, new_get_request=%d\n", my_th_idx,
								fd_db[fd_idx].tx.buf_length, fd_db[fd_idx].tx.buf_cur_position , PENDING_TX_LEN(fd_idx) , fd_idx, cntr.stat.get_requests, new_get_request);
						tx_send_packet(fd_idx);
					}
				}
			}
		}

		if (((!ds_file.rcv_mode) &&
				(tx_th_db[my_th_idx].thread_open_sockets == tx_th_db[my_th_idx].sess_per_th) &&
				(tx_th_db[my_th_idx].th_active_sessions == 0)) ||
				(tx_thread_done) ||
				(shut_down_now))
		{
			tx_running = 0;
			DBG_TX PRINTF_VZ("thread[%d]=%lu, thread_open_sockets=%d, exiting TX thread...\n", my_th_idx, tx_th_db[my_th_idx].tx_th_id , tx_th_db[my_th_idx].thread_open_sockets);
			break;
		}
	}
	tx_th_db[my_th_idx].active = 0;
	cntr.stat.TX_threads--;
	DBG_TX PRINTF_VZ("thread[%d]=%lu done!, exiting...\n", my_th_idx, tx_th_db[my_th_idx].tx_th_id);

	return(0);/*Don't use pthread_exit, since then it kill's all sockets related to this thread...*/
}



/*********************************/
void TX_threads_creator()
{
	uint tx_th_idx, sess_per_th;

	/*wait until RX thread is up and running*/
	while (th_rx_up != cfg.int_v.rx_num_of_threads.val)
	{
		usleep (1000);
	}

	for (tx_th_idx=0 ; tx_th_idx<(uint)cfg.int_v.tx_num_of_threads.val ; tx_th_idx++)
	{
		if (tx_th_idx==0)
		{
			sess_per_th = ((uint)cfg.int_v.num_of_session.val / (uint)cfg.int_v.tx_num_of_threads.val) + ((uint)cfg.int_v.num_of_session.val % (uint)cfg.int_v.tx_num_of_threads.val);
		}
		else
		{
			sess_per_th = ((uint)cfg.int_v.num_of_session.val / (uint)cfg.int_v.tx_num_of_threads.val);
		}
		if (sess_per_th > 0)
		{
			DBG_TX	PRINTF_VZ(":TX_threads_creator(%d), sessions_per_th = %d\n" , tx_th_idx,sess_per_th);
			tx_th_db[tx_th_idx].active = 1;
			tx_th_db[tx_th_idx].local_th_idx = tx_th_idx;
			tx_th_db[tx_th_idx].sess_per_th = sess_per_th;
			tx_th_db[tx_th_idx].tx_th_id = sess_per_th;
			tx_th_db[tx_th_idx].fd_idx_start = tx_th_idx * (uint)cfg.int_v.tx_th_active_sessions.val;
			tx_th_db[tx_th_idx].fd_idx_span = (uint)cfg.int_v.tx_th_active_sessions.val;
			/*TX thread*/
			if (pthread_create(&tx_th_db[tx_th_idx].tx_th_id , NULL, thread_TX, /*(void *)tx_th_idx*/ &tx_th_db[tx_th_idx]) != 0)
			{
				DBG_TX PRINTF_VZ(":pthread_create() for thread thread_TX error - %s\n", strerror(errno));
				exit_vz(EXIT_FAILURE , NULL);
			}
		}
	}
}
