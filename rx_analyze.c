/* rx_analyze.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  rx_analyze.c is part of vazaget.
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
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>
#include "global.h"
#include "data_sender.h"
#include "rx_range.h"
#include "rx.h"
#include "tx.h"
#include "close.h"

#define DBG_CHUNK_FILE	"dbg_chunk_file"

/*********************************/
void compare_dst_port(char *client_dst_port)
{
	int i;
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (strncmp(srv_dst_port[i].port_string , client_dst_port, PORT_STRING_LENGTH) != 0)
		{/*srv_dst_port is different*/
			if (srv_dst_port[i].port_string[0])
			{/*is there any value in this place */
				continue;
			}
			else
			{/*no value - stop the of loop, basically it should not be get here*/
				cntr.warning.dst_port_match_not_found++;
				return;/*finish the loop*/
			}
		}
		else
		{/*dst Port already kept*/
			srv_dst_port[i].dstPort_diff_cntr++;
			return;
		}
	}
}


/*********************************/
void save_dst_port(char *rcv_srv_dst_port)
{
	int i;
	DBG_RX PRINTF_VZ("rcv_srv_dst_port=%s\n",rcv_srv_dst_port);
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (strncmp(srv_dst_port[i].port_string , rcv_srv_dst_port, PORT_STRING_LENGTH) != 0)
		{/*dst_port is different*/
			if (srv_dst_port[i].port_string[0])
			{/*is there any value in this place */
				continue;
			}
			else
			{/*no value - keep this one*/
				strncpy(srv_dst_port[i].port_string , rcv_srv_dst_port , PORT_STRING_LENGTH);
				DBG_RX PRINTF_VZ("srv_dst_port[%d].ip_string=%s\n",i,srv_dst_port[i].port_string);
				return;/*finish*/
			}
		}
		else
		{/*dst Port already kept*/
			return;
		}
	}
	cntr.warning.reached_max_dst_ports++;
	return;
}

/*********************************/
void compare_dst_ip(char *client_dst_ip)
{
	int i;
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (strncmp(srv_dst_ip[i].ip_string , client_dst_ip, INET6_ADDRSTRLEN) != 0)
		{/*dst_ip is different*/
			if (srv_dst_ip[i].ip_string[0])
			{/*is there any value in this place */
				continue;
			}
			else
			{/*no value - stop the of loop, basically it should not be get here*/
				cntr.warning.dst_ip_match_not_found++;
				return;/*finish the loop*/
			}
		}
		else
		{/*dst IP already kept*/
			srv_dst_ip[i].dstIP_diff_cntr++;
			return;
		}
	}
	cntr.warning.reached_max_dst_ips++;
	return;
}



/*********************************/
void save_dst_ip(char *rcv_srv_dst_ip)
{
	int i;
	DBG_RX PRINTF_VZ("rcv_srv_dst_ip=%s\n",rcv_srv_dst_ip);
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		if (strncmp(srv_dst_ip[i].ip_string , rcv_srv_dst_ip, INET6_ADDRSTRLEN) != 0)
		{/*dst_ip is different*/
			if (srv_dst_ip[i].ip_string[0])
			{/*is there any value in this place */
				continue;
			}
			else
			{/*no value - keep this one*/
				strncpy(srv_dst_ip[i].ip_string , rcv_srv_dst_ip , INET6_ADDRSTRLEN);
				DBG_RX PRINTF_VZ("srv_dst_ip[%d].ip_string=%s\n",i,srv_dst_ip[i].ip_string);
				return;/*finish*/
			}
		}
		else
		{/*dst IP already kept*/
			return;
		}
	}
	cntr.warning.reached_max_dst_ips++;
	return;
}

/**************find_available_cookie_entry*******************/
int find_available_cookie_entry()
{
	int i;
	for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
	{
		if (!last.cookie_rcv_from_reply[i][0])
		{
			return i;
		}
	}
	return i;
}

/**************copy_cookie_from_parsed_to_last*******************/
void copy_cookie_from_parsed_to_last(char *last_cookie , char *parsed_cookie)
{
	last.cookie_copy_done = 0;
	strncpy(last_cookie , parsed_cookie , MAX_COOKIE_LENGTH);
	last.cookie_copy_done = 1;
	DBG_PARSER PRINTF_VZ("saved rcv cookie=%s\n", last_cookie);
}

/*************update_last_cookies_values********************/
void update_last_cookies_values_for_print(parser_struct *parsed_msg)
{
	int i;

	if (!cfg.flag.cookie_from_reply.val)
	{/*it will overwrite the existing last cookies values, so we need to do it only if we not expect to reuse cookie from reply*/
		for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
		{
			if (parsed_msg->http.set_cookie[i])
			{/*if we parsed any cookie*/
				DBG_PARSER PRINTF_VZ("Parsed cookie found[%d]=%s\n", i ,parsed_msg->http.set_cookie[i]);
				if(last.cookie_rcv_from_reply[i])
				{/*if we already have saved cookie*/
					if (strncmp(last.cookie_rcv_from_reply[i] , parsed_msg->http.set_cookie[i] , MAX_COOKIE_LENGTH))
					{/*if saved cookie is different then the last*/
						copy_cookie_from_parsed_to_last(last.cookie_rcv_from_reply[i] , parsed_msg->http.set_cookie[i]);
					}
				}
				else
				{/*Don't have any saved cookie*/
					copy_cookie_from_parsed_to_last(last.cookie_rcv_from_reply[i] , parsed_msg->http.set_cookie[i]);
				}
			}
		}

	}
}

void save_cookie_from_reply_to_non_del_fd_idx(parser_struct *parsed_msg, uint fd_idx)
{
	uint i, cookie_len = 0;

	if (parsed_msg->http.set_cookie[0])
	{
		for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
		{
			if (parsed_msg->http.set_cookie[i])
			{
				cookie_len = (uint)strnlen (parsed_msg->http.set_cookie[i] , MAX_COOKIE_LENGTH);
				if ((cookie_len > 0) && (cookie_len < MAX_COOKIE_LENGTH))
				{
					cookie_struct_t *cookie_struct = &fd_db[fd_idx].non_del.cookie_struct[i];
					/*check if we need to malloc */
					if (cookie_struct->cookie_ptr == NULL)
					{
						cookie_struct->cookie_ptr = malloc(cookie_len + 1);
						cookie_struct->cookie_alloc_length = cookie_len + 1;
					}
					else if (cookie_len + 1 > cookie_struct->cookie_alloc_length)
					{
						cookie_struct->cookie_ptr = realloc(cookie_struct->cookie_ptr , cookie_len + 1);
						cookie_struct->cookie_alloc_length = cookie_len + 1;
					}
					if (cookie_struct->cookie_ptr)
					{
						snprintf(cookie_struct->cookie_ptr , cookie_len + 1 ,
								"%s" , parsed_msg->http.set_cookie[i]);
					}
				}
			}
		}
	}


#if 0
	if ((!fd_db[fd_idx].non_del.last_cookie[0][0]) && (parsed_msg->http.set_cookie[0]))
	{
		for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
		{
			if (parsed_msg->http.set_cookie[i])
			{
				snprintf(fd_db[fd_idx].non_del.last_cookie[i] , MAX_COOKIE_LENGTH , "%s" , parsed_msg->http.set_cookie[i]);
				DBG_RANGE PRINTF_VZ("fd_idx=%d, copy cookie to last_cookie[%d] = %s\n",
						fd_idx , i , fd_db[fd_idx].non_del.last_cookie[i]);
				if (i==MAX_PARSED_COOKIES)
				{
					cntr.warning.max_saved_cookies++;
				}
			}
			else
			{/*no more cookies*/
				break;
			}
		}
	}
#endif
}


/*************save_cookie_from_reply********************/
void save_cookie_from_reply(parser_struct *parsed_msg, uint fd_idx)
{
	int i, avail_cookie_entry = MAX_PARSED_COOKIES ;
	DBG_PARSER PRINTF_VZ("save_cookie_from_reply\n");
	if (cfg.flag.range.val)
	{
		save_cookie_from_reply_to_non_del_fd_idx(parsed_msg , fd_idx);
	}
	else if (cfg.flag.cookie_from_reply.val)
	{/* for cookie_from_reply, we'll fill this struct only once, so TX will always use the same cookie*/
		if ((!last.cookie_rcv_from_reply[0][0]) && (parsed_msg->http.set_cookie[0]))
		{
			for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
			{
				if (parsed_msg->http.set_cookie[i])
				{
					DBG_PARSER PRINTF_VZ("Parsed cookie found[%d]=%s\n", i ,parsed_msg->http.set_cookie[i]);
					avail_cookie_entry = find_available_cookie_entry();
					DBG_PARSER PRINTF_VZ("avail_cookie_entry=%d\n", avail_cookie_entry);
					if (avail_cookie_entry == MAX_PARSED_COOKIES)
					{
						cntr.warning.max_saved_cookies++;
						return;
					}
					else
					{
						copy_cookie_from_parsed_to_last(last.cookie_rcv_from_reply[avail_cookie_entry] , parsed_msg->http.set_cookie[i]);
					}
				}
			}

		}
	}
	else if (cfg.flag.cookie_reply_2.val)
	{
		save_cookie_from_reply_to_non_del_fd_idx(parsed_msg , fd_idx);
#if 0
		if ((!fd_db[fd_idx].non_del.last_cookie[0][0]) && (parsed_msg->http.set_cookie[0]))
		{
			for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
			{
				if (parsed_msg->http.set_cookie[i])
				{
					strncpy(fd_db[fd_idx].non_del.last_cookie[i] , parsed_msg->http.set_cookie[i] , MAX_COOKIE_LENGTH);
					if (i==MAX_PARSED_COOKIES)
					{
						cntr.warning.max_saved_cookies++;
					}
				}
				else
				{/*no more cookies*/
					break;
				}
			}
		}
#endif
	}
}


/***************http_status_code_counters******************/
void http_status_code_counters(parser_struct *parsed_msg)
{
	if ((parsed_msg) && (parsed_msg->http.return_code))
	{ /*not HTTP header...*/
		cntr.stat.http_replies_total++;
		switch (parsed_msg->http.return_code[0])
		{
		case '1':
			cntr.stat.http_1xx++;
			break;
		case '2':
			cntr.stat.http_2xx++;
			break;
		case '3':
			cntr.stat.http_3xx++;
			break;
		case '4':
			cntr.stat.http_4xx++;
			break;
		case '5':
			cntr.stat.http_5xx++;
			break;
		default:
			cntr.stat.http_unknown_ret_value++;
			break;
		}
	}
	if ((parsed_msg->http.content_encoding) && (strncmp(parsed_msg->http.content_encoding ,  "gzip" , strlen("gzip")) == 0))
		cntr.stat.gzip_reply++;
	return;
}



/***************analyze_vazaget_reply******************/
void analyze_vazaget_reply(uint fd_idx , parser_struct *parsed_msg)
{
	if ((parsed_msg->html.vazaget_srv) &&
			(parsed_msg->html.srv_src_ip) &&
			(parsed_msg->html.srv_src_port) &&
			(parsed_msg->html.srv_dst_ip) &&
			(parsed_msg->html.srv_dst_port))
	{
		vaza_server_found = 1;
		if ((fd_db[fd_idx].client.client_src_ip[0]) && (fd_db[fd_idx].client.client_src_port[0]))
		{
			/*srcIP*/
			if(parsed_msg->html.srv_src_ip)
			{
				if (strncmp(parsed_msg->html.srv_src_ip ,fd_db[fd_idx].client.client_src_ip, INET6_ADDRSTRLEN) != 0)
				{
					cntr.stat.srcIP_diff++;
				}
			}

			/*srcPort*/
			if(parsed_msg->html.srv_src_port)
			{
				if (strncmp(parsed_msg->html.srv_src_port , fd_db[fd_idx].client.client_src_port, PORT_STRING_LENGTH) != 0)
				{
					cntr.stat.srcPort_diff++;
				}
			}

			/*dstIP*/
			if(parsed_msg->html.srv_dst_ip)
			{
				save_dst_ip(parsed_msg->html.srv_dst_ip);
				if (strncmp(parsed_msg->html.srv_dst_ip , fd_db[fd_idx].client.client_dst_ip, INET6_ADDRSTRLEN) != 0)
				{
					compare_dst_ip(parsed_msg->html.srv_dst_ip);
				}
				if (cfg.flag.cookie_reply_2.val)
				{
					if (!fd_db[fd_idx].non_del.last_real_srv_dst_ip[0])
					{
						strncpy(fd_db[fd_idx].non_del.last_real_srv_dst_ip , parsed_msg->html.srv_dst_ip , INET6_ADDRSTRLEN);
					}
				}
			}

			/*dstPort*/
			if(parsed_msg->html.srv_dst_port)
			{
				save_dst_port(parsed_msg->html.srv_dst_port);
				if (strncmp(parsed_msg->html.srv_dst_port , fd_db[fd_idx].client.client_dst_port, PORT_STRING_LENGTH) != 0)
				{
					compare_dst_port(parsed_msg->html.srv_dst_port);
					cntr.stat.dstPort_diff++;
				}
			}

			/*httpProto*/
			if(parsed_msg->html.http_protocol)
			{
				if (strncmp(parsed_msg->html.http_protocol , fd_db[fd_idx].client.client_http_proto, MAX_HTTP_PROTO_LENGTH) != 0)
				{
					cntr.stat.http_proto_diff++;
				}
			}
		}
	}
}

/**************update_last_values_every_100msec*******************/
void update_last_values_every_100msec(uint fd_idx)
{
	/*SRV srcIP*/
	if(fd_db[fd_idx].parser.parsed_msg.html.srv_src_ip)
	{
		strncpy(last.srv_src_ip , fd_db[fd_idx].parser.parsed_msg.html.srv_src_ip , INET6_ADDRSTRLEN);
	}
	/*client srcIP - should not be changed, just in case in the future I'll add src IP chnages*/
	if (strncmp(last.client_src_ip , fd_db[fd_idx].client.client_src_ip , INET6_ADDRSTRLEN))
	{
		strncpy(last.client_src_ip , fd_db[fd_idx].client.client_src_ip , INET6_ADDRSTRLEN);
	}
	/*SRV srcPort*/
	if((fd_db[fd_idx].parser.parsed_msg.html.srv_src_port) &&
			(strncmp(last.srv_src_port  , fd_db[fd_idx].parser.parsed_msg.html.srv_src_port , PORT_STRING_LENGTH)))
	{
		strncpy(last.srv_src_port , fd_db[fd_idx].parser.parsed_msg.html.srv_src_port , PORT_STRING_LENGTH);
	}
	/*client srcPort*/
	if (strncmp(last.client_src_port  , fd_db[fd_idx].client.client_src_port , PORT_STRING_LENGTH))
	{
		strncpy(last.client_src_port , fd_db[fd_idx].client.client_src_port , PORT_STRING_LENGTH);
	}
	/*client dst IP*/
	if (strncmp(last.client_dst_ip  , fd_db[fd_idx].client.client_dst_ip , INET6_ADDRSTRLEN))
	{
		strncpy(last.client_dst_ip , fd_db[fd_idx].client.client_dst_ip , INET6_ADDRSTRLEN);
	}
	/*SRV dstPort*/
	if ((fd_db[fd_idx].parser.parsed_msg.html.srv_dst_port) &&
			(strncmp(last.srv_dst_port  , fd_db[fd_idx].parser.parsed_msg.html.srv_dst_port , PORT_STRING_LENGTH)))
	{
		strncpy(last.srv_dst_port , fd_db[fd_idx].parser.parsed_msg.html.srv_dst_port , PORT_STRING_LENGTH);
	}
	/*Client dstPort*/
	if (strncmp(last.client_dst_port  , fd_db[fd_idx].client.client_dst_port , PORT_STRING_LENGTH))
	{
		strncpy(last.client_dst_port , fd_db[fd_idx].client.client_dst_port , PORT_STRING_LENGTH);
	}
	/*SRV HTTP protocol*/
	if ((fd_db[fd_idx].parser.parsed_msg.html.http_protocol) &&
			(strncmp(last.srv_http_proto  , fd_db[fd_idx].parser.parsed_msg.html.http_protocol , MAX_HTTP_PROTO_LENGTH)))
	{
		strncpy(last.srv_http_proto , fd_db[fd_idx].parser.parsed_msg.html.http_protocol , MAX_HTTP_PROTO_LENGTH);
	}
	/*client HTTP protocol*/
	if (strncmp(last.client_http_proto  , fd_db[fd_idx].client.client_http_proto , MAX_HTTP_PROTO_LENGTH))
	{
		strncpy(last.client_http_proto , fd_db[fd_idx].client.client_http_proto , MAX_HTTP_PROTO_LENGTH);
	}

	update_last_cookies_values_for_print(&fd_db[fd_idx].parser.parsed_msg);
	/*Cookie*/
	if (fd_db[fd_idx].parser.parsed_msg.html.http_cookie)
	{
		if (strncmp(fd_db[fd_idx].parser.parsed_msg.html.http_cookie , last.cookie_parsed_from_html , sizeof(last.cookie_parsed_from_html)) != 0)
		{
			strncpy(last.cookie_parsed_from_html , fd_db[fd_idx].parser.parsed_msg.html.http_cookie , sizeof(last.cookie_parsed_from_html));
		}
	}
	/*SSL ID*/
	if (fd_db[fd_idx].parser.parsed_msg.html.ssl_sess_id)
	{
		if (strncmp(fd_db[fd_idx].parser.parsed_msg.html.ssl_sess_id , last.ssl_sess_id_from_html , sizeof(last.ssl_sess_id_from_html)) != 0)
		{
			strncpy(last.ssl_sess_id_from_html , fd_db[fd_idx].parser.parsed_msg.html.ssl_sess_id , sizeof(last.ssl_sess_id_from_html));
		}
	}
	/*HTTP VIA*/
	if (fd_db[fd_idx].parser.parsed_msg.html.http_via)
	{
		if (strncmp(fd_db[fd_idx].parser.parsed_msg.html.http_via , last.http_via , sizeof(last.http_via)) != 0)
		{
			strncpy(last.http_via , fd_db[fd_idx].parser.parsed_msg.html.http_via , sizeof(last.http_via));
		}
	}
	/*x_forwarded_for*/
	if (fd_db[fd_idx].parser.parsed_msg.html.x_forwarded_for)
	{
		if (strncmp(fd_db[fd_idx].parser.parsed_msg.html.x_forwarded_for , last.x_forwarded_for , sizeof(last.x_forwarded_for)) != 0)
		{
			strncpy(last.x_forwarded_for , fd_db[fd_idx].parser.parsed_msg.html.x_forwarded_for , sizeof(last.x_forwarded_for));
		}
	}
}

/**************update_last_values*******************/
void update_last_values(uint fd_idx)
{
	analyze_vazaget_reply(fd_idx , &fd_db[fd_idx].parser.parsed_msg);
#if 0
	if (fd_db[fd_idx].parser.parsed_msg.http.set_cookie[0])
	{
		save_cookie_from_reply(&fd_db[fd_idx].parser.parsed_msg , (uint)fd_idx);
	}
#endif
	if (last.print_status == PR_STAT_READY)
	{/*will be performed only once in 100msec*/
		update_last_values_every_100msec(fd_idx);
		last.print_status = PR_STAT_FILLED;
	}
}


/**************analyze_3xx_reply*******************/
void build_boundary_numer(char *rand_string, uint length)
{
	uint rand_num, i;
	uint iterations = (length / INT_STRING_LENGTH); /*each rand number will give string of 8 bytes long*/
	uint modulo8 = (length % INT_STRING_LENGTH);
	char tmp[INT_STRING_LENGTH + 1];

	rand_string[0] = '\0';
	srand((uint)cntr.stat.open_sockets);

	for (i=0 ; i<iterations ; i++)
	{
		rand_num = (uint)(rand());
		sprintf(tmp , "%08x" , rand_num);
		strncat(rand_string , tmp , INT_STRING_LENGTH);
	}
	rand_num = (uint)(rand());
	sprintf(tmp , "%08x" , rand_num);
	strncat(rand_string , tmp , modulo8);
}

/**************analyze_200_post_reply*******************/
uint analyze_200_and_post_reply(uint fd_idx , parser_struct *parsed_msg)
{
	int i;

	if (parsed_msg->html.form_method == NULL)
	{
		cntr.warning.post_not_found_in_200OK++;
		return SESSION_FINISH;
	}
	if (strcmp (remove_quotes(parsed_msg->html.form_method, HDR_STRING_LENGTH), "post") != 0)
	{
		return SESSION_FINISH;
	}
	zero_tx_buf(fd_idx);
	char boundary_numer[BOUNDERY_NUM_STRING_LENGTH + 1];
	char boundary_string[BOUNDERY_FULL_STRING_LENGTH + 1];
	char first_boundary[HDR_STRING_LENGTH+1]={0};
	char middle_boundary[HDR_STRING_LENGTH+1]={0};
	char last_boundary[HDR_STRING_LENGTH+1]={0};
	char double_eol[]={"\r\n\r\n"};
	int	 payload_content_length = 0;

	build_boundary_numer(boundary_numer , BOUNDERY_NUM_STRING_LENGTH);
	sprintf(boundary_string , "-----------------------------%s" , boundary_numer); /*the contenet type header should be -2 --, that's why transfer to header the boundary_string[2], e.g.-----------------------------796348870795623121112252532*/
	sprintf(first_boundary , "%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"tmp.vzg\"\r\nContent-Type: application/octet-stream\r\n\r\n" , boundary_string);
	sprintf(middle_boundary , "%s\r\nContent-Disposition: form-data; name=\"submit\"\r\n\r\n" , boundary_string);
	sprintf(last_boundary , "Submit\r\n%s--\r\n" , boundary_string);
	payload_content_length = cfg.int_v.post_upload.val + (int)strlen(first_boundary) + (int)strlen(middle_boundary) + (int)strlen(last_boundary) + (int)strlen(double_eol);
	build_http_post_request(fd_db[fd_idx].buf.tx_buf , parsed_msg , fd_idx, &boundary_string[2], payload_content_length); /*the contenet type header should be -2 --, that's why transfer to header the boundary_string[2]*/

	strncat(fd_db[fd_idx].buf.tx_buf , first_boundary, HDR_STRING_LENGTH);
	int tmp_position = (int)strlen(fd_db[fd_idx].buf.tx_buf);
	for(i=0 ; i<cfg.int_v.post_upload.val ; i++)
	{
		char tmp[5];
		snprintf(tmp  , 2 , "%x" , i % 16);
		memcpy(&fd_db[fd_idx].buf.tx_buf[tmp_position + i] , tmp , sizeof(char));
	}
	fd_db[fd_idx].buf.tx_buf[tmp_position + i] = 0;
	strncat(fd_db[fd_idx].buf.tx_buf , double_eol , strlen(double_eol));
	strncat(fd_db[fd_idx].buf.tx_buf , middle_boundary, HDR_STRING_LENGTH);
	strncat(fd_db[fd_idx].buf.tx_buf , last_boundary, HDR_STRING_LENGTH);
	/*finished building the TX buffer, update the length*/
	tx_add_pending_buf((uint)fd_idx);
	fd_db[fd_idx].gen.state = STATE_SENT_POST;
	cntr.stat.post_requests++;
	return SESSION_CONTINUE;
}


/**************analyze_3xx_reply*******************/
uint analyze_3xx_reply(uint fd_idx , parser_struct *parsed_msg)
{
	if (!parsed_msg->http.return_code)
	{
		return SESSION_FINISH;
	}

	if ((strncmp(parsed_msg->http.return_code, "301" , strlen("301")) == 0) ||
			(strncmp(parsed_msg->http.return_code, "302" , strlen("302")) == 0))
	{
		zero_tx_buf(fd_idx);
		build_http_get_request(fd_db[fd_idx].buf.tx_buf , parsed_msg , fd_idx);
		tx_add_pending_buf((uint)fd_idx);
		/*after 301 we need to zero the file names, so coming 200OK will write to disk the new file name*/
		fd_db[fd_idx].gen.dst_direct.file_name_ptr = NULL;
		fd_db[fd_idx].gen.dst_proxy.file_name_ptr = NULL;
		fd_db[fd_idx].gen.state = STATE_SENT_GET;
		DBG_RX_TX PRINTF_VZ_N("finshed building the 2nd GET (after 301), pending length=%d:\n%s---------\n",PENDING_TX_LEN(fd_idx) ,fd_db[fd_idx].buf.tx_buf);
		return SESSION_CONTINUE;
	}
	return SESSION_FINISH;
}


/**************analyze_cookie_reply_2*******************/
void analyze_cookie_reply_2(uint fd_idx)
{
	if ((fd_db[fd_idx].non_del.last_real_srv_dst_ip[0]) && (fd_db[fd_idx].parser.parsed_msg.html.srv_dst_ip))
	{
		if (strncmp(fd_db[fd_idx].non_del.last_real_srv_dst_ip , fd_db[fd_idx].parser.parsed_msg.html.srv_dst_ip , INET6_ADDRSTRLEN))
		{
			cntr.stat.cookie_2_real_non_match++;
		}
		else
		{
			cntr.stat.cookie_2_real_match++;
		}
		fd_db[fd_idx].non_del.last_real_srv_dst_ip[0] = '\0';
		fd_db[fd_idx].non_del.cookie_struct[0].cookie_ptr[0] = '\0';
	}
}


/**************rx_analyze_payload_content*******************/
uint rx_analyze_payload_content(uint fd_idx)
{
	uint result = SESSION_FINISH , ret = READ_NOT_DONE ;
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;

	if ((/*parsed_msg->analyzed_html*/ parsed_msg->analyzed_html == 0) && ((parsed_msg->html.end) || (fd_db[fd_idx].rx.buffer_full)))
	{/*verify we analyze the HTML only once, otherwise with fragments it will reanalyze packet few times*/
		update_last_values(fd_idx);
		parsed_msg->analyzed_html = 1;
		if (cfg.flag.cookie_reply_2.val)
		{
			analyze_cookie_reply_2((uint)fd_idx);
		}
	}

	/*payload content analyze ONLY after all content arrived*/
	if ((parsed_msg->http.return_code) && (is_content_length_fully_received(fd_idx) == TRUE_1))
	{
		/*handle  200 OK - (20x) close the connection if receive 20x with http.connection = close*/
		if (strncmp(parsed_msg->http.return_code, "20" , strlen("20")) == 0)
		{
			if ((parsed_msg->http.connection) &&
					(strncmp(parsed_msg->http.connection, "close" , strlen("close")) == 0))
			{
				DBG_RX PRINTF_VZ("[%d]**INFO** recieved %s with http.connection:close \n",
						 fd_idx ,parsed_msg->http.return_code);
				cntr.info.closing_upon_http_connection_close++;
				if (cfg.flag.range.val)
				{
					range_global.range_table[fd_idx].state = RANGE_HTTP_CLOSE;
				}
				result = SESSION_FINISH;
			}

			/*handle POST*/
			else if ((cfg.int_v.post_upload.val) &&
					(parsed_msg->html.end) &&
					(strncmp(parsed_msg->http.return_code, "200" , strlen("200")) == 0))
			{
				if (fd_db[fd_idx].gen.state == STATE_SENT_GET)
				{/*get in here only for the 200OK of the GET, and not for the 200OK of the POST...*/
					result = analyze_200_and_post_reply(fd_idx , &fd_db[fd_idx].parser.parsed_msg);
				}
				else if (fd_db[fd_idx].gen.state == STATE_SENT_POST)
				{
					if (parsed_msg->html.success_upload)
					{
						cntr.stat.post_upload_susscess++;
					}
					else
					{
						cntr.stat.post_upload_fail++;
					}
				}
			}
		}

		/*handle 301 , 302*/
		else if ((strncmp(parsed_msg->http.return_code, "301" , strlen("301")) == 0) ||
				(strncmp(parsed_msg->http.return_code, "302" , strlen("302")) == 0))
		{
			if (fd_db[fd_idx].buf.file_name_rcv_buf)
			{
				/*delete the saved 301 file from disk*/
				delete_file_from_disk(fd_db[fd_idx].buf.file_name_rcv_buf);
				fd_db[fd_idx].buf.file_name_rcv_buf[0] ='\0';
			}
			result = analyze_3xx_reply(fd_idx , &fd_db[fd_idx].parser.parsed_msg);
			fd_db[fd_idx].rx.wrote_buf_from_http_end=0; /*it will make the next pkt written to disk from http->end*/
		}
	}
	else
	{
		result = SESSION_CONTINUE;
		ret = READ_NOT_DONE;
	}

	/*data sender RX process*/
	if (cfg.str_v.data_sender[0])
	{
		if (fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_RX)
		{
			result = ds_analyze_rx((uint)fd_idx);
		}
//		return result;
	}

	if (result == SESSION_FINISH)
	{
		close_fd_db(fd_idx , REASON_CONTENT_LENGTH_FULLY_ARRIVED);
		ret = READ_DONE;
	}

	return ret;

}
