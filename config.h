/*
 * config.h
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  config.h is part of vazaget.
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

#ifndef CONFIG_H_
#define CONFIG_H_

#define DEFAULT_CFG				0
#define USER_CFG				1
#define OVERWRITE_CFG			2
#define OVERWRITE_IN_RUN_TIME	3

#define MAX_NUM_OF_SESSIONS		0x7fffffff /*2^31 since it's int value...*/
#define MAX_RX_THREADS			10

#define MAX_PORT_VALUE			65535
#define MAX_CHUNKS_ON_SINGLE_BUF 100
#define MAX_CHUNK_BUF_SIZE 		500000
#define DEFAULT_HTTP_VERSION	"1.1"

#define MAX_DEBUG_COUNTERS		0x7
#define DEBUG_COUNTER_ERROR		0x1
#define DEBUG_COUNTER_WARNING	0x2
#define DEBUG_COUNTER_INFO		0x4

#define DEFAULT_DEBUG_COUNTER		0x3 /* ERROR + WARNING */

/*cfg*/
void display_commands_usage();
void display_php_file();
void parse_ip_addr_and_path(char *rcv_ip_string);
void usage();
void usage_hidden();
void usage_data_sender();
void fill_default_param();
void params_parser (int argc, char **argv);
void validate_config_values();
void init_uri_parser_pointers (uri_parser *uri_parser_struct);
uint validate_http_protocol(uri_parser *uri_parse, int support_https);

uint  parse_destination_url(char *uri_rcv_string , uri_parser *uri_parse);
int validate_and_convert_ip_address_from_string(uri_parser *uri_parse);
uint validate_and_convert_port_from_string(uri_parser *uri_parse);
uint resolve_dns_web_address(uri_parser *uri_parse);
void dbg_print_url_pars_struct(uri_parser *uri_parse);
char *strnstr(char *buf, char *find , uint max_len);
char *get_dest_host_ptr(uri_parser *url_parser);


#endif /* CONFIG_H_ */
