/* parsers.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  parsers.h is part of vazaget.
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

#ifndef HTTP_PARSER_H_
#define HTTP_PARSER_H_

#define MAX_PARSED_COOKIES 		10
#define MAX_HTTP_PARSE_LINES	100

#define MAX_HTML_PARSE_TAGS			1000

/*HTML parser State*/
typedef enum {
	HTML_PARSE_START,
	HTML_PARSE_OPEN_TAG,
	HTML_PARSE_FORM,
	HTML_PARSE_CLOSE_TAG,
	HTML_PARSE_END,
	HTML_PARSE_MAX
}HTML_PARSER_STATE;


/*HTTP parser State*/
typedef enum {
	HTTP_PARSE_START,
	HTTP_PARSE_LOCATION,
	HTTP_PARSE_END,
	HTTP_PARSE_MAX
}HTTP_PARSER_STATE;

typedef struct
{
	char *start;
	char *vazaget_srv;
	char *srv_src_ip;
	char *srv_src_port;
	char *srv_dst_ip;
	char *srv_dst_port;
	char *http_protocol;
	char *http_cookie;
	char *http_via;
	char *x_forwarded_for;
	char *ssl_sess_id;
	char *form;
	char *form_action;
	char *form_method;
	char *form_enctype;
	char *success_upload; /*use it to make sure we not posting again on the 200OK*/
	char *end;
}html_struct;

typedef struct
{
	char *start;
	char *http_proto;
	char *return_code;
	char *return_phrase;
	char *location;
	char *location_host;
	char *location_path;
	char *set_cookie[MAX_PARSED_COOKIES+1];
	char *content_length;
	char *content_type;
	char *content_encoding;
	char *transfer_encoding;
	char *accept_ranges;
	char *content_range;
	char *connection;
	char *keep_alive;
	char *end;
}http_struct;

typedef struct
{
	http_struct http;
	char 		*last_http_parsed_line;
	uint 		http_parsed_lines_so_far;
	int			analyzed_http;
	uint 		http_state;
	html_struct html;
	char 		*last_html_parsed_tag;
	int			analyzed_html;
	uint		html_state;
}parser_struct;

char *html_parse(char *buf, parser_struct *parsed_msg , uint max_chars_to_parse);

/*CHUNK parser State*/
typedef enum {
	CHUNK_PARSE_START = 0,
	CHUNK_PARSE_OPEN_CR_FOUND,
	CHUNK_PARSE_OPEN_LF_FOUND,
	CHUNK_PARSE_CLOSE_CR_FOUND,
	CHUNK_PARSE_CLOSE_LF_FOUND,
	CHUNK_PARSE_MAX
}CHUNK_PARSER_STATE;
#endif /* HTTP_PARSER_H_ */
