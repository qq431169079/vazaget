/* http_parser.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  http_parser.c is part of vazaget.
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
#include <ctype.h>
#include <errno.h>
#include "zlib.h"
#include "global.h"
#include "parsers.h"
#include "rx.h"

/**********************************************************/
/*http_parse_Location*/
/*Location: http://127.0.0.1/tmp/\r\n\*/
/*Location: /home/0,7340,L-8,00.html\r\n\*/
/**********************************************************/
void http_parse_Location(char *buf, parser_struct *parsed_msg /*, int *location_hdr_found*/)
{
	DBG_PARSER	PRINTF_VZ("Starting: (http_state=%d) %c,%c,%c,%c,%c...\n" , parsed_msg->http_state ,buf[0],buf[1],buf[2],buf[3],buf[4]);

	if ((!(IS_STRING_SET(parsed_msg->http.location_path))) &&  /*verify we don't have already path */
			(buf[0] == '/') && /*verify we search for the first / */
			(buf[1] != '/') && /*verify that the next char is not 0, since it can be the second / from the host*/
			(&buf[1] != parsed_msg->http.location_host))
	{
		DBG_PARSER	PRINTF_VZ("found PATH ,%c%c%c%c%c..\n" , buf[0],buf[1],buf[2],buf[3],buf[4] );
		buf[0] = '\0';
		parsed_msg->http.location_path = &buf[1];
	}


	if (!(IS_STRING_SET(parsed_msg->http.location_host))) /*verify we don't have already host */
	{
		if ((buf[0] == '/') && (buf[1] == '/'))
		{
			DBG_PARSER	PRINTF_VZ("found HOST for // ,%c%c%c%c%c...\n" ,buf[0],buf[1],buf[2],buf[3],buf[4]);
			parsed_msg->http.location_host = &buf[2];
		}

		if ((buf[0] == '/') && (parsed_msg->http.location_path == &buf[0]))
		{
			DBG_PARSER	PRINTF_VZ(" Location HOST and PATH are the same, setting NULL on PATH...\n" );
			parsed_msg->http.location_host = &buf[1];
			parsed_msg->http.location_path = NULL;
		}
	}
}

/**********************************************************/
/*http_parse_K*/
/*Keep-Alive: timeout=5, max=100\r\n\*/
/**********************************************************/
char *http_parse_K(char *new_line, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");
	if (strncmp (new_line , "Keep-Alive: ", strlen("Keep-Alive: ")) == 0)
	{/*found the string*/
		parsed_msg->http.keep_alive = new_line + strlen("Keep-Alive: ");
	}
	return NULL;
}

/**********************************************************/
/*http_parse_A*/
/*Accept-Ranges: bytes\r\n\*/
/**********************************************************/
char *http_parse_A(char *new_line, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");

	if (strncmp (new_line , "Accept-Ranges: ", strlen("Accept-Ranges: ")) == 0)
	{/*found the string*/
		parsed_msg->http.accept_ranges = new_line + strlen("Accept-Ranges: ");
	}
	return NULL;
}

/**********************************************************/
/*http_parse_T*/
/*Transfer-Encoding: chunked\r\n\*/
/**********************************************************/
char *http_parse_T(char *new_line, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");
	if (strncmp (new_line , "Transfer-Encoding: ", strlen("Transfer-Encoding: ")) == 0)
	{/*found the string*/
		parsed_msg->http.transfer_encoding = new_line + strlen("Transfer-Encoding: ");
	}
	return NULL;
}


/**********************************************************/
/*http_parse_HTML*/
/*to be on the safe side, we should not get in here...*/
/*<html>*/
/**********************************************************/
char *http_parse_HTML(char *new_line, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");
	if (strncmp (new_line , "<html> ", strlen("<html>")) == 0)
	{/*found the Location*/
		cntr.info.http_parser_reached_html++;
		parsed_msg->http.end = new_line - 1;
		parsed_msg->http.end = '\0';
		return new_line;
	}
	return NULL;
}

/**********************************************************/
/*http_parse_L*/
/*Location: http://127.0.0.1/tmp/\r\n\*/
/**********************************************************/
char *http_parse_L(char *new_line, parser_struct *parsed_msg /*, int *location_hdr_found*/)
{
	DBG_PARSER PRINTF_VZ("==>Starting...\n");
	if (strncmp (new_line , "Location: ", strlen("Location: ")) == 0)
	{/*found the Location*/
		DBG_PARSER PRINTF_VZ("===>Found Location: ...\n");
		parsed_msg->http.location = new_line + strlen("Location: ");
		/**location_hdr_found = 1;*/
		parsed_msg->http_state = HTTP_PARSE_LOCATION;

	}
	return NULL;
}

/**********************************************************/
/*http_parse_H*/
/*HTTP/1.1 200 OK\r\n\ */
/**********************************************************/
char *http_parse_H(char *new_line, parser_struct *parsed_msg, int *replace_space_with_null)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");
	if (strncmp (new_line , "HTTP/", strlen("HTTP/")) == 0)
	{/*found the HTTP/*/
		parsed_msg->http.http_proto = new_line + strlen("HTTP/");
		if (new_line[strlen("HTTP/1.1")] == 0x20) /*found space char*/
		{
			*replace_space_with_null = *replace_space_with_null + 1;
			parsed_msg->http.return_code = new_line + strlen("HTTP/1.1 ");
		}

		if (new_line[strlen("HTTP/1.1 200")] == 0x20) /*found space char*/
		{
			*replace_space_with_null = *replace_space_with_null + 1;
			parsed_msg->http.return_phrase = new_line + strlen("HTTP/1.1 200 ");
		}
	}
	return NULL;
}

/**********************************************************/
/*http_parse_C*/
/*Content-Length: 152\r\n\ */
/*Content-Type: text/html\r\n\*/
/*Content-Encoding: gzip\r\n\*/
/*Connection: close\r\n\*/
/**********************************************************/
char *http_parse_C(char *new_line, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ("-Starting...\n");

	if (strncmp (new_line , "Content-Length: ", strlen("Content-Length: ")) == 0)
	{/*found the set_cookie_string*/
		parsed_msg->http.content_length = new_line + strlen("Content-Length: ");
	}

	if (strncmp (new_line , "Content-Type: ", strlen("Content-Type: ")) == 0)
	{/*found the set_cookie_string*/
		parsed_msg->http.content_type = new_line + strlen("Content-Type: ");
	}

	if (strncmp (new_line , "Content-Encoding: ", strlen("Content-Encoding: ")) == 0)
	{/*found the set_cookie_string*/
		parsed_msg->http.content_encoding = new_line + strlen("Content-Encoding: ");
	}

	if (strncmp (new_line , "Connection: ", strlen("Connection: ")) == 0)
	{/*found the set_cookie_string*/
		parsed_msg->http.connection = new_line + strlen("Connection: ");
	}

	if (strncmp (new_line , "Content-Range: ", strlen("Content-Range: ")) == 0)
	{/*found the set_cookie_string*/
		parsed_msg->http.content_range = new_line + strlen("Content-Range: ");
	}

	return NULL;
}
/**********************************************************/
/*http_parse_S*/
/**********************************************************/
char *http_parse_S (char *new_line, parser_struct *parsed_msg, int *set_cookie_found)
{
	int i;
	char set_cookie_string[]={"Set-Cookie: "};
	uint str_length = (uint)strlen(set_cookie_string);

	DBG_PARSER PRINTF_VZ("-Starting...\n");
	if (strncmp (new_line , set_cookie_string, str_length) == 0)
	{/*found the set_cookie_string*/
		for (i = 0 ; i < MAX_PARSED_COOKIES ; i++)
		{
			if (parsed_msg->http.set_cookie[i])
			{/*cookie entry in use, keep on searching*/
				if ((parsed_msg->http.set_cookie[i]) == (new_line + str_length))
				{
					DBG_PARSER PRINTF_VZ("-Set-Cookie entry already exist in i=%d\n",i);
					*set_cookie_found = 1;
					break;
				}
				else
				{
					continue;
				}
			}
			else
			{
				parsed_msg->http.set_cookie[i] = new_line + str_length;
				*set_cookie_found = 1;
				break;
			}
			if (i == (MAX_PARSED_COOKIES - 1))
			{
				cntr.warning.parser_reached_max_cookies++;
			}
		}
	}
	return NULL;
}


/**********************************************************/
/*parser_handle_eol*/
/**********************************************************/
char *parser_terminate_eol(char *eol_ptr , parser_struct *parsed_msg  , int offset_from_line_start)
{
	char *ret_ptr = NULL;

	DBG_PARSER PRINTF_VZ("start eol_ptr[0]=0x%x, ptr[1]=0x%x , offset_from_line_start=%d\n",eol_ptr[0] , eol_ptr[1] , offset_from_line_start);

	if (parsed_msg->http_state == HTTP_PARSE_LOCATION)
	{
		parsed_msg->http_state = HTTP_PARSE_START;
	}

	/*eol_ptr[0]*/
	if (eol_ptr[0] == '\r')
	{ /*for \r we will continue parsing, return NULL*/
		eol_ptr[0] = '\0';
	}
	else if (eol_ptr[0] == '\n')
	{
		eol_ptr[0] = '\0';
		ret_ptr = &eol_ptr[1];
	}

	/*eol_ptr[1]*/
	if (eol_ptr[1] == '\r')
	{ /*for \r we will continue parsing, return NULL*/
		eol_ptr[1] = '\0';
	}
	else if (eol_ptr[1] == '\n')
	{
		eol_ptr[1] = '\0';
		ret_ptr = &eol_ptr[2];
	}

	if (ret_ptr)
	{
		DBG_PARSER PRINTF_VZ("EOL found \n");
		if (offset_from_line_start==0 || offset_from_line_start==1)
		{
			DBG_PARSER PRINTF_VZ("Reached to the end of HTTP hdr...\n");
			parsed_msg->http.end = ret_ptr;
			parsed_msg->http_state = HTTP_PARSE_END;
		}
	}
	else
	{
		DBG_PARSER PRINTF_VZ("EOL not found \n");
	}

	return ret_ptr;

}

/**********************************************************/
/*handle_end_of_http_hdr*/
/**********************************************************/
void handle_end_of_http_hdr(char *eol_ptr, parser_struct *parsed_msg , int offset_from_line_start)
{
	DBG_PARSER PRINTF_VZ("-Starting... eol_ptr[0]=0x%x , eol_ptr[1]=0x%x\n",eol_ptr[0] , eol_ptr[1]);

	if ((eol_ptr[0] == '\n') || (eol_ptr[1] == '\n'))
	{
		if (offset_from_line_start==0 || offset_from_line_start==1)
		{
			parsed_msg->http.end = parser_terminate_eol(eol_ptr , parsed_msg , offset_from_line_start);
			parsed_msg->http_state = HTTP_PARSE_END;
		}
		else
		{
			parser_terminate_eol(eol_ptr , parsed_msg , offset_from_line_start);
		}
	}

	if (parsed_msg->http.end)
	{
		DBG_PARSER PRINTF_VZ("Found End Of HTTP hdr parsed_msg->http.end[0]=0x%x(%c),[1]=0x%x(%c)\n",
				parsed_msg->http.end[0],parsed_msg->http.end[0],
				parsed_msg->http.end[1],parsed_msg->http.end[1]);
	}
	else
	{
		DBG_PARSER PRINTF_VZ(" NOT Found End Of HTTP hdr\n");
	}


	return;
}




/**********************************************************/
/*http_parse_line*/
/*Return value*/
/*NULL - if not reached to EOL*/
/*POINTER - if EOL founded*/
/**********************************************************/
char *http_parse_line(char *new_line, parser_struct *parsed_msg, uint max_chars_to_parse)
{
	uint ch;
	char *next_line = NULL;
	int set_cookie_found = 0;
	int replace_space_with_null = 0 /*, location_hdr_found = 0*/;
	uint chars_so_far = (uint)(new_line - parsed_msg->http.start);
	uint chars_to_parse = max_chars_to_parse - chars_so_far;

	for (ch=0 ; ch < chars_to_parse ; ch++)
	{
		int offset_from_line_start = (int)(&new_line[ch] - parsed_msg->last_http_parsed_line);
		DBG_PARSER PRINTF_VZ("ch=%d, max_chars_to_parse=%d, chars_so_far=%d, , chars_to_parse=%d, offset_from_line_start=%d, new_line[%d]=%c(0x%x)\n",
				ch ,max_chars_to_parse , (int) (&new_line[ch] - parsed_msg->http.start) ,chars_to_parse , offset_from_line_start , ch , new_line[ch], new_line[ch] );
		/***Examine the first character ONLY*/
		if (ch == 0)
		{
			switch(/*tolower*/(new_line[ch]))
			{
			case '\0':
				DBG_PARSER PRINTF_VZ("Begin with 0, continue...)\n");
				continue;
				/*\r\n*/
			case '\r':
			case '\n':
				handle_end_of_http_hdr(&new_line[ch] , parsed_msg , offset_from_line_start);
				return NULL;

				/*HTTP\1.1*/
			case 'H':
				next_line = http_parse_H(&new_line[ch], parsed_msg, &replace_space_with_null);
				continue;
				/*Set-Cookie*/
			case 'S':
				next_line = http_parse_S(&new_line[ch], parsed_msg, &set_cookie_found);
				continue;
				/*Content-length*/
			case 'C':
				next_line = http_parse_C(&new_line[ch], parsed_msg);
				continue;
			case 'L':
				next_line = http_parse_L(&new_line[ch], parsed_msg/*, &location_hdr_found*/);
				continue;
			case 'T':
				next_line = http_parse_T(&new_line[ch], parsed_msg);
				continue;
			case 'A':
				next_line = http_parse_A(&new_line[ch], parsed_msg);
				continue;
			case 'K':
				next_line = http_parse_K(&new_line[ch], parsed_msg);
				continue;
			case '\t':
				cntr.info.http_parser_line_start_with_tab++;
				continue;

				/*<HTML>*/
			case '<': /*we should not get in here, only if **FAIL** HTTP parsing*/
				next_line = http_parse_HTML(&new_line[ch] , parsed_msg);
				if (next_line == NULL)
					continue;
				else
				{
					DBG_PARSER PRINTF_VZ("**WARNING**, http parser reached to <HTML>, stopping http parser, return next_line(0x%p)[0]=0x%x,[1]=0x%x ...)\n",next_line ,next_line[0],next_line[1]);
					return next_line;
				}
			default:
				DBG_PARSER PRINTF_VZ("unknown http parse line");
				cntr.info.http_parser_unknon_header_line++;
				continue;
			}
		}
		/***Examine the rest of the chars*/
		else
		{
			/***Search for the EOL character*/
			switch(/*tolower*/(new_line[ch]))
			{
			case '\0':
				DBG_PARSER PRINTF_VZ("middle with 0, continue...)\n");
				continue;
				//				return NULL;
				/*\r\n*/
			case '\r': /*remove the /r since it get to scenario where first char is /r then assume it's end of HTTP header*/
			case '\n':
				next_line = parser_terminate_eol(&new_line[ch] , parsed_msg , offset_from_line_start);
				if (next_line == NULL)
					continue;
				else
				{
					DBG_PARSER PRINTF_VZ("Reached to end of line, return next_line(0x%p)[0]=0x%x,[1]=0x%x ...)\n",next_line ,next_line[0],next_line[1]);
					return next_line;
				}

				/*<HTML>*/
			case '<': /*we should not get in here, only if **FAIL** parsing*/
				next_line = http_parse_HTML(&new_line[ch] , parsed_msg);
				if (next_line == NULL)
					continue;
				else
				{
					DBG_PARSER PRINTF_VZ("**WARNING**, http parser reached to <HTML>, stopping http parser, return next_line(0x%p)[0]=0x%x,[1]=0x%x ...)\n",next_line ,next_line[0],next_line[1]);
					return next_line;
				}

				/*cut the rest of the cookie*/
			case ';':
				if (set_cookie_found) new_line[ch] = '\0';
				continue;
			case '/':
				//				DBG_PARSER PRINTF_VZ("/ found (ch=%d), parsed_msg->http_state=%d\n",ch,parsed_msg->http_state);
				if (/*location_hdr_found*/ parsed_msg->http_state == HTTP_PARSE_LOCATION)
				{
					http_parse_Location(&new_line[ch], parsed_msg /*, &location_hdr_found*/);
				}
				continue;
				/*replace space with NULL*/
			case 0x20:
				if (replace_space_with_null)
				{
					new_line[ch] = '\0';
					replace_space_with_null--;
				}
				continue;
			}
		}
	}
	DBG_PARSER PRINTF_VZ("reached to end of FOR, ch(%d)= max_chars_to_parse(%d),returning (%p)\n",ch , max_chars_to_parse ,next_line);
	return next_line;
}


/**********************************************************/
/*http_parse*/
/*the HTTP parser will replace each \r\n with /0\n*/
/*e.g: */
/*Vary: Accept-Encoding\r\n\ */
/*Content-Length: 152\r\n\ */
/*will become==> */
/*Vary: Accept-Encoding/0\n\ */
/*Content-Length: 152/0\n\ */
/**********************************************************/
char *http_parse(char *buf, parser_struct *parsed_msg, uint max_chars_to_parse)
{
	uint i;
	char *new_line_to_parse = NULL;
	char *last_parsed_line = NULL;

	if (buf == NULL)
	{
		DBG_PARSER PRINTF_VZ(" buf=NULL --> returning NULL...\n");
		return NULL;
	}

	if (!((buf[0] == 'H') &&
			(buf[1] == 'T') &&
			(buf[2] == 'T') &&
			(buf[3] == 'P')))
	{ /*not HTTP header...*/
		DBG_PARSER PRINTF_VZ(" not HTTP packet --> returning NULL...\n");
		return NULL;
	}

	if (parsed_msg->http.end)
	{/*Already parsed the HTTP header and founded the end of HTTP...*/
		DBG_PARSER PRINTF_VZ(" parsed_msg->http.end already exist --> returning NULL...\n");
		return NULL;
	}

	if (!parsed_msg->http.start)
	{
		parsed_msg->http.start = buf;
		DBG_PARSER	PRINTF_VZ_N ("-->Starting HTTP parser\n%s\n",parsed_msg->http.start);
	}
	if (parsed_msg->last_http_parsed_line)
	{/*if we get the packet in chunks, then we keep on parsing from the last line*/
		new_line_to_parse = parsed_msg->last_http_parsed_line;
		DBG_PARSER	PRINTF_VZ_N ("-->Continue HTTP parser\n%s\n",new_line_to_parse);
	}
	else
	{
		new_line_to_parse = buf;
		parsed_msg->last_http_parsed_line = new_line_to_parse;
	}
	for (i = 0 ; i < MAX_HTTP_PARSE_LINES ; i++)
	{
		DBG_PARSER PRINTF_VZ("HTTP parsed line=%d\n%s\n",i,new_line_to_parse);
		new_line_to_parse = http_parse_line(new_line_to_parse, parsed_msg , max_chars_to_parse);
		if (new_line_to_parse == NULL)
		{/*EOL NOT found*/
			last_parsed_line = parsed_msg->last_http_parsed_line;
			DBG_PARSER PRINTF_VZ("No more to parse, keeping last line and return, i=%d, last_parsed_line=%p\n",i,last_parsed_line);
			break;
		}
		else
		{
			/*EOL found*/
			last_parsed_line = new_line_to_parse;/*keep the ptr to the last parsed line*/
			parsed_msg->last_http_parsed_line = last_parsed_line;
			DBG_PARSER PRINTF_VZ("continue to next line =%s\n",last_parsed_line);
		}
		if (parsed_msg->http.end)
		{
			DBG_PARSER PRINTF_VZ("Reached to END of HTTP header, last_parsed_line=%p\n",last_parsed_line);
			break;
		}
	}
	if (i == (MAX_HTTP_PARSE_LINES))
	{
		cntr.warning.parser_reached_max_lines++;
	}
	parsed_msg->http_parsed_lines_so_far += i;
	DBG_PARSER PRINTF_VZ_N ("<--HTTP parsed DONE, total lines(in cur iteration)=%d , http_parsed_lines_so_far=%d\n",i , parsed_msg->http_parsed_lines_so_far);

	return last_parsed_line;
}

/**********************************************************/
/*inflate_gzip*/
/**********************************************************/
int inflate_gzip(const char *src, uint srcLen, const char *dst, uint dstLen)
{
	z_stream strm;
	strm.zalloc=Z_NULL;
	strm.zfree=Z_NULL;
	strm.opaque=Z_NULL;

	strm.avail_in = srcLen;
	strm.avail_out = dstLen;
	strm.next_in = (Bytef *)src;
	strm.next_out = (Bytef *)dst;

	int err=-1;
	err = inflateInit2(&strm, MAX_WBITS+16);
	if (err != Z_OK)
	{
		inflateEnd(&strm);
		DBG_PARSER PRINTF_VZ(" inflateInit2 error, err=%d\n",err);
		return err;
	}

	err = inflate(&strm, Z_FINISH);
	if (err < 0)
	{
		inflateEnd(&strm);
		DBG_PARSER PRINTF_VZ(" inflate error, err=%d\n",err);
		return err;
	}

	inflateEnd(&strm);
	return (int)strm.avail_out;
}


/**********************************************************/
/*decompress_gzip*/
/**********************************************************/
uint decompress_gzip( uint fd_idx ,parser_struct *parsed_msg , char *extract_buf)
{
	int avail_un_compLen = 0;
	uint extracted_len = 0;
	uint compLen = (uint)(atoi (parsed_msg->http.content_length));
	if (compLen <= 0)
	{
		cntr.warning.failed_to_read_content_length++;
		DBG_PARSER PRINTF_VZ(" Illegal parsed_msg->http.content_length=%d\n",compLen);
		return 0;
	}
	else
	{
		DBG_PARSER PRINTF_VZ("Start Inflating GZIP reply ,rcv_bytes=%"PRIu64"/%"PRIu64" compLen=%d, avail_un_compLen=%d, \n",
				fd_db[fd_idx].rx.rcv_bytes, fd_db[fd_idx].rx.bytes_to_rcv, compLen, RCV_BUF_SIZE);
		/* Inflate GZIP reply*/
		avail_un_compLen = inflate_gzip(parsed_msg->http.end, compLen , extract_buf, RCV_BUF_SIZE);
		if (avail_un_compLen >= 0)
		{
			extracted_len = RCV_BUF_SIZE - (uint)avail_un_compLen;
			DBG_PARSER PRINTF_VZ(" success Inflate GZIP, extracted=%d, avail_un_compLen=%d, extract_buf-->\n%s\n", extracted_len , avail_un_compLen, extract_buf);
		}
		else
		{
			cntr.warning.gzip_inflate_error++;
			DBG_PARSER PRINTF_VZ(" Inflate FAIL, avail_un_compLen=%d\n",avail_un_compLen);
		}
	}
	return extracted_len;
}



/**********************************************************/
/*is_more_to_receive*/
/**********************************************************/
uint is_more_to_receive(uint fd_idx)
{

	if (fd_db[fd_idx].rx.rcv_bytes == fd_db[fd_idx].rx.bytes_to_rcv)
	{
		DBG_RX PRINTF_VZ("fd_db[%d] all content length received! bytes_to_rcv(%"PRIu64")=rcv_bytes(%"PRIu64")\n",
				fd_idx , fd_db[fd_idx].rx.bytes_to_rcv ,fd_db[fd_idx].rx.rcv_bytes);
		return TRUE_1;
	}
	return FALSE_0;
}

/**********************************************************/
/*is_content_length_fully_received*/
/**********************************************************/
int is_content_length_fully_received(uint fd_idx)
{
	uint64_t http_content_length;
	uint http_hdr_length;
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;



	/*already have the bytes_to_rcv...*/
	if (fd_db[fd_idx].rx.bytes_to_rcv)
	{
		if (is_more_to_receive(fd_idx) == TRUE_1)
		{
			DBG_RX PRINTF_VZ("a. return TRUE_1\n");
			return TRUE_1;
		}
	}

	/*find out the bytes_to_rcv...*/
	if ((parsed_msg->http.end) && (parsed_msg->http.content_length) && (fd_db[fd_idx].rx.bytes_to_rcv == 0))
	{
		char *pEnd = NULL;
		http_hdr_length = (uint)(parsed_msg->http.end - parsed_msg->http.start);

		errno = 0;

		http_content_length = strtoull(parsed_msg->http.content_length , &pEnd , 10);

		if (/*(http_content_length >= 0) && */ (errno == 0))
		{
			fd_db[fd_idx].rx.bytes_to_rcv = http_hdr_length + http_content_length;
			if ((file_download_global.file_size == 0) && (IS_STRING_SET(cfg.dest_params.file_name_ptr)))
			{
				file_download_global.file_size = fd_db[fd_idx].rx.bytes_to_rcv;
			}
			DBG_RX PRINTF_VZ("fd_db[%d].rx.bytes_to_rcv(%"PRIu64")=http_hdr_length(%u)+http_content_length(%"PRIu64")\n",
					fd_idx , fd_db[fd_idx].rx.bytes_to_rcv , http_hdr_length , http_content_length);

			if (is_more_to_receive(fd_idx) == TRUE_1)
			{
				return TRUE_1;
			}
		}
	}

	return FALSE_0;
}

/**********************************************************/
/*print_parse_results*/
/**********************************************************/
void print_parse_results(parser_struct *parsed_msg)
{
	int i;

	PRINTF_VZ_N ("---------HTTP parse results:---------\n");
	//	PRINTF_VZ_N ("parsed_msg.start=%s\n",parsed_msg.http_start);
	PRINTF_VZ_N ("parsed_msg->http.http_proto=%s\n",parsed_msg->http.http_proto);
	PRINTF_VZ_N ("parsed_msg->http.return_code=%s\n",parsed_msg->http.return_code);
	PRINTF_VZ_N ("parsed_msg->http.return_phrase=%s\n",parsed_msg->http.return_phrase);
	PRINTF_VZ_N ("parsed_msg->http.location=%s\n",parsed_msg->http.location);
	PRINTF_VZ_N ("parsed_msg->http.location_host=%s\n",parsed_msg->http.location_host);
	PRINTF_VZ_N ("parsed_msg->http.location_path=%s\n",parsed_msg->http.location_path);
	for (i=0 ; i < MAX_PARSED_COOKIES ; i++)
	{
		if(parsed_msg->http.set_cookie[i])
			PRINTF_VZ_N ("Set-Cookie[%d]:=%s\n",i,parsed_msg->http.set_cookie[i]);
	}
	PRINTF_VZ_N ("parsed_msg->http.content_length=%s\n",parsed_msg->http.content_length);
	PRINTF_VZ_N ("parsed_msg->http.content_type=%s\n",parsed_msg->http.content_type);
	PRINTF_VZ_N ("parsed_msg->http.content_encoding=%s\n",parsed_msg->http.content_encoding);
	PRINTF_VZ_N ("parsed_msg->http.transfer_encoding=%s\n",parsed_msg->http.transfer_encoding);
	PRINTF_VZ_N ("parsed_msg->http.accept_ranges=%s\n",parsed_msg->http.accept_ranges);
	PRINTF_VZ_N ("parsed_msg->http.content_range=%s\n",parsed_msg->http.content_range);
	PRINTF_VZ_N ("parsed_msg->http.keep_alive=%s\n",parsed_msg->http.keep_alive);
	PRINTF_VZ_N ("parsed_msg->http.connection=%s\n",parsed_msg->http.connection);
	if (parsed_msg->http.end)
		PRINTF_VZ_N ("parsed_msg->http.end Found\n");
	else
		PRINTF_VZ_N ("parsed_msg->http.end NOT Found\n");

	PRINTF_VZ_N ("HTML parse results:\n");
	//	PRINTF_VZ_N ("parsed_msg.html.start=%s\n",parsed_msg.html.start);
	PRINTF_VZ_N ("parsed_msg->html.vazaget_srv=%s\n",parsed_msg->html.vazaget_srv);
	PRINTF_VZ_N ("parsed_msg->html.srv_src_ip=%s\n",parsed_msg->html.srv_src_ip);
	PRINTF_VZ_N ("parsed_msg->html.srv_src_port=%s\n",parsed_msg->html.srv_src_port);
	PRINTF_VZ_N ("parsed_msg->html.srv_dst_ip=%s\n",parsed_msg->html.srv_dst_ip);
	PRINTF_VZ_N ("parsed_msg->html.srv_dst_port=%s\n",parsed_msg->html.srv_dst_port);
	PRINTF_VZ_N ("parsed_msg->html.http_protocol=%s\n",parsed_msg->html.http_protocol);
	PRINTF_VZ_N ("parsed_msg->html.http_cookie=%s\n",parsed_msg->html.http_cookie);
	PRINTF_VZ_N ("parsed_msg->html.http_via=%s\n",parsed_msg->html.http_via);
	PRINTF_VZ_N ("parsed_msg->html.x_forwarded_for=%s\n",parsed_msg->html.x_forwarded_for);
	PRINTF_VZ_N ("parsed_msg->html.ssl_sess_id=%s\n",parsed_msg->html.ssl_sess_id);
	PRINTF_VZ_N ("parsed_msg->html.form=%s\n",parsed_msg->html.form);
	PRINTF_VZ_N ("parsed_msg->html.form_action=%s\n",parsed_msg->html.form_action);
	PRINTF_VZ_N ("parsed_msg->html.form_method=%s\n",parsed_msg->html.form_method);
	PRINTF_VZ_N ("parsed_msg->html.form_enctype=%s\n",parsed_msg->html.form_enctype);
	PRINTF_VZ_N ("parsed_msg->html.success_upload=%s\n",parsed_msg->html.success_upload);
	if (parsed_msg->html.end)
		PRINTF_VZ_N ("parsed_msg->html.end=Found\n");
	else
		PRINTF_VZ_N ("parsed_msg->html.end=NOT Found\n");
	PRINTF_VZ_N ("-------------------------------------\n");
}

/**********************************************************/
/*test_http_parse*/
/**********************************************************/
void test_http_parse()
{
	parser_struct parsed_msg;
#if 0
	char input_string[]={"HTTP/1.1 200 OK\r\n\
	Set-Cookie: virt-2=2001000000000000000000000000001120010000000000000000000000000001707fcfc00050\r\n\
	Date: Sun, 28 Oct 2012 13:35:06 GMT\r\n\
	Server: Apache/2.2.22 (Ubuntu)\r\n\
	Set-Cookie: Apache=2001::11.1351431306181051; path=/\r\n\
	X-Powered-By: PHP/5.3.10-1ubuntu3.2\r\n\
	Vary: Accept-Encoding\r\n\
	Content-Length: 152\r\n\
	Keep-Alive: timeout=5, max=100\r\n\
	Connection: Keep-Alive\r\n\
	Content-Type: text/html\r\n\
	\r\n"};

	char input_string[]={"HTTP/1.1 200 OK\r\n\
Set-Cookie: virt-2=2001000000000000000000000000001120010000000000000000000000000001707fcfc00050\r\n\
Date: Sun, 28 Oct 2012 13:35:06 GMT\r\n\
Server: Apache/2.2.22 (Ubuntu)\r\n\
Set-Cookie: Apache=2001::11.1351431306181051; path=/\r\n\
X-Powered-By: PHP/5.3.10-1ubuntu3.2\r\n\
Vary: Accept-Encoding\r\n\
Content-Length: 152\r\n\
Keep-Alive: timeout=5, max=100\r\n\
Connection: Keep-Alive\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><h1>VazaGet server!</h1>\
ClientSrcIP=2001::11<br />ClientSrcPort=2057<br />ClientDstIP=2002::11<br />ClientDstPort=80<br />\
</body>\
</html>"};


	char input_string[]={"HTTP/1.1 200 OK\r\n\
Date: Wed, 31 Oct 2012 14:51:28 GMT\r\n\
Server: Apache/2.2.22 (Ubuntu)\r\n\
Set-Cookie: Apache=127.0.0.1.1351695088405024; path=/\r\n\
X-Powered-By: PHP/5.3.10-1ubuntu3.4\r\n\
Vary: Accept-Encoding\r\n\
Content-Length: 154\r\n\
Keep-Alive: timeout=5, max=100\r\n\
Connection: Keep-Alive\r\n\
Content-Type: text/html\r\n\
\r\n\
<html><body><h1>VazaGet server!</h1>\
ClientSrcIP=127.0.0.1<br />ClientSrcPort=42605<br />ClientDstIP=127.0.0.1<br />ClientDstPort=80<br /></body>\
</html>"};


	char input_string[]={"HTTP/1.1 200 OK\r\n\
Date: Thu, 08 Nov 2012 16:09:37 GMT\r\n\
Server: Apache/2.2.22 (Ubuntu)\r\n\
X-Powered-By: PHP/5.3.10-1ubuntu3.2\r\n\
Vary: Accept-Encoding\r\n\
Content-Encoding: gzip\r\n\
Content-Length: 228\r\n\
Connection: close\r\n\
Content-Type: text/html\r\n\
\r\n\
<html>\n\
<body>\n\
\n\
<center><b>VazaGet server!</b></center>\n\
<hr>\n\
\n\
ClientSrcIP=1.1.1.1 <br />\n\
ClientSrcPort=48255 <br />\n\
ClientDstIP=5.1.1.1 <br />\n\
ClientDstPort=80 <br />\n\
HttpProtocol=HTTP/1.1 <br />\n\
X-ForwardedFor=20.20.1.1 <br />\n\
HttpCookie=Apache=1.1.1.1.1352383959905050 <br />\n\
HttpVia=1.1 localhost (squid/3.1.19) <br />\n\
\n\
</body>\n\
</html>\n"};


	char input_string[]={"HTTP/1.1 200 OK\r\n\
Date: Mon, 19 Nov 2012 14:15:45 GMT\r\n\
Server: Apache/2.2.22 (Ubuntu)\r\n\
Set-Cookie: Apache=127.0.0.1.1353334545744802; path=/\r\n\
X-Powered-By: PHP/5.3.10-1ubuntu3.4\r\n\
Vary: Accept-Encoding\r\n\
Keep-Alive: timeout=5, max=100\r\n\
Connection: Keep-Alive\r\n\
Transfer-Encoding: chunked\r\n\
Content-Type: text/html\r\n\
\r\n"};




	char input_string[]={"HTTP/1.1 301 Moved Permanently\r\n\
Date: Wed, 14 Nov 2012 12:59:08 GMT\r\n\
Server: Apache/2.2.22 (Ubuntu)\r\n\
Set-Cookie: Apache=127.0.0.1.1352897948767575; path=/\r\n\
X-Powered-By: PHP/5.3.10-1ubuntu3.4\r\n\
Location: http://127.0.0.1/tmp/\r\n\
Vary: Accept-Encoding\r\n\
Content-Encoding: gzip\r\n\
Content-Length: 20\r\n\
Keep-Alive: timeout=5, max=99\r\n\
Connection: Keep-Alive\r\n\
Content-Type: text/html\r\n\
\r\n"};
#endif

	char input_string[]={"HTTP/1.1 301 Moved Permanently\r\n\
Server: AkamaiGHost\r\n\
Content-Length: 0\r\n\
Location: /home/0,7340,L-8,00.html\r\n\
Cache-Control: max-age=0\r\n\
Expires: Tue, 20 Nov 2012 15:38:15 GMT\r\n\
Date: Tue, 20 Nov 2012 15:38:15	GMT\r\n\
Connection: keep-alive\r\n\
\r\n"};

	//	PRINTF_VZ_N ("test_http_parse - input string = \n%s \n",input_string);

	memset(&parsed_msg, 0 , sizeof (parser_struct));
	PRINTF_VZ_N ("------>Starting HTTP parse:\n");
	parsed_msg.last_http_parsed_line = http_parse(input_string , &parsed_msg , (uint)strlen (input_string));
	PRINTF_VZ_N ("------>Starting HTML parse:\n");
	parsed_msg.last_html_parsed_tag = html_parse(parsed_msg.http.end ,  &parsed_msg, (uint)strlen (input_string));
	print_parse_results(&parsed_msg);
	exit_vz(EXIT_FAILURE, NULL);
}
