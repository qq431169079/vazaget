/* html_parser.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  html_parser.c is part of vazaget.
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
#include "global.h"
#include "parsers.h"

/**********************************************************/
/*html_parse_form_enctype*/
/**********************************************************/
void html_parse_form_enctype(char *buf, parser_struct *parsed_msg)
{
	char form_enctype_string[]={"enctype="};
	uint str_length = (uint)strlen(form_enctype_string);

	DBG_PARSER PRINTF_VZ(" starting...\n");
	if (strncmp (buf , form_enctype_string, str_length) == 0)
	{/*found the vazaget_srv_string*/
		parsed_msg->html.form_enctype = buf + str_length;
	}
	return;
}

/**********************************************************/
/*html_parse_form_method*/
/**********************************************************/
void html_parse_form_method(char *buf, parser_struct *parsed_msg)
{
	char form_method_string[]={"method="};
	uint str_length = (uint)strlen(form_method_string);

	DBG_PARSER PRINTF_VZ(" starting...\n");
	if (strncmp (buf , form_method_string, str_length) == 0)
	{/*found the vazaget_srv_string*/
		parsed_msg->html.form_method = buf + str_length;
	}
	return;
}

/**********************************************************/
/*html_parse_form_action*/
/**********************************************************/
void html_parse_form_action(char *buf, parser_struct *parsed_msg)
{
	char form_action_string[]={"action="};
	uint str_length = (uint)strlen(form_action_string);

	DBG_PARSER PRINTF_VZ(" starting...\n");
	if (strncmp (buf , form_action_string, str_length) == 0)
	{/*found the vazaget_srv_string*/
		parsed_msg->html.form_action = buf + str_length;
	}
	return;
}

/**********************************************************/
/*html_parse_form*/
/**********************************************************/
void html_parse_form(char *buf, parser_struct *parsed_msg)
{
	char form_string[]={"form"};
	uint str_length = (uint)strlen(form_string);

	DBG_PARSER PRINTF_VZ(" starting...\n");
	if (strncmp (buf , form_string, str_length) == 0)
	{/*found the vazaget_srv_string*/
		parsed_msg->html.form = buf + str_length;
		parsed_msg->html_state = HTML_PARSE_FORM;
	}
	return;
}

/**********************************************************/
/*html_parse_C*/
/*ClientSrcIP=2001::11<br />ClientSrcPort=2057<br />ClientDstIP=2002::11<br />ClientDstPort=80<br />*/
/**********************************************************/
void html_parse_C(char *buf, parser_struct *parsed_msg)
{
	char src_ip[]	={"ClientSrcIP="};
	char src_port[]	={"ClientSrcPort="};
	char dst_ip[]	={"ClientDstIP="};
	char dst_port[]	={"ClientDstPort="};

	uint src_ip_len 		= (uint)strlen(src_ip);
	uint src_port_len 	= (uint)strlen(src_port);
	uint dst_ip_len 		= (uint)strlen(dst_ip);
	uint dst_port_len 	= (uint)strlen(dst_port);

	DBG_PARSER PRINTF_VZ(" staring...\n");
	/*ClientSrcIP*/
	if ((!parsed_msg->html.srv_src_ip) &&
			(strncmp (buf , src_ip, src_ip_len) == 0))
	{
		DBG_PARSER PRINTF_VZ(" parsed_msg->html.srv_src_ip Found\n");
		parsed_msg->html.srv_src_ip = buf + src_ip_len;
		return;
	}
	/*ClientSrcPort*/
	if ((!parsed_msg->html.srv_src_port) &&
			(strncmp (buf , src_port, src_port_len) == 0))
	{
		DBG_PARSER PRINTF_VZ(" parsed_msg->html.srv_src_port Found\n");
		parsed_msg->html.srv_src_port = buf + src_port_len;
		return;
	}
	/*ClientDstIP*/
	if ((!parsed_msg->html.srv_dst_ip) &&
			(strncmp (buf , dst_ip, dst_ip_len) == 0))
	{
		DBG_PARSER PRINTF_VZ(" parsed_msg->html.srv_dst_ip Found\n");
		parsed_msg->html.srv_dst_ip = buf + dst_ip_len;
		return;
	}
	/*ClientDstPort*/
	if ((!parsed_msg->html.srv_dst_port) &&
			(strncmp (buf , dst_port, dst_port_len) == 0))
	{
		DBG_PARSER PRINTF_VZ(" parsed_msg->html.srv_dst_port Found\n");
		parsed_msg->html.srv_dst_port = buf + dst_port_len;
		return;
	}
	return;
}

/**********************************************************/
/*html_parse_S*/
/*SSLSessionID=6918351935328A6F05A4F6718E17528CC5EDAE13330B24E2BAD7E78588041741*/
/**********************************************************/
void html_parse_S(char *buf, parser_struct *parsed_msg)
{
	char ssl_sess_id_string[]={"SSLSessionID="};
	char success_string[]={"Success Upload"};
	uint ssl_str_length = (uint)strlen(ssl_sess_id_string);
	uint success_str_length = (uint)strlen(success_string);

	DBG_PARSER PRINTF_VZ(" staring...\n");
	if (strncmp (buf , ssl_sess_id_string, ssl_str_length) == 0)
	{/*found the ssl_sess_id_string*/
		parsed_msg->html.ssl_sess_id = buf;
	}
	if (strncmp (buf , success_string, success_str_length) == 0)
	{/*found the ssl_sess_id_string*/
		parsed_msg->html.success_upload = buf;
	}
	return;
}


/**********************************************************/
/*html_parse_V*/
/**********************************************************/
void html_parse_V(char *buf, parser_struct *parsed_msg)
{
	char vazaget_srv_string[]={"VazaGet server!"};
	uint str_length = (uint)strlen(vazaget_srv_string);

	DBG_PARSER PRINTF_VZ(" starting...\n");
	if (strncmp (buf , vazaget_srv_string, str_length) == 0)
	{/*found the vazaget_srv_string*/
		parsed_msg->html.vazaget_srv = buf;
		DBG_PARSER PRINTF_VZ(" Found %s\n" , vazaget_srv_string);
	}
	return;
}


/**********************************************************/
/*html_parse_H*/
/*HttpProtocol=HTTP\1.1*/
/*HttpCookie=Apache=1.1.1.1.1352383959905050 */
/*HttpVia=1.1 localhost (squid/3.1.19)*/
/**********************************************************/
void html_parse_H(char *buf, parser_struct *parsed_msg)
{
	DBG_PARSER PRINTF_VZ(" staring...\n");

	if (strncmp (buf , "HttpProtocol=" , strlen("HttpProtocol=")) == 0)
	{/*found the HttpProtocol*/
		parsed_msg->html.http_protocol = buf+strlen("HttpProtocol=");
	}
	if (strncmp (buf , "HttpCookie=" , strlen("HttpCookie=")) == 0)
	{/*found the HttpCookie*/
		parsed_msg->html.http_cookie = buf+strlen("HttpCookie=");
	}
	if (strncmp (buf , "HttpVia=" , strlen("HttpVia=")) == 0)
	{/*found the HttpVia*/
		parsed_msg->html.http_via = buf+strlen("HttpVia=");
	}
	return;
}

/**********************************************************/
/*html_parse_X*/
/*X-ForwardedFor=20.1.1.1*/
/**********************************************************/
void html_parse_X(char *buf, parser_struct *parsed_msg)
{
	char x_fwd_for_string[]={"X-ForwardedFor"};
	uint str_length = (uint)strlen(x_fwd_for_string);

	DBG_PARSER PRINTF_VZ(" staring...\n");
	if (strncmp (buf , x_fwd_for_string, str_length) == 0)
	{/*found the x_fwd_for_string*/
		parsed_msg->html.x_forwarded_for = buf+str_length;
	}
	return;
}
/**********************************************************/
/*end_of_html*/
/**********************************************************/
char *end_of_html(char *eol_ptr, parser_struct *parsed_msg)
{
	char end_of_html_string[]={"/html>"};
	uint len = (uint)strlen(end_of_html_string);
	DBG_PARSER PRINTF_VZ(" staring...\n");
	if (strncmp(eol_ptr , end_of_html_string , len) == 0)
	{
		parsed_msg->html.end = eol_ptr + len;
		DBG_PARSER	PRINTF_VZ_N ("found EOHTML!!!\n");
		return NULL;
	}
	return eol_ptr;

}

/**********************************************************/
/*html_parse_tag*/
/**********************************************************/
char *html_parse_tag(char *new_tag, parser_struct *parsed_msg , uint max_chars_to_parse)
{
	uint ch;
	char *next_tag = NULL;
	uint chars_so_far = (uint)(new_tag - parsed_msg->html.start);
	uint chars_to_parse = max_chars_to_parse - chars_so_far;

	DBG_PARSER PRINTF_VZ_N ("start new tag,=%c%c%c%c%c%c... chars_to_parse=%u\n",new_tag[0],new_tag[1],new_tag[2],new_tag[3],new_tag[4],new_tag[5] , chars_to_parse);
	for (ch = 0 ; ch < chars_to_parse ; ch++)
	{
		DBG_PARSER PRINTF_VZ("ch=%d, max_chars_to_parse=%d, chars_so_far=%d, chars_to_parse=%d, new_tag[%d]=%c(0x%x)\n",
				ch ,max_chars_to_parse ,chars_so_far ,chars_to_parse , ch , new_tag[ch], new_tag[ch] );
		/***Examine the first character ONLY*/
		if (ch == 0)
		{
			switch(/*tolower*/(new_tag[ch]))
			{
			case '\0':
				DBG_PARSER PRINTF_VZ("Begin with 0\n");
				next_tag = &new_tag[ch+1];
				return (next_tag);
				/*<  start of tag*/
			case '<':
				parsed_msg->html_state = HTML_PARSE_OPEN_TAG;
				new_tag[ch]='\0';
				next_tag = &new_tag[ch+1];
				return (next_tag);
				/*handle \n like end of TAG, and start new tag parse*/
			case '\n':
				new_tag[ch]='\0';
				next_tag = &new_tag[ch+1];
				return (next_tag);
				/*Parse V --> VazaGet server*/
			case 'V':
				html_parse_V(&new_tag[ch], parsed_msg);
				continue;
				/*Parse C --> Client...*/
			case 'C':
				html_parse_C(&new_tag[ch], parsed_msg);
				continue;
				/*Parse H --> HttpProtocol=...*/
			case 'H':
				html_parse_H(&new_tag[ch], parsed_msg);
				continue;
			case 'X':
				html_parse_X(&new_tag[ch], parsed_msg);
				continue;
			case 'S':
				html_parse_S(&new_tag[ch], parsed_msg);
				continue;
			case 'f':
				html_parse_form(&new_tag[ch], parsed_msg);
				continue;
				/*if we parsing form, then we need to replace spaces in NULL*/
			case ' ':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
				{
					new_tag[ch]='\0';
					next_tag = &new_tag[ch+1];
					return (next_tag);
				}
				continue;
			case 'a':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
					html_parse_form_action(&new_tag[ch], parsed_msg);
				continue;
			case 'm':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
					html_parse_form_method(&new_tag[ch], parsed_msg);
				continue;
			case 'e':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
					html_parse_form_enctype(&new_tag[ch], parsed_msg);
				continue;
			case '/':
				end_of_html(&new_tag[ch], parsed_msg);
				continue;
			}
		}
		/***Examine the rest of the chars*/
		else
		{
			/***Search for the EOT character*/
			switch(/*tolower*/(new_tag[ch]))
			{
			case '\0':
				DBG_PARSER PRINTF_VZ("middle with 0)\n");
				next_tag = &new_tag[ch+1];
				return (next_tag);
				/*<  start of tag*/
			case '<':
				parsed_msg->html_state = HTML_PARSE_OPEN_TAG;
				next_tag = &new_tag[ch];
				return (next_tag);
				/*> close tag*/
			case '>':
				parsed_msg->html_state = HTML_PARSE_CLOSE_TAG;
				new_tag[ch]='\0';
				next_tag = &new_tag[ch+1];
				return (next_tag);
			case '\n':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
				{
					new_tag[ch]='\0';
					next_tag = &new_tag[ch+1];
					return (next_tag);
				}
				continue;
			case ' ':
				if (parsed_msg->html_state==HTML_PARSE_FORM)
				{
					new_tag[ch]='\0';
					next_tag = &new_tag[ch+1];
					return (next_tag);
				}
				continue;
			case '/':
				next_tag = end_of_html(&new_tag[ch], parsed_msg);
				if (next_tag == NULL)
				{
					return (next_tag);
				}
				continue;
			}
		}
	}
	DBG_PARSER PRINTF_VZ("reached to end of FOR, ch(%d)= max_chars_to_parse(%d),returning (%p)\n",ch , max_chars_to_parse ,next_tag);
	return next_tag;
}

/**********************************************************/
/*html_parse*/
/*for every new TAG it will replace the open tag char '<' into --> '\0'*/
/*e.g <html><body><h1>VazaGet server!</h1> */
/*will be -->\0html>\0body>\0h1>VazaGet server!\0/h1>*/
/**********************************************************/
char *html_parse(char *buf, parser_struct *parsed_msg , uint max_chars_to_parse)
{
	int i;
	char *new_tag_to_parse = NULL;
	char *last_parsed_tag = NULL;

	if (buf == NULL)
	{
		DBG_PARSER PRINTF_VZ(" buf=NULL --> returning NULL...\n");
		return NULL;
	}

	if (parsed_msg->html.end)
	{
		DBG_PARSER PRINTF_VZ(" parsed_msg->html.end already exist --> returning NULL...\n");
		return NULL;
	}
	/*after 1st parsing the first < will be replace in 0*/
	if (!(((buf[0] == '<') || (parsed_msg->html.start))&&
			((buf[1] == 'h') || (buf[1] == 'H')) &&
			((buf[2] == 't') || (buf[2] == 'T')) &&
			((buf[3] == 'm') || (buf[3] == 'M'))&&
			((buf[4] == 'l') || (buf[4] == 'L'))&&
			((buf[5] == '>')|| (parsed_msg->html.start))))
	{ /*not HTML header...*/
		DBG_PARSER PRINTF_VZ_N ( "HTML NOT FOUND=%c,%c,%c,%c,%c,%c\n",buf[0],buf[1],buf[2],buf[3],buf[4],buf[5]);
		DBG_PARSER PRINTF_VZ(" not HTML packet --> returning NULL...\n");
		return NULL;
	}

	if (!parsed_msg->html.start)
	{
		parsed_msg->html.start = buf;
		DBG_PARSER	PRINTF_VZ_N("-->Starting HTML parser (max_chars_to_parse=%u):\n%s\n", max_chars_to_parse ,parsed_msg->html.start);
	}
	if (parsed_msg->last_html_parsed_tag)
	{/*if we get the packet in chunks, then we keep on parsing from the last line*/
		new_tag_to_parse = parsed_msg->last_html_parsed_tag;
		DBG_PARSER	PRINTF_VZ_N("-->Continue HTML parser (max_chars_to_parse=%u):\n%s\n",max_chars_to_parse,parsed_msg->html.start);
	}
	else
	{
		new_tag_to_parse = buf;
		parsed_msg->last_html_parsed_tag = new_tag_to_parse;
	}
	for (i = 0 ; i < MAX_HTML_PARSE_TAGS ; i++)
	{
		new_tag_to_parse = html_parse_tag(new_tag_to_parse, parsed_msg , max_chars_to_parse);
		DBG_PARSER	PRINTF_VZ_N("finished HTML parse tag=%d\n",i);
		if (new_tag_to_parse == NULL)
		{/*EOT NOT found*/
			last_parsed_tag = parsed_msg->last_html_parsed_tag;
			DBG_PARSER PRINTF_VZ("No more to parse, keeping last tag and return, i=%d, last_parsed_tag=%p\n",i,last_parsed_tag);
			break;
		}
		else
		{
			/*EOT  found keep the last parsed tag*/
			last_parsed_tag = new_tag_to_parse;
			parsed_msg->last_html_parsed_tag = last_parsed_tag;
			DBG_PARSER PRINTF_VZ("continue to next TAG =%s\n",last_parsed_tag);
		}
		if (parsed_msg->html.end)
		{
			DBG_PARSER PRINTF_VZ("Reached to END of HTML header, last_parsed_tag=%p\n",last_parsed_tag);
			break;
		}
	}
	if (i == (MAX_HTML_PARSE_TAGS -1))
	{
		cntr.warning.html_parser_reached_max_tags++;
	}
	DBG_PARSER	PRINTF_VZ_N("<--HTML parsed DONE total tags=%d\n",i);
	return last_parsed_tag;
}
