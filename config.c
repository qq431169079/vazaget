/* config.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  config.c is part of vazaget.
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
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <errno.h>
#include "global.h"
#include "data_sender.h"
#include "ssl_vazaget.h"
#include "rx_range.h"
#include "prints.h"
#include "config.h"

#define CAT_GEN		1 /*category general*/
#define CAT_SSL		2 /*category SSL*/
#define CAT_COO		3 /*category cookies*/

#define SPACE_2_CHAR	"  "
#define SPACE_4_CHAR	"    "

/*compilation date*/
char *compilation_date = __DATE__;
char *compilation_time = __TIME__;

int num_of_int_params = 0;
int num_of_string_params = 0;
int num_of_flags_params = 0;


void display_version();

typedef struct
{
	char 	ident_string[10];
	int		hidden;
	int 	category;
	param_int_struct 	*received_value;
	int 	min;
	int		max;
	int 	default_value;
	int 	cfg_mode;
	char 	description[STRING_200_B_LENGTH];
}parameters_int;

typedef struct
{
	char 	ident_string[10];
	int		hidden;
	int 	category;
	char 	*received_value;
	char 	*default_value;
	int  	max_length;
	char 	description[STRING_200_B_LENGTH];
}parameters_string;

typedef struct
{
	char 	ident_string[10];
	int		hidden;
	int 	category;
	param_flag_struct 	*received_value;
	char 	default_value;
	void 	*function;
	char 	description[STRING_200_B_LENGTH];
}parameters_flags ;



/********Parameters integers only******/
parameters_int params_int[] =
{
		/*string-hide-CATEGORY-variable-------------------min--max----------------Default-----------------cfg_mode-----Description*/
		{{"-z"},  1 ,CAT_GEN, &cfg.int_v.display_counters, 0, MAX_DEBUG_COUNTERS,DEFAULT_DEBUG_COUNTER ,DEFAULT_CFG,   {"set display counters severity (summarize): 0x1=ERROR, 0x2=WARNING, 0x4=INFO"}},
		{{"-ps"}, 0 ,CAT_GEN, &cfg.int_v.src_port 	 	, 1 , MAX_PORT_VALUE,	DEFAULT_SRC_PORT ,DEFAULT_CFG, 		   {"set source port"}},
		{{"-n"},  0 ,CAT_GEN,&cfg.int_v.num_of_session , 1 , MAX_NUM_OF_SESSIONS,DEFAULT_NUM_OF_SESSIONS,DEFAULT_CFG, {"number of sessions"}},
		{{"-tx"}, 1 ,CAT_GEN, &cfg.int_v.tx_num_of_threads,1, 50     , 			DEFAULT_TX_NUM_OF_THREADS ,DEFAULT_CFG, 	{"number of simultanious TX threads"}},
		{{"-rx"}, 1 ,CAT_GEN, &cfg.int_v.rx_num_of_threads,1, MAX_RX_THREADS,	DEFAULT_RX_NUM_OF_THREADS,DEFAULT_CFG,	{"number of RX threads"}},
		{{"-ts"}, 1 ,CAT_GEN, &cfg.int_v.tx_th_active_sessions,1,5   , 			DEFAULT_TH_ACTIVE_SESS ,DEFAULT_CFG, 	{"number of simultanious sessions per TX thread"}},
		{{"-br"} ,0 ,CAT_GEN, &cfg.int_v.bw_rx_limit    , 1 , 1000000, 			DEFAULT_BW_RX_LIMIT	  ,DEFAULT_CFG,		{"(Bytes Per Second) BW RX limit"}},
		{{"-bt"} ,0 ,CAT_GEN, &cfg.int_v.bw_TX_limit    , 1 , 1000000, 			DEFAULT_BW_TX_LIMIT	  ,DEFAULT_CFG,		{"(Bytes Per Second) BW TX limit"}},
		{{"-up"} ,0 ,CAT_GEN, &cfg.int_v.post_upload    , 1 , 1300   , 			DEFAULT_POST_UPLOAD	  ,DEFAULT_CFG,		{"(Bytes) Post upload file (reuquires vazaget php (./vazaget -php) on the server)"}},
		{{"-wn"}, 0 ,CAT_GEN, &cfg.int_v.delay_tx_sec   , 1 , 1000000, 			DEFAULT_TX_DELAY 	  ,DEFAULT_CFG, 	{"(sec)delay creation of new socket"}},
		{{"-wg"}, 0 ,CAT_GEN, &cfg.int_v.delay_get_sec  , 1 , 1000000,	 		DEFAULT_GET_DELAY 	  ,DEFAULT_CFG, 	{"(sec)delay sending the GET request"}},
		{{"-wc"}, 0 ,CAT_GEN, &cfg.int_v.delay_close_sec, 1 , 1000000, 			DEFAULT_CLOSE_DELAY   ,DEFAULT_CFG, 	{"(sec)delay close socket"}},
		{{"-rs"}, 1 ,CAT_GEN, &cfg.int_v.range_size     , 1 , 10000000,			RANGE_DEFAULT_SIZE 	  ,DEFAULT_CFG, 	{"(Bytes)range : single range block size"}},
		{{"-sv"}, 0 ,CAT_SSL, &cfg.int_v.ssl_verify_cert, 0 , 2,				SSL_DEFAULT_VERIFY_CERT,DEFAULT_CFG, 	{"SSL:verify certificate common name, 0=none, 1=optional, 2=required"}},
		{{"-sminv"},0,CAT_SSL,&cfg.int_v.ssl_min_ver	,SSL_DEFAULT_MIN_VER,SSL_DEFAULT_MAX_VER,SSL_DEFAULT_MIN_VER,DEFAULT_CFG,{"SSL:set minimum version, 0=ssl3, 1=tls1, 2=tls1_1, 3=tls1_2"}},
		{{"-smaxv"},0,CAT_SSL,&cfg.int_v.ssl_max_ver	,SSL_DEFAULT_MIN_VER,SSL_DEFAULT_MAX_VER,SSL_DEFAULT_MAX_VER,DEFAULT_CFG,{"SSL:set maximum version, 0=ssl3, 1=tls1, 2=tls1_1, 3=tls1_2"}},
		{{"-sd"}, 0 ,CAT_SSL, &cfg.int_v.ssl_debug_flag , 0 , 4,				SSL_DEFAULT_DBG_FLAG  ,DEFAULT_CFG, 	{"SSL:mbedtls debug flag"}}

};
/********Parameters string only******/
parameters_string params_string[] =
{
		/*string-hide-CATEGORY-variable---------------------default-----max------------------------Description*/
		{{"-o"},  0 ,CAT_GEN, cfg.str_v.note_string 	   , NULL , sizeof(cfg.str_v.note_string)      , {"add note, it will be added to the log file"}},
		{{"-cc"}, 0 ,CAT_COO, cfg.str_v.cookie_string_cli  , NULL , sizeof(cfg.str_v.cookie_string_cli), {"add your own cookie string to the HTTP GET request"}},
		{{"-pr"}, 0 ,CAT_GEN, cfg.str_v.proxy_addr         , NULL , sizeof(cfg.str_v.proxy_addr) 	   , {"send request to proxy"}},
		{{"-ds"}, 0 ,CAT_GEN, cfg.str_v.data_sender        , NULL , sizeof(cfg.str_v.data_sender) 	   , {"(file name) send your own data from file"}},
		{{"-ua"}, 0 ,CAT_GEN, cfg.str_v.ua        		   , NULL , sizeof(cfg.str_v.ua) 	   		   , {"change the default UA (user agent)"}},
		{{"-scf"},0 ,CAT_SSL, cfg.str_v.ssl_ciphers		   , NULL , sizeof(cfg.str_v.ssl_ciphers) 	   , {"SSL:force ciphers list: max 4 ciphers, separate by comma(,).\n\t\t\t\tget full cipher list using \"-sc\". e.g -scf 0xc02c,0xc030... "}},
		{{"-scaf"},0,CAT_SSL, cfg.str_v.ca_file		       , NULL , sizeof(cfg.str_v.ca_file) 	       , {"SSL:The single file containing the top-level CA(s) you fully trust"}},
		{{"-scap"},0,CAT_SSL, cfg.str_v.ca_path		       , NULL , sizeof(cfg.str_v.ca_path) 	       , {"SSL:The path containing the top-level CA(s) you fully trust"}}
};

/********Parameters flags only******/
parameters_flags params_flags[] =
{
		/*string-hide-CATEGORY-variable--------------------default-*function------Description*/
		{{"-gz"}, 0 ,CAT_GEN, &cfg.flag.encoding_gzip		, 0 , NULL				, {"Add encoding-gzip to the GET"}},
		{{"-cr"}, 0 ,CAT_COO, &cfg.flag.cookie_from_reply	, 1 , NULL				, {"Cookie reuse from the last HTTP GET request"}},
		{{"-cr2"},0 ,CAT_COO, &cfg.flag.cookie_reply_2		, 0 , NULL				, {"send every 2nd GET with last cookie, and verify it arrived to destinated dst IP"}},
		{{"-cw"}, 0 ,CAT_COO, &cfg.flag.cookie_wait			, 0 , NULL				, {"Wait and hold all connections until receive cookie"}},
		{{"-fr"}, 0 ,CAT_GEN, &cfg.flag.close_by_rst		, 0 , NULL				, {"Close connection by RST, will activate automatic for over then 10K sessions."}},
		{{"-fs"}, 0 ,CAT_GEN, &cfg.flag.close_by_server		, 0 , NULL				, {"Close connection by server, if overload, sockets last long time and may cause problems"}},
		{{"-sr"}, 0 ,CAT_GEN, &cfg.flag.socket_resue		, 0 , NULL				, {"Socket Reuse, each thread uses 1 socket, and resend GET's on it, auto change to 1 thread"}},
		{{"-ch"}, 1 ,CAT_GEN, &cfg.flag.chunks_dis			, 0 , NULL				, {"Disable HTTP chunks stripping"}},
		{{"-k"} , 1 ,CAT_GEN, &cfg.flag.save_to_file		, 1 , NULL				, {"Keep/Save the receive data to file, for n>1 will be turned off"}},
		{{"-r"} , 0 ,CAT_GEN, &cfg.flag.range				, 0 , NULL				, {"Support http header of Range, will download big files in few sim connections"}},
		{{"-rm"}, 1 ,CAT_GEN, &cfg.flag.range_on_mem		, 0 , NULL				, {"save tmp ranges on RAM memory instead of using /tmp"}},
		{{"-ct"}, 1 ,CAT_GEN, &cfg.flag.close_thread_dis	, 0 , NULL				, {"Disable Closing sockets via seperate closing thread"}},
		{{"-sc"}, 0 ,CAT_SSL, &cfg.flag.ssl_cipher_list     , 0 , &ssl_print_cipher_list, {"SSL:print the supported ciphers"}},
		{{"-v"} , 0 ,CAT_GEN, &cfg.flag.version				, 0 , &display_version	, {"display version number"}},
		{{"-h"} , 0 ,CAT_GEN, &cfg.flag.help_menu       	, 0 , &usage			, {"help menu"}},
		{{"-hds"},0 ,CAT_GEN, &cfg.flag.help_ds       		, 0 , &usage_data_sender, {"help - data sender"}},
		{{"-e"}	, 1 ,CAT_GEN, &cfg.flag.http_parse_test		, 0 , NULL				, {"(h)HTTP parser test"}},
		{{"-php"},1 ,CAT_GEN, &cfg.flag.php_file		    , 0 , &display_php_file	, {"(h)Display index.php file to be implement on the Apache"}},
		{{"-hh"}, 1 ,CAT_GEN, &cfg.flag.help_menu       	, 0 , &usage_hidden		, {"(h)help with hidden menu"}}
};

/********States******/
state_description state_desc[]=
{
		{STATE_READY 	, 	"STATE_READY"},
		{STATE_SENT_GET , 	"STATE_SENT_GET"},
		{STATE_SENT_POST, 	"STATE_SENT_POST"},
		{STATE_CLOSE 	, 	"STATE_CLOSE"},
		{STATE_MAX 		, 	"STATE_MAX"},
};

/**********************************************************/
/*display_debug_params*/
/**********************************************************/
void display_debug_params()
{
	PRINTF_VZ_N ("Debug menu: -d <debug_flag> (you can assign multiple debug joining few flags\n");
	PRINTF_VZ_N ("\t%03x = debug parser HTTP + HTML\n"	,DEBUG_FLAG_PARSER);
	PRINTF_VZ_N ("\t%03x = debug configuration\n"		,DEBUG_FLAG_CONFIG);
	PRINTF_VZ_N ("\t%03x = debug TX\n"					,DEBUG_FLAG_TX);
	PRINTF_VZ_N ("\t%03x = debug RX\n"					,DEBUG_FLAG_RX);
	PRINTF_VZ_N ("\t%03x = debug DS\n"					,DEBUG_FLAG_DS);
	PRINTF_VZ_N ("\t%03x = debug LISTENER\n"			,DEBUG_FLAG_LISTENER);
	PRINTF_VZ_N ("\t%03x = debug RANGE\n"				,DEBUG_FLAG_RANGE);
	PRINTF_VZ_N ("\t%03x = debug CLOSE\n"				,DEBUG_FLAG_CLOSE);
	PRINTF_VZ_N ("\t%03x = debug SSL\n"					,DEBUG_FLAG_SSL);
	PRINTF_VZ_N ("\t%03x = debug BUF\n"					,DEBUG_FLAG_BUF);
	PRINTF_VZ_N ("use -ed to set mbedtls debug flag\n");
}


#include "include_mbedtls/version.h"
/**********************************************************/
/*display_version()*/
/**********************************************************/
void display_version()
{
	PRINTF_VZ_N ("vazaGet version = %s%s\n",VAZAGET_VERSION, BUILD_PLATFORM);
	char mbedtls_ssl_version_string[STRING_50_B_LENGTH];
	mbedtls_version_get_string_full(mbedtls_ssl_version_string);
	PRINTF_VZ_N ("mbedtls version = %s\n",mbedtls_ssl_version_string);
	PRINTF_VZ_N("Compilation date = %s , %s\n", compilation_date , compilation_time);

	exit_vz(EXIT_SUCCESS, NULL);
}

/**********************************************************/
/*display_flags_params()*/
/**********************************************************/
void display_flags_params(int show_hidden, int category)
{
	int i = 0;

	for (i=0 ; i < num_of_flags_params ; i++)
	{
		if ((category == params_flags[i].category) &&
				((show_hidden) || (!params_flags[i].hidden)))
		{
			PRINTF_VZ_N("\t%s\t\t--> %s (default=%d)\n",
					params_flags[i].ident_string,
					params_flags[i].description,
					params_flags[i].default_value);
		}
	}
}
/**********************************************************/
/*display_string_params*/
/**********************************************************/
void display_string_params(int show_hidden, int category)
{
	int i = 0;

	for (i=0 ; i < num_of_string_params ; i++)
	{
		if ((category == params_string[i].category) &&
				((show_hidden) || (!params_string[i].hidden)))
		{
			PRINTF_VZ_N("\t%s <string>	--> %s (max_length=%d)\n",
					params_string[i].ident_string,
					params_string[i].description,
					params_string[i].max_length);
		}
	}
}
/**********************************************************/
/*display_int_params*/
/**********************************************************/
void display_int_params(int show_hidden, int category)
{
	int i = 0;

	for (i=0 ; i < num_of_int_params ; i++)
	{
		if ((category == params_int[i].category) &&
				((show_hidden) || (!params_int[i].hidden)))
		{
			PRINTF_VZ_N("\t%s <%d-%d>%s--> %s (default=%d)\n",
					params_int[i].ident_string,
					params_int[i].min,
					params_int[i].max,
					(params_int[i].max < 10000000) ? "\t" : "" , /*allign the line in the print*/
							params_int[i].description,
							params_int[i].default_value);
		}
	}
}


/**********************************************************/
/*display_examples*/
/**********************************************************/
void display_examples()
{
	PRINTF_VZ_N("\nExamples (recommend load on your web server vazaget index.php (./vazaget -php)):\n");
	PRINTF_VZ_N("\t./vazaget 192.168.1.1 -n 1000 --> 1000 IPv4 GET's\n");
	PRINTF_VZ_N("\t./vazaget [2010::1]:8080  --> IPv6 GET over port 8080\n");
	PRINTF_VZ_N("\t./vazaget http://your_site.com/your_path/your_file  --> GET to webaddress with path and file name\n");
	PRINTF_VZ_N("\t./vazaget https://your_secured_site.com --> GET over SSL\n");
	PRINTF_VZ_N("\t./vazaget http://your_site.com -pr http://www.your_proxy.com:3128 --> GET through proxy on port 3128\n");
	PRINTF_VZ_N("\t./vazaget [2010::1] -up 1000 -bt 500 -br 400 --> POST of 1000 Bytes (require the vazaget php file \"vazaget -php\") \n\t\t\twith BW TX limit to 500 Bps, and BW RX limit to 400 Bps\n\n");
}

void usage_display(int show_hidden)
{
	PRINTF_VZ_N("usage %s: vazaget <ip(v4|v6)+path> [options] \n",show_hidden ? "(+hidden)" : "");
	display_int_params(show_hidden , CAT_GEN);
	display_string_params(show_hidden , CAT_GEN);
	display_flags_params(show_hidden , CAT_GEN);

	PRINTF_VZ_N( SPACE_4_CHAR "SSL:\n");
	display_int_params(show_hidden , CAT_SSL);
	display_string_params(show_hidden , CAT_SSL);
	display_flags_params(show_hidden , CAT_SSL);

	PRINTF_VZ_N( SPACE_4_CHAR "Cookies:\n");
	display_int_params(show_hidden , CAT_COO);
	display_string_params(show_hidden , CAT_COO);
	display_flags_params(show_hidden , CAT_COO);

	if (show_hidden)
	{
		display_debug_params();
	}

	display_examples();
	exit_vz(EXIT_FAILURE , NULL);
}
/**********************************************************/
/*usage_hidden*/
/**********************************************************/
void usage_hidden()
{
	usage_display(1);
	exit_vz(EXIT_FAILURE , NULL);
}

/**********************************************************/
/*usage*/
/**********************************************************/
void usage()
{
	usage_display(0);
	exit_vz(EXIT_FAILURE , NULL);
}

/**********************************************************/
/*usage_data_sender*/
/**********************************************************/
void usage_data_sender()
{
	char get_1[]={"{GET / HTTP/1.1\r\nUser-Agent: VazaGet\r\nAccept: */*\r\nHost: 127.0.0.1\r\nX-vazaget: ID=1\r\nConnection: Keep-Alive\r\n\r\n}\r\n"};
	char get_2[]={"{GET / HTTP/1.1\r\nUser-Agent: VazaGet\r\nAccept: */*\r\nHost: 127.0.0.1\r\nX-vazaget: ID=2\r\nConnection: Keep-Alive\r\n\r\n}\r\n"};
	PRINTF_VZ_N("usage: Data Sender :\n");
	display_commands_usage();
	PRINTF_VZ_N("file example:\n");
	PRINTF_VZ_N("==============================\n");
	PRINTF_VZ_N(BOLDGREEN "TX\r\n" RESET);
	PRINTF_VZ_N("%s",get_1);
	PRINTF_VZ_N("\r\n");
	PRINTF_VZ_N(BOLDGREEN "RX " RESET "{200 OK}\r\n");
	PRINTF_VZ_N("\r\n");
	PRINTF_VZ_N(BOLDGREEN "WAIT " RESET "{3}\r\n");
	PRINTF_VZ_N("\r\n");
	PRINTF_VZ_N(BOLDGREEN "TX\r\n" RESET);
	PRINTF_VZ_N("%s",get_2);
	PRINTF_VZ_N("\r\n");
	PRINTF_VZ_N(BOLDGREEN "RX " RESET "{200 OK}\r\n");
	PRINTF_VZ_N("==============================\n");
	exit_vz(EXIT_FAILURE , NULL);
}

/**********************************************************/
/*atoh*/
/**********************************************************/
unsigned char atoh(char *byte)
{
	uint  output_hex = 0;
	sscanf(byte, "%2x", &output_hex);
	return (unsigned char) output_hex;
}


/**********************************************************/
/*strnstr()*/
/*search string inside string*/
/**********************************************************/
char *strnstr(char *buf, char *find , uint max_len)
{
	uint ch;
	uint find_len, chars_to_check;

	if ((buf == NULL) || (find == NULL) || (max_len == 0))
	{
		return NULL;
	}

	find_len = (uint)strlen(find);
	chars_to_check = max_len - find_len;

	if (chars_to_check < 1)
	{
		return NULL;
	}

	for (ch=0 ; ch < chars_to_check ; ch++)
	{
		if (buf[ch] == '\0')
		{
			return NULL;
		}
		else if(buf[ch] == find[0])
		{
			if (strncmp(&buf[ch] , find , find_len) == 0)
			{
				return &buf[ch];
			}
		}
	}
	return NULL;
}
/**********************************************************/
/*recieve_int_value*/
/**********************************************************/
int recieve_flag_value(char *input_string)
{
	int i;
	for (i=0 ; i<num_of_flags_params; i++)
	{
		if (strncmp(input_string , params_flags[i].ident_string , 10) == 0)
		{
			param_flag_struct *flag_val = params_flags[i].received_value;
			flag_val->val =! flag_val->val; /*set the oposite value*/
			flag_val->config_mode = USER_CFG;

			DBG_CONF PRINTF_VZ_N("received flag option for %s\n",params_flags[i].ident_string);
			if (params_flags[i].function)
			{
				void (*run_func)();
				run_func = params_flags[i].function;
				run_func();
			}
			return 1;
		}
	}
	return 0;
}

/**********************************************************/
/*recieve_string_value*/
/**********************************************************/
int recieve_string_value(char *ident_string, char *input_str)
{
	int i;
	for (i=0 ; i<num_of_string_params ; i++)
	{
		if (strncmp(ident_string , params_string[i].ident_string , 10) == 0)
		{
			if (input_str == NULL)
			{
				PRINTF_VZ_N("\n%s <string> cannot be empty\n\n",ident_string);
				usage();
			}
			uint len = (uint)strlen(input_str);
			if (len >= (uint)params_string[i].max_length)
			{
				PRINTF_VZ_N("\nIllegal string length = %d > max string len(%d)\n\n",len , params_string[i].max_length);
				usage();
			}
			if (len < 1)
			{
				PRINTF_VZ_N("\nIllegal string length = %d < 1\n\n",len);
				usage();
			}
			strncpy (params_string[i].received_value , input_str , (uint)params_string[i].max_length);
			DBG_CONF PRINTF_VZ_N("recived option %s with string value=%s\n",params_string[i].ident_string , input_str);
			return 1;
		}
	}
	return 0;
}
/**********************************************************/
/*recieve_int_value*/
/**********************************************************/
int recieve_int_value(char *input_string, char *value_str)
{
	int i;

	char *ptr_end = NULL;
	errno = 0;
	int value  = (int)strtol(value_str , &ptr_end , 10);
	if (errno != 0)
	{
		PRINTF_VZ_N("\n%s cannot receive value of: %s (%s)\n\n",input_string , value_str, strerror(errno));
		usage();
	}

	if (ptr_end == value_str)
	{
		PRINTF_VZ_N("\nNo digits found (%s %s)\n\n",input_string , value_str);
		usage();
	}


	for (i=0 ; i<num_of_int_params ; i++)
	{
		if (strncmp(input_string , params_int[i].ident_string , 10) == 0)
		{
			if (value < params_int[i].min)
			{
				PRINTF_VZ_N("\n%s Illegal value = %d < min(%d)\n\n",input_string , value, params_int[i].min);
				usage();
			}
			if (value > params_int[i].max)
			{
				PRINTF_VZ_N("\n%s Illegal value = %d > max(%d)\n\n",input_string , value, params_int[i].max);
				usage();
			}

			param_int_struct *int_val = params_int[i].received_value;
			int_val->val = value;
			int_val->config_mode = USER_CFG;

			DBG_CONF PRINTF_VZ_N("recived option %s with int value=%d\n",params_int[i].ident_string , value);
			return 1;
		}
	}
	return 0;
}


/**********************************************************/
/*recieve_debug_value*/
/**********************************************************/
int recieve_debug_value(char *input_string, char *value_str)
{

	cfg.dbg_v.dbg = 0;
	char *ptr_end = NULL;

	if (strncmp(input_string ,"-d" , 10) != 0)
	{
		return 0;
	}

	cfg.dbg_v.dbg  = (int)strtol(value_str , &ptr_end , 16);
	if (cfg.dbg_v.dbg <= 0)
	{
		PRINTF_VZ_N ( "\n-d string conversion(strtol) **FAIL** (%s)\n\n",strerror(errno));
		display_debug_params();
		exit_vz(EXIT_SUCCESS , NULL);
	}
	return 1;
}


/**********************************************************/
/*validate_data_sender_file*/
/*********************************************************/
void validate_data_sender_file (char *ds_file_name)
{
	struct stat st;
	int file_not_valid = 0 , read_bytes=0 , i;
	uint event , name_length = 0;
	ds_disp = 1;/*set the DS prints ON*/
	void* fp = NULL;
	fd_ds_db_t ds_valid;

	memset (&ds_valid , 0 , sizeof(fd_ds_db_t));
	memset (&ds_file , 0 , sizeof(ds_file_t));

	if (ds_file.file_name == NULL)
	{
		name_length = (uint)strnlen(ds_file_name , MAX_FILE_NAME_LENGTH);
		if ((name_length == 0) || (name_length == MAX_FILE_NAME_LENGTH))
		{
			PRINTF_VZ_N ( "Failed name_len\n");
			PANIC_NO_DUMP(1);
		}

		ds_file.file_name = malloc(name_length + 1);
		if (ds_file.file_name == NULL)
		{
			PRINTF_VZ_N ( "Failed file_name malloc\n");
			PANIC_NO_DUMP(1);
		}
	}

	snprintf(ds_file.file_name , name_length + 1 , "%s" , ds_file_name);

	fp = fopen(ds_file.file_name , "r");
	if (fp == NULL)
	{/*open the file*/
		PRINTF_VZ("**FAIL** to open %s file\n",ds_file.file_name);
		PRINTF_VZ("fopen error - %s\n", strerror(errno));
		usage_data_sender();
		exit_vz(EXIT_FAILURE , NULL);
	}

	init_ds_file_payload();

	if ((!file_not_valid) && (stat(ds_file.file_name, &st) != 0))
	{/*read file details*/
		PRINTF_VZ("stat error - %s\n", strerror(errno));
		file_not_valid = 1;
	}

	ds_file.file_size = (uint)st.st_size;

	if ((!file_not_valid) && ((ds_file.file_size <= 0) || (ds_file.file_size > DS_MAX_PAYLOAD)))
	{/*validate file size*/
		PRINTF_VZ("Datasender file(%s) size=%u > allowed file size=%d\n", ds_file.file_name, ds_file.file_size , DS_MAX_PAYLOAD);
		file_not_valid = 1;
	}

	if ((!file_not_valid) && (read_bytes = fread(ds_file.content , 1 , ds_file.file_size , fp) != ds_file.file_size))
	{
		PRINTF_VZ("**FAIL** to copy from file (%s), read_bytes=%d, st.st_size=%u\n", ds_file.file_name , read_bytes , ds_file.file_size);
		file_not_valid = 1;
	}

	if (file_not_valid)
	{
		usage_data_sender();
		fclose(fp);
		exit_vz(EXIT_FAILURE, NULL);
	}

	fclose(fp);/*don't need any more the file pointer*/
	init_ds_cmd_combinations();
	ds_valid.cur_cmd = DS_CMD_MAX;
	DBG_DS PRINTF_VZ("start validating: %s, length=%d\n", ds_file.file_name ,ds_file.file_size);
	for (i=0 ; i < DS_MAX_COMMANDS ; i++)
	{
		event = ds_parser(&ds_valid);
		if (event == DS_EVENT_CMD_FOUND)
		{
			ds_file.num_of_cmds++;
			if (ds_valid.new_cmd == DS_CMD_TX)
			{
				ds_file.tx_cmds++;
				DBG_DS PRINTF_VZ("TX CMD's so far=%d, line=%d\n",ds_file.tx_cmds , ds_valid.cur_line);
			}
			else if (ds_valid.new_cmd == DS_CMD_RX)
			{
				ds_file.rx_cmds++;
				if (ds_file.num_of_cmds == 1)
				{/*if we have RX as the first cmd, then we need to work in RX mode*/
					ds_file.rcv_mode = 1;
				}
				DBG_DS PRINTF_VZ("RX CMD's so far=%d, line=%d, rcv_mode=%d\n",ds_file.rx_cmds , ds_valid.cur_line, ds_file.rcv_mode);
			}
			else if (ds_valid.new_cmd == DS_CMD_WAIT)
			{
				ds_file.wait_cmds++;
				DBG_DS PRINTF_VZ("WAIT CMD's so far=%d, line=%d\n",ds_file.wait_cmds , ds_valid.cur_line);
			}
			continue;
		}
		else
		{
			break;
		}
	}
	if (i == DS_MAX_COMMANDS)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):ds_parser reached to DS_MAX_COMMANDS(%d)\n",FUNC_LINE,DS_MAX_COMMANDS);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	ds_file.num_of_lines = ds_valid.cur_line;
	DS_PRINT PRINTF_VZ_N("[Successfully validated: %s (lines=%d, length=%d, Commands: TX=%d, RX=%d, WAIT=%d)]\n",ds_file_name , ds_file.num_of_lines , ds_file.file_size, ds_file.tx_cmds , ds_file.tx_cmds, ds_file.wait_cmds);
	return;
}


/**********************************************************/
/*validate_config_ssl*/
/*********************************************************/
void validate_config_ssl()
{
#if 0
	if ((cfg.flag.ssl.val) && (cfg.int_v.tx_th_active_sessions.val > 1))
	{
		DBG_CONF PRINTF_VZ(" ssl can work only with cfg.int_v.tx_th_active_sessions.val=1, setting it to 1\n");
		cfg.int_v.tx_th_active_sessions.val = 1;
	}
#endif

}


/**********************************************************/
/*validae_url*/
/*********************************************************/
void validae_url(char *uri_rcv_string , uri_parser *uri_parse , int resolve_dns)
{
	int result;

	if (parse_destination_url(uri_rcv_string , uri_parse) != TRUE_1)
	{
		PRINTF_VZ_N ( "**FAIL** to parse destination URL-->%s\n",uri_rcv_string);
		usage();
	}

	DBG_CONF PRINTF_VZ(" Start validating URL=%s, (resolve_dns=%d)\n",uri_rcv_string , resolve_dns);

	/*validate http protocol*/
	if (IS_STRING_SET(uri_parse->protocol_ptr)  /*uri_parse->protocol_ptr!=NULL && cfg.dest_params.protocol_ptr[0]*/)
	{
		if (validate_http_protocol(uri_parse , 1) != TRUE_1)
		{
			PRINTF_VZ_N ( "**FAIL** to validate protocol-->%s/\n",uri_parse->protocol_ptr);
			usage();
		}
	}

	/*validate and convert IP address*/
	result = validate_and_convert_ip_address_from_string(uri_parse);
	if (result <= 0)
	{
		DBG_CONF PRINTF_VZ(" **FAIL** validate_and_convert_ip_address_from_string, still it can be www destination, will check DNS...(%s)\n",uri_parse->orig_full_uri);
		uri_parse->ip_addr_ptr=NULL;
	}
	else
	{
		uri_parse->www_addr_ptr=NULL;
	}

	/*validate and convert port*/
	if (validate_and_convert_port_from_string(uri_parse) != TRUE_1)
	{
		PRINTF_VZ_N ( "**FAIL** to validate port-->%s\n",uri_parse->port_ptr);
		usage();
	}

	/*DNS resolution*/
	if (resolve_dns && (!IS_STRING_SET(uri_parse->ip_addr_isolate_string)))
	{
		if (!IS_STRING_SET(uri_parse->www_addr_ptr))
		{
			DBG_CONF PRINTF_VZ(" Cannot resolve DNS, couldn't isolate www address...(%s)\n",uri_parse->orig_full_uri);
			usage();
		}

		if (resolve_dns_web_address(uri_parse) != TRUE_1)
		{
			PRINTF_VZ_N ( "\nunresolved host : %s\n\n",uri_parse->www_addr_ptr);
			usage();
		}
	}
}


/**********************************************************/
/*validate_config_values*/
/*********************************************************/
void validate_config_values_range()
{
	if (!(IS_STRING_SET(cfg.dest_params.file_name_ptr)) && !(IS_STRING_SET(cfg.dest_proxy_params.file_name_ptr)))
	{
		DBG_CONF PRINTF_VZ("cannot work with range, if file name is not specified\n");
		cfg.flag.range.val = 0;
		cfg.flag.range.config_mode = OVERWRITE_CFG;
		return;
	}

	if (cfg.int_v.rx_num_of_threads.config_mode == DEFAULT_CFG)
	{
		DBG_CONF PRINTF_VZ("range seems to be work better with 1 RX thread \n");
		cfg.int_v.rx_num_of_threads.val = 1;
		cfg.int_v.rx_num_of_threads.config_mode = OVERWRITE_CFG;
	}

	if (cfg.int_v.tx_num_of_threads.val >  15)
	{
		DBG_CONF PRINTF_VZ("range - for more then 10 tx threads, will use 3 active sessions per thread \n");
		cfg.int_v.tx_th_active_sessions.val = 3;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}
	if (cfg.int_v.tx_num_of_threads.val >  10)
	{
		DBG_CONF PRINTF_VZ("range - for more then 2 tx threads, will use 2 active sessions per thread \n");
		cfg.int_v.tx_th_active_sessions.val = 2;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}
	else
	{
		DBG_CONF PRINTF_VZ("range - for more less 5 tx threads, will use 1 active session per thread \n");
		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}

	if (!cfg.flag.save_to_file.val)
	{
		DBG_CONF PRINTF_VZ("range cannot work with save to file = 0, set it to 1\n");
		cfg.flag.save_to_file.val = 1;
		cfg.flag.save_to_file.config_mode = OVERWRITE_CFG;
	}

	if (cfg.int_v.num_of_session.config_mode == DEFAULT_CFG)
	{
		DBG_CONF PRINTF_VZ("for range set default sessions to maximum\n");
		cfg.int_v.num_of_session.val = MAX_NUM_OF_SESSIONS;
		cfg.int_v.num_of_session.config_mode = OVERWRITE_CFG;
	}

	if (cfg.flag.socket_resue.config_mode == DEFAULT_CFG)
	{
		DBG_CONF PRINTF_VZ("for range set socket reuse\n");
		cfg.flag.socket_resue.val = 1;
		cfg.flag.socket_resue.config_mode = OVERWRITE_CFG;
	}
}

void validate_ssl_force_ciphers_list(char *force_ciphers_list)
{
	char *next_cipher_ptr = NULL;
	char *cur_cipher_ptr = force_ciphers_list;
	uint cipher_num = 0, ciphers_cntr=0;

	DBG_CONF PRINTF_VZ("start : force_ciphers_list=%s\n",force_ciphers_list);
	while (1)
	{
		cipher_num = (uint)strtoul (cur_cipher_ptr, &next_cipher_ptr, 16);
		if (!cipher_num)
		{/*invalid strtoul*/
			break;
		}
		if (!mbedtls_ssl_ciphersuite_from_id((int)cipher_num))
		{
			PRINTF_VZ_N("unknown cipher number = 0x%x\n", cipher_num);
			usage();
		}
		else
		{
			DBG_CONF PRINTF_VZ("validate cipher[%d]=0x%x\n",ciphers_cntr , cipher_num);
			ciphers_cntr++;
		}

		if ((!next_cipher_ptr) || (next_cipher_ptr[0] != ','))
		{/*no more ciphers*/
			break;
		}
		cur_cipher_ptr = next_cipher_ptr + 1;
		next_cipher_ptr = NULL;

	}
	if (ciphers_cntr > SSL_MAX_FORCE_CIPHERS)
	{
		PRINTF_VZ_N("Cannot use more then %d ciphers (detected %d)\n", SSL_MAX_FORCE_CIPHERS , ciphers_cntr);
		usage();
	}
	DBG_CONF PRINTF_VZ("Success validating %d ciphers\n",ciphers_cntr);
}

/**********************************************************/
/*validate_config_values*/
/*********************************************************/
void validate_config_values()
{
	/*******COOKIES*********/
	/*cookies - cookie_from_reply*/
	if ((cfg.flag.cookie_from_reply.val) && (cfg.str_v.cookie_string_cli[0]))
	{
		PRINTF_VZ_N ( "!!!cannot use -cr with -cc\n");
		usage();
	}
	/*cookies - cookie_reply_2*/
	if ((cfg.flag.cookie_reply_2.val) && (cfg.flag.cookie_from_reply.val))
	{
		PRINTF_VZ_N ( "!!!cannot use -cr2 with -cr, disabling -cr\n");
		cfg.flag.cookie_from_reply.val = 0;
		cfg.flag.cookie_from_reply.config_mode = OVERWRITE_CFG;
	}
	/*cookies - cookie_reply_2*/
	if ((cfg.flag.cookie_reply_2.val) && (cfg.flag.cookie_wait.val))
	{
		PRINTF_VZ_N ( "!!!cannot use -cr2 with -cw, disabling -cw\n");
		cfg.flag.cookie_wait.val = 0;
		cfg.flag.cookie_wait.config_mode = OVERWRITE_CFG;
	}

	/*******CLOSE MODE (RST \ FIN)*********/
	/*connection close method*/
	if ((cfg.flag.close_by_rst.val) && (cfg.flag.close_by_server.val))
	{
		PRINTF_VZ_N ( "!!!cannot use -fr with -fs\n");
		usage();
	}

	/*when running stress of over ~10K of sockets, sockets are get stuck for 2 minutes in TIME_WAIT state, closing in reset will terminate the socket without holding the socket in TIME_WAIT*/
	if ((cfg.int_v.num_of_session.val > 10000) && (!cfg.flag.close_by_rst.val) && (!cfg.flag.close_by_server.val))
	{
		cfg.flag.close_by_rst.val = 1;
		cfg.flag.close_by_rst.config_mode = OVERWRITE_CFG;
	}

	/*will not save file if num of sessions are more then 1*/
	if ((cfg.int_v.num_of_session.val > 1) && (cfg.flag.save_to_file.val))
	{
		cfg.flag.save_to_file.val = 0;
		cfg.flag.save_to_file.config_mode = OVERWRITE_CFG;
	}

	/*******SOCKET REUSE*********/
	/*in case of socket reuse, most tests requires only 1 thread, otherwise the reuse is spreaded between all threades which is confusing.*/
#if 0
	if ((cfg.flag.socket_resue.val) && (cfg.int_v.tx_num_of_threads.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
	}
#endif
	/*for socket_resue, change the default active sessions per thread to 1*/
	if ((cfg.flag.socket_resue.val) && (cfg.int_v.tx_th_active_sessions.config_mode == DEFAULT_CFG ))
	{
		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
	}

	/*******POST UPLOAD*********/
	/*for post_upload, change the default num of threads to 1*/
	if ((cfg.int_v.post_upload.val) && (cfg.int_v.tx_num_of_threads.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
	}

	/*for post_upload, change the default active sessions per thread to 1*/
	if ((cfg.int_v.post_upload.val) && (cfg.int_v.tx_th_active_sessions.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}

	/*******SOURCE PORT*********/
	/*for Source port, change the default num of threads to 1*/
	if (cfg.int_v.src_port.val)
	{
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;

		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}

	/*******BW RX*********/
	/*for BW RX, change the default num of threads to 1*/
	if ((cfg.int_v.bw_rx_limit.val) && (cfg.int_v.tx_num_of_threads.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
	}

	/*for BW RX, change the default active sessions per thread to 1*/
	if ((cfg.int_v.bw_rx_limit.val) && (cfg.int_v.tx_th_active_sessions.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}

	/*******BW TX*********/
	/*for BW TX, change the default num of threads to 1*/
	if ((cfg.int_v.bw_TX_limit.val) && (cfg.int_v.tx_num_of_threads.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_num_of_threads.val = 1;
		cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
	}

	/*for BW TX, change the default active sessions per thread to 1*/
	if ((cfg.int_v.bw_TX_limit.val) && (cfg.int_v.tx_th_active_sessions.config_mode == DEFAULT_CFG))
	{
		cfg.int_v.tx_th_active_sessions.val = 1;
		cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
	}


	/*******DATA SENDER*********/
	/*datasender limitations*/
	if (cfg.str_v.data_sender[0])
	{
		if (cfg.int_v.post_upload.val)
		{
			PRINTF_VZ_N ( "-ds cannot work with either: -up , -cr , -cr2 , Wc\n");
			usage();
		}

		/*for data sender, change the default num of threads to 1*/
		if (cfg.int_v.tx_num_of_threads.config_mode == DEFAULT_CFG)
		{
			cfg.int_v.tx_num_of_threads.val = 1;
			cfg.int_v.tx_num_of_threads.config_mode = OVERWRITE_CFG;
		}

		/*for data sender, change the default active sessions per thread to 1*/
		if (cfg.int_v.tx_th_active_sessions.config_mode == DEFAULT_CFG)
		{
			cfg.int_v.tx_th_active_sessions.val = 1;
			cfg.int_v.tx_th_active_sessions.config_mode = OVERWRITE_CFG;
		}
		/*data sender*/
		validate_data_sender_file(cfg.str_v.data_sender);

	}
	/*******PROXY*********/
	/*proxy setings*/
	if (IS_STRING_SET(cfg.str_v.proxy_addr) /*cfg.str_v.proxy_addr[0]*/)
	{
		validae_url(cfg.str_v.proxy_addr , &cfg.dest_proxy_params , 1);
	}


	/*********PARSE DEST VALUES********/
	/*will resolve DNS only if there is no proxy set...*/
	validae_url(cfg.dest_params.orig_full_uri , &cfg.dest_params , (!IS_STRING_SET(cfg.str_v.proxy_addr)));

	if (IS_STRING_SET(cfg.str_v.proxy_addr))
	{
		/*set port*/
		cfg.int_v.port.val = (int)cfg.dest_proxy_params.port;
		/*set ip_ver*/
		ip_ver = cfg.dest_proxy_params.ip_ver;
	}
	else
	{
		/*set port*/
		cfg.int_v.port.val = (int)cfg.dest_params.port;
		/*set ip_ver*/
		ip_ver = cfg.dest_params.ip_ver;
	}


	/*** range validation - have to be after parsed URL ***/
	if (cfg.flag.range.val)
	{
		validate_config_values_range();
	}

	DBG_CONF PRINTF_VZ(" Success parsing and resolving dest params:\n");
	DBG_CONF dbg_print_url_pars_struct(&cfg.dest_params);

	/*******SSL*********/
	if (cfg.dbg_v.dbg & DEBUG_FLAG_SSL)
	{
		if (cfg.int_v.ssl_verify_cert.config_mode != USER_CFG)
		{
			DBG_CONF PRINTF_VZ("Changing the SSL_VERIFY_CERT (-sv) to optional (1)\n");
			cfg.int_v.ssl_verify_cert.val = SSL_VERIFY_CERT_OPTIONAL;
			cfg.int_v.ssl_verify_cert.config_mode = OVERWRITE_CFG;
		}
	}
	if (IS_STRING_SET(cfg.str_v.ssl_ciphers))
	{
		validate_ssl_force_ciphers_list(cfg.str_v.ssl_ciphers);
	}
}


/**********************************************************/
/*fill_default_flags_params*/
/**********************************************************/
void fill_default_flags_params()
{
	int i;
	for (i=0 ; i < num_of_flags_params ; i++)
	{
		if (params_flags[i].default_value)
		{
			param_flag_struct *flag_val = params_flags[i].received_value;
			flag_val->val = params_flags[i].default_value;
			flag_val->config_mode = DEFAULT_CFG;

			//			*params_flags[i].received_value = params_flags[i].default_value;
		}
	}
}

/**********************************************************/
/*fill_default_int_param*/
/**********************************************************/
void fill_default_string_params()
{
	int i;
	for (i=0 ; i < num_of_string_params ; i++)
	{
		if (params_string[i].default_value)
		{
			strncpy(params_string[i].received_value , params_string[i].default_value , (uint)params_string[i].max_length);
		}
	}
}

/**********************************************************/
/*fill_default_int_param*/
/**********************************************************/
void fill_default_int_params()
{
	int i;
	for (i=0 ; i < num_of_int_params ; i++)
	{
		param_int_struct *int_val = params_int[i].received_value;
		int_val->val = params_int[i].default_value;
		int_val->config_mode = DEFAULT_CFG;
	}
}

/**********************************************************/
/*fill_default_param*/
/**********************************************************/
void fill_default_param()
{

	memset (&cfg , 0 , sizeof(configuration_params));

	num_of_int_params =  sizeof(params_int) / sizeof(parameters_int);
	num_of_string_params = sizeof(params_string) / sizeof(parameters_string);
	num_of_flags_params = sizeof(params_flags) / sizeof(parameters_flags);

	/*default params*/
	ip_ver = IPV4;

	fill_default_int_params();
	fill_default_string_params();
	fill_default_flags_params();


}

/**********************************************************/
/*rcv_dst_ip*/
/**********************************************************/
void rcv_dst_ip(char *rcv_ip_string)
{
	if (rcv_ip_string == NULL)
	{
		PRINTF_VZ_N ("Destination cannot be empty\n");
		usage();
	}
	if (strlen(rcv_ip_string) > HDR_STRING_LENGTH)
	{
		PRINTF_VZ_N ("Destination string is too long, cannot exceed %d Bytes\n",HDR_STRING_LENGTH);
		usage();
	}
	strncpy(cfg.dest_params.orig_full_uri, rcv_ip_string , sizeof(cfg.dest_params.orig_full_uri));/*keep the www/host address*/

	return;
}


/**********************************************************/
/*init_uri_parser_struct*/
/**********************************************************/
void init_uri_parser_pointers (uri_parser *uri_parser_struct)
{
	uri_parser_struct->protocol_ptr = NULL;
	uri_parser_struct->www_addr_ptr = NULL;
	uri_parser_struct->ip_addr_ptr = NULL;
	uri_parser_struct->port_ptr = NULL;
	uri_parser_struct->path_ptr = NULL;
	uri_parser_struct->file_name_ptr = NULL;
	return;
}

/**********************************************************/
/*parse_destination_url()*/
/*examples:*/
/*192.168.0.2*/
/*[2001::1]*/
/*http://192.168.0.2:8888/servlet/test/rece*/
/*http://[2001::1]:8888/servlet/test/rece*/
/*http://192.168.0.2/servlet/rece*/
/*http://[2001::1]/servlet/rece*/
/*http://www.test.com/servlet/rece*/
/*192.168.0.2:8888/servlet/rece*/
/*[2001::1]:/servlet/rece*/
/**********************************************************/
uint  parse_destination_url(char *uri_rcv_string , uri_parser *uri_parse)
{
	uint rcv_string_len = 0;
	char *tmp_port_scan_start_point = NULL;
	char *tmp_path_scan_start_point = NULL;

	if (uri_rcv_string == NULL)
	{
		PRINTF_VZ_N ("rcv_ip_string cannot be NULL\n");
		return FALSE_0;
	}

	rcv_string_len = (uint)strlen(uri_rcv_string);

	if (rcv_string_len > HDR_STRING_LENGTH)
	{
		PRINTF_VZ_N ("uri_rcv_string too long (%d Bytes)\n",rcv_string_len);
		return FALSE_0;
	}

	/*keep the original and trashed string*/
	strncpy (uri_parse->orig_full_uri , uri_rcv_string , HDR_STRING_LENGTH);
	strncpy (uri_parse->trashed_uri , uri_rcv_string , HDR_STRING_LENGTH);

	/*check if start in http://*/
	uri_parse->www_addr_ptr = strnstr(uri_parse->trashed_uri , "://" , rcv_string_len);
	if (uri_parse->www_addr_ptr)
	{/*found :// trim the last /*/
		uri_parse->www_addr_ptr[2] = '\0';
		/*point to the next char*/
		uri_parse->www_addr_ptr = &uri_parse->www_addr_ptr[3];
		uri_parse->protocol_ptr = uri_parse->trashed_uri;
	}
	else
	{/*NOT found ://*/
		uri_parse->www_addr_ptr = uri_parse->trashed_uri;
	}
	uri_parse->ip_addr_ptr = uri_parse->www_addr_ptr;

	/*is it ipv6?*/
	if (uri_parse->ip_addr_ptr[0] == '[')
	{

		/*trim the [ of the IPv6 address*/
		uri_parse->ip_addr_ptr[0] = '\0';
		uri_parse->ip_addr_ptr = &uri_parse->ip_addr_ptr[1];/*point on the next string*/

		tmp_port_scan_start_point = strchr(uri_parse->ip_addr_ptr , ']');
		if (tmp_port_scan_start_point == NULL)
		{ /***FAIL** to find closing bracket ] of IPv6*/
			PRINTF_VZ_N ("**FAIL** to find closing bracket ] of IPv6 for string = %s\n",uri_rcv_string);
			return FALSE_0;
		}
		else
		{/*trim the ] of the IPv6 address*/
			tmp_port_scan_start_point[0] = '\0';
			tmp_port_scan_start_point = &tmp_port_scan_start_point[1];/*point on the next string*/
			uri_parse->ip_ver = IPV6;
		}
	}
	else
	{/*not IPv6*/
		tmp_port_scan_start_point = uri_parse->ip_addr_ptr;
	}

	/*search for port*/
	uri_parse->port_ptr = strchr(tmp_port_scan_start_point , ':');
	if (uri_parse->port_ptr)
	{/*port found , trim the : */
		uri_parse->port_ptr[0] = '\0';
		uri_parse->port_ptr = &uri_parse->port_ptr[1];/*point on the port string*/
		tmp_path_scan_start_point = uri_parse->port_ptr;
	}
	else
	{/*port not found*/
		tmp_path_scan_start_point = tmp_port_scan_start_point /*uri_parse->ip_addr_ptr*/;
	}


	/*look for the FIRST occurance of / which represent the path*/
	uri_parse->path_ptr = strchr(tmp_path_scan_start_point , '/');
	/*look for the LAST occurance of / which represent the path*/
	uri_parse->file_name_ptr = strrchr(tmp_path_scan_start_point , '/');

	if ((uri_parse->path_ptr == NULL) && (uri_parse->file_name_ptr == NULL))
	{/*no path or file name found*/
		/*do nothing, leave them as NULL*/
	}
	else if (uri_parse->path_ptr == uri_parse->file_name_ptr)
	{/*Only single / found , meaning no path, only file name*/
		uri_parse->path_ptr = NULL;
		uri_parse->file_name_ptr[0] = '\0';

		/*verify didn't reach to the end of the string*/
		if (((uri_parse->file_name_ptr + 1) - uri_parse->trashed_uri) < (int)rcv_string_len)
		{
			uri_parse->file_name_ptr = &uri_parse->file_name_ptr[1];
		}
	}

	else if (uri_parse->path_ptr != uri_parse->file_name_ptr)
	{/*Multiple / found , path, and file name*/
		/*trim first / in the path*/
		uri_parse->path_ptr[0] = '\0';
		uri_parse->path_ptr = &uri_parse->path_ptr[1];
		uri_parse->file_name_ptr[0] = '\0';

		uri_parse->file_name_ptr = &uri_parse->file_name_ptr[1];

	}

	return TRUE_1;

}


/*************************************/
/*validate_http_protocol*/
/*return value = 1=success , 0=protocol not supported */
/*************************************/
uint validate_http_protocol(uri_parser *uri_parse, int support_https)
{
	if ((uri_parse->protocol_ptr[0] == 'H' || uri_parse->protocol_ptr[0] == 'h') &&
			(uri_parse->protocol_ptr[1] == 'T' || uri_parse->protocol_ptr[1] == 't') &&
			(uri_parse->protocol_ptr[2] == 'T' || uri_parse->protocol_ptr[2] == 't') &&
			(uri_parse->protocol_ptr[3] == 'P' || uri_parse->protocol_ptr[3] == 'p'))
	{
		if (uri_parse->trashed_uri[4] == ':' &&
				uri_parse->trashed_uri[5] == '/')
		{ /*found http:/*/
			return TRUE_1;
		}
		else if ((uri_parse->trashed_uri[4] == 'S' || uri_parse->trashed_uri[4] == 's') &&
				uri_parse->trashed_uri[5] == ':' &&
				uri_parse->trashed_uri[6] == '/' )
		{/*found https:/*/
			if (support_https)
			{
				cfg.flag.ssl.val = 1;
				validate_config_ssl();
			}
			return TRUE_1;
		}
	}
	return FALSE_0;
}

/*************************************/
/*validate_and_convert_ip_address_from_string*/
/*return value = 1=success ,-1=errno, 0=ip string invalid, or not match to IPver*/
/*************************************/

int validate_and_convert_ip_address_from_string(uri_parser *uri_parse)
{
	int result; /*1=success ,-1=errno, 0=ip string invalid, or not match to IPver*/

	/*check if it's IPv4 or IPv6 IP address*/
	/*IPv4*/
	result = inet_pton(IPV4 , uri_parse->ip_addr_ptr , uri_parse->ip_addr_isolate_binary);
	if (result > 0)
	{
		strncpy (uri_parse->ip_addr_isolate_string , uri_parse->ip_addr_ptr , INET6_ADDRSTRLEN);
		uri_parse->ip_ver = IPV4;
	}
	/*IPv6*/
	else
	{/*check if it's IPv6 IP address*/
		result = inet_pton(IPV6 , uri_parse->ip_addr_ptr , uri_parse->ip_addr_isolate_binary);
		if (result > 0)
		{
			strncpy (uri_parse->ip_addr_isolate_string , uri_parse->ip_addr_ptr , INET6_ADDRSTRLEN);
			uri_parse->ip_ver = IPV6;
		}
	}
	DBG_CONF PRINTF_VZ("result =%d\n",result);
	return result;
}


/**********************************************************/
/*validate_and_convert_port_from_string*/
/**********************************************************/
uint validate_and_convert_port_from_string(uri_parser *uri_parse)
{
	char *ptr_end = NULL;
	uint ret = FALSE_0;


	if ((uri_parse->port_ptr == NULL) || (uri_parse->port_ptr[0] == '\0'))
	{
		if (cfg.flag.ssl.val)
		{
			uri_parse->port = DEFAULT_SSL_PORT;
		}
		else
		{
			uri_parse->port = DEFAULT_PORT;
		}
		ret = TRUE_1;
	}
	else
	{
		uri_parse->port  = (uint)strtoul(uri_parse->port_ptr , &ptr_end , 10);
		if (uri_parse->port <= 0)
		{
			PRINTF_VZ_N ( "**FAIL** convert port from string(%s), errno=%d\n",uri_parse->port_ptr, errno);
			ret = FALSE_0;
		}
		else if (uri_parse->port >= MAX_PORT_VALUE)
		{
			PRINTF_VZ_N ( "port max value = %d, cannot use %s\n",MAX_PORT_VALUE , uri_parse->port_ptr);
			uri_parse->port = 0;
			ret = FALSE_0;
		}
		else
		{/*success convert port*/
			ret = TRUE_1;
		}
	}
	return ret;
}

/**********************************************************/
/*resolve_dns_web_address*/
/**********************************************************/

uint resolve_dns_web_address(uri_parser *uri_parse)
{
	struct addrinfo hints, *res;
	int errcode;
	void *ptr;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags |= AI_CANONNAME;

	/*resolve the name*/
	errcode = getaddrinfo (uri_parse->www_addr_ptr, NULL, &hints, &res);
	if (errcode != 0)
	{
		DBG_CONF PRINTF_VZ("getaddrinfo error - %s\n", strerror(errno));
		return FALSE_0;
	}

	DBG_CONF PRINTF_VZ("success getaddrinfo errcode =%d\n",errcode);

	if (res) /*select the first address, don't need the while...*/
	{
		switch (res->ai_family)
		{
		case AF_INET:
			uri_parse->ip_ver = IPV4;
			ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			break;
		case AF_INET6:
			uri_parse->ip_ver = IPV6;
			ptr = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
			break;
		}
		/*keep the binary IP notation*/
		memset(uri_parse->ip_addr_isolate_binary , 0 , sizeof(uri_parse->ip_addr_isolate_binary));
		memcpy (uri_parse->ip_addr_isolate_binary , ptr , (sizeof(ptr)));

		/*convert the binaty to ip address string and keep the binary IP notation*/
		inet_ntop (res->ai_family, ptr, uri_parse->ip_addr_isolate_string, HDR_STRING_LENGTH);
		DBG_CONF PRINTF_VZ_N ("SUccess DNS resolution for %s = IPv%d address: %s (%s)\n",uri_parse->www_addr_ptr , res->ai_family == PF_INET6 ? 6 : 4,	uri_parse->ip_addr_isolate_string, res->ai_canonname);
		res = res->ai_next; /*choose only the first*/
	}
	return TRUE_1;
}

/**********************************************************/
/*dbg_print_url_pars_struct*/
/**********************************************************/
void dbg_print_url_pars_struct(uri_parser *uri_parse)
{
	PRINTF_VZ_N ("uri_parse->orig_full_uri=%s\n",uri_parse->orig_full_uri);
	PRINTF_VZ_N ("uri_parse->protocol_ptr=%s\n",uri_parse->protocol_ptr);
	PRINTF_VZ_N ("uri_parse->ip_ver=%d\n",uri_parse->ip_ver);
	PRINTF_VZ_N ("uri_parse->port=%d\n",uri_parse->port);
	PRINTF_VZ_N ("uri_parse->ip_addr_isolate_string=%s\n",uri_parse->ip_addr_isolate_string);
	PRINTF_VZ_N ("uri_parse->ip_addr_isolate_binary=%x,%x,%x,%x,%x\n"
			,uri_parse->ip_addr_isolate_binary[0],
			uri_parse->ip_addr_isolate_binary[1],
			uri_parse->ip_addr_isolate_binary[2],
			uri_parse->ip_addr_isolate_binary[3],
			uri_parse->ip_addr_isolate_binary[4]);
	PRINTF_VZ_N ("uri_parse->www_addr_ptr(%p)=%s\n",uri_parse->www_addr_ptr , uri_parse->www_addr_ptr);
	PRINTF_VZ_N ("uri_parse->ip_addr_ptr(%p)=%s\n",uri_parse->ip_addr_ptr,uri_parse->ip_addr_ptr);
	PRINTF_VZ_N ("uri_parse->port_ptr(%p)=%s\n",uri_parse->port_ptr,uri_parse->port_ptr);
	PRINTF_VZ_N ("uri_parse->path_ptr(%p)=%s \n",uri_parse->path_ptr , uri_parse->path_ptr);
	PRINTF_VZ_N ("uri_parse->file_name_ptr(%p)=%s\n",uri_parse->file_name_ptr,uri_parse->file_name_ptr);
}

/**********************************************************/
/*params_parsesr*/
/**********************************************************/
void params_parser(int argc, char **argv)
{
	int i;

	/*parsing params */
	if (argc > 1)
	{
		for(i = 1; i < argc; i++)
		{
			DBG_CONF PRINTF_VZ("params_parsesr, argv[%d]=%s\n ",i, argv[i]);
			if (argv[i][0] == '-')
			{
				if (recieve_flag_value(argv[i]) == 1)
				{
					continue;
				}
				else if (/*(i + 1 < argc) && (argv[i+1][0] != '-') && (argv[i+1][0] != '/') &&*/
						(recieve_string_value(argv[i], argv[i+1]) == 1))
				{
					i++;
					continue;
				}
				else if ((i + 1 < argc) && (argv[i+1][0] != '-') && (argv[i+1][0] != '/') &&
						(recieve_int_value(argv[i], argv[i+1]) == 1))
				{
					i++;
					continue;
				}
				else if ((i + 1 < argc) && (argv[i+1][0] != '-') && (argv[i+1][0] != '/') &&
						(recieve_debug_value(argv[i], argv[i+1]) == 1))
				{
					i++;
					continue;
				}
				else
				{
					PRINTF_VZ_N ("\nunknown value = %s\n\n",argv[i]);
					usage();
				}
			}
			else
			{
				rcv_dst_ip(argv[i]);
			}
		}
	}
}


/**********************************************************/
/*get_dest_host_or_ip_ptr()*/
/**********************************************************/
char *get_dest_host_ptr(uri_parser *url_parser)
{
	if (IS_STRING_SET(url_parser->www_addr_ptr))
	{
		return url_parser->www_addr_ptr;
	}
	else
	{
		return NULL;
	}

}
/**********************************************************/
/*display_php_file()*/
/**********************************************************/
void display_php_file()
{
	char hr[]=
	{"<html>\r\n\
<body>\r\n\
<center><b>VazaGet server!</b></center>\r\n\
<hr>\r\n\
<?php if (!empty($_SERVER['REMOTE_ADDR'])) echo \"ClientSrcIP=\" .  $_SERVER['REMOTE_ADDR'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['REMOTE_PORT'])) echo \"ClientSrcPort=\" .  $_SERVER['REMOTE_PORT'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['SERVER_ADDR'])) echo \"ClientDstIP=\" .  $_SERVER['SERVER_ADDR'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['SERVER_PORT'])) echo \"ClientDstPort=\" .  $_SERVER['SERVER_PORT'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['SERVER_PROTOCOL'])) echo \"HttpProtocol=\" .  $_SERVER['SERVER_PROTOCOL'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) echo \"X-ForwardedFor=\" .  $_SERVER['HTTP_X_FORWARDED_FOR'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['HTTP_COOKIE'])) echo \"HttpCookie=\" .  $_SERVER['HTTP_COOKIE'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['HTTP_VIA'])) echo \"HttpVia=\" .  $_SERVER['HTTP_VIA'] . \"<br />\"; ?>\r\n\
<?php if (!empty($_SERVER['SSL_SESSION_ID'])) echo \"SSLSessionID=\" .  $_SERVER['SSL_SESSION_ID'] . \"<br />\"; ?>\r\n\
<hr>\r\n"};

	char form[]=
	{"<form action=\"<?php echo $_SERVER['PHP_SELF']; ?>\" method=\"post\" enctype=\"multipart/form-data\">\r\n\
<label for=\"file\">File upload (POST test):</label>\r\n\
<input type=\"file\" name=\"file\" id=\"file\"><br>\r\n\
<input type=\"submit\" name=\"submit\" value=\"Submit\">\r\n\
</form>\r\n\
\r\n"};

	char php[]=
	{"<?php\r\n\
if(isset($_POST['submit']))\r\n\
{\r\n\
	$allowedExts = array(\"gif\", \"jpeg\", \"jpg\", \"png\", \"vzg\" , \"txt\");\r\n\
	$extension = end(explode(\".\", $_FILES[\"file\"][\"name\"]));\r\n\
	if ((($_FILES[\"file\"][\"type\"] == \"image/gif\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"image/jpeg\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"image/jpg\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"image/pjpeg\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"image/x-png\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"image/png\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"application/octet-stream\")\r\n\
	|| ($_FILES[\"file\"][\"type\"] == \"text/plain\"))\r\n\
	&& in_array($extension, $allowedExts))\r\n\
	{\r\n\
		if ($_FILES[\"file\"][\"error\"] > 0)\r\n\
		{\r\n\
			echo \"Return Code: \" . $_FILES[\"file\"][\"error\"] . \"<br>\";\r\n\
		}\r\n\
		else\r\n\
		{\r\n\
			$dir_path = \"/dev/null\";\r\n\
			echo \"Success Upload file--> \";\r\n\
			echo $_FILES[\"file\"][\"name\"] . \" , size=\" . ($_FILES[\"file\"][\"size\"] / 1024) . \" kB\" . \"<br>\";\r\n\
\r\n\
			if (file_exists($dir_path . $_FILES[\"file\"][\"name\"]))\r\n\
			{\r\n\
				echo $_FILES[\"file\"][\"name\"] . \" already exists. \";\r\n\
			}\r\n\
			else\r\n\
			{\r\n\
				move_uploaded_file($_FILES[\"file\"][\"tmp_name\"],\r\n\
				$dir_path . $_FILES[\"file\"][\"name\"]);\r\n\
			}\r\n\
		}\r\n\
	}\r\n\
	else\r\n\
	{\r\n\
		echo \"!!!Invalid file type!!!, allowed-->\";\r\n\
		foreach($allowedExts as $v) echo \"*.\" . $v , PHP_EOL;\r\n\
	}\r\n\
}\r\n\
?>\r\n\
</body>\r\n\
</html>\r\n"};

	PRINTF_VZ_N ("index.php file for the vazaget server (requires php5 on the apache):\n");
	PRINTF_VZ_N ("==============================\n");
	PRINTF_VZ_N ("%s",hr);
	PRINTF_VZ_N ("%s",form);
	PRINTF_VZ_N ("%s",php);
	PRINTF_VZ_N ("==============================\n");
	exit_vz(EXIT_FAILURE, NULL);
}



