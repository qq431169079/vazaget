/*
 * data_sender.c
 *
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  data_sender.c is part of vazaget.
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
#include <errno.h>
#include <stdlib.h>
#include "global.h"
#include "data_sender.h"
#include "rx.h"
#include "tx.h"
#include "prints.h"
#include "close.h"


ds_commnads_t ds_cmd[] =
{
		/*enum------hide-min-max--CMD-----short-desc.------------long-desc.-----------------------------------------*/
		{DS_CMD_TX , 0 , 0 , 0 , {"TX"} , {"TX"}, {"String to send (inside {}), e.g: TX {GET / HTTP/1.1...}"}},
		{DS_CMD_RX , 0 , 0 , 0 , {"RX"} , {"RX"}, {"Pending for string to be received (inside {}), e.g: RX {200 OK}"}},
		{DS_CMD_WAIT,0 , 1 ,1000,{"WAIT"},{"WAIT"},{"(seconds), insert wait period (inside {}), e.g: WAIT {5}"}},
		{DS_CMD_MAX, 0 , 0 , 0 , {""}   , {"DS_CMD_MAX"},{"Invalid command"}},
};

/*****************************************/
/*init_ds_file_payload()*/
/*****************************************/
void init_ds_file_payload()
{
	ds_file.content = calloc (DS_MAX_PAYLOAD+1 , sizeof(char));
	if (ds_file.content == NULL)
	{/***FAIL** malloc*/
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}

/*****************************************/
/*init_ds_file_payload()*/
/*****************************************/
void init_ds_cmd_combinations()
{
	int cur_cmd , next_cmd;

	/*fill all commands to default(INVALID_CMD)*/
	for (cur_cmd=0 ; cur_cmd < DS_CMD_MAX ; cur_cmd++)
	{
		for (next_cmd=0 ; next_cmd < DS_CMD_MAX ; next_cmd++)
		{
			cmd_combinations[cur_cmd][next_cmd] = INVALID_CMD;
		}
	}

	/*fill all commands valid combinations*/
	cmd_combinations[DS_CMD_MAX-1][DS_CMD_TX] = VALID_CMD;
	/*from DS_CMD_TX*/
	cmd_combinations[DS_CMD_TX][DS_CMD_TX] = VALID_CMD;
	cmd_combinations[DS_CMD_TX][DS_CMD_RX] = VALID_CMD;
	cmd_combinations[DS_CMD_TX][DS_CMD_WAIT] = VALID_CMD;
	/*from DS_CMD_RX*/
	cmd_combinations[DS_CMD_RX][DS_CMD_TX] = VALID_CMD;
	cmd_combinations[DS_CMD_RX][DS_CMD_WAIT] = VALID_CMD;
	/*from DS_CMD_WAIT*/
	cmd_combinations[DS_CMD_WAIT][DS_CMD_TX] = VALID_CMD;
	cmd_combinations[DS_CMD_WAIT][DS_CMD_RX] = VALID_CMD;
}

/*****************************************/
/*display_commands_usage()*/
/*****************************************/
void display_commands_usage()
{
	int cmd;
	PRINTF_VZ_N ("Data Sender commands options:\n");
	for (cmd=0 ; cmd < DS_CMD_MAX ; cmd++)
	{
		if (!ds_cmd[cmd].hidden)
			PRINTF_VZ_N ("%s\t--> %s\n", ds_cmd[cmd].cmd_string , ds_cmd[cmd].description);
	}
}


/*****************************************/
/*ds_atoi_cmd()*/
/*****************************************/
uint ds_strtol_cmd(fd_ds_db_t *ds_db)
{
#define CMD_ATOI_STRING	10
	char tmp[CMD_ATOI_STRING+1] = {'\0'};
	uint  min_val=0 , max_val=0;
	uint converted_value=0;
	char *ptr_end = NULL;
	/*Sanity*/
	if (ds_db->phrase_length >= CMD_ATOI_STRING)
	{
		DS_PRINT PRINTF_VZ_N ("phrase string too long (%d Bytes) max=%d for cmd=%s\n",ds_db->phrase_length , CMD_ATOI_STRING , ds_cmd[ds_db->new_cmd].short_description);
		return DS_EVENT_ILLEGAL_PHRASE;
	}

	/*init for CMD_WAIT*/
	if (ds_db->new_cmd == DS_CMD_WAIT)
	{
		memset (&ds_db->ds_cmd_wait , 0 , sizeof(ds_cmd_wait_t));
		min_val = ds_cmd[ds_db->new_cmd].min_value;
		max_val = ds_cmd[ds_db->new_cmd].max_value;
	}

	/*convert*/
	memcpy(tmp , ds_db->phrase_start , ds_db->phrase_length);
	converted_value = (uint)strtoul(tmp , &ptr_end , 10);

	/*validate value*/
	if (converted_value > max_val)
	{
		DS_PRINT PRINTF_VZ_N ("value (%d) above max=%d for cmd=%s\n",converted_value ,max_val , ds_cmd[ds_db->new_cmd].short_description);
		return DS_EVENT_ILLEGAL_PHRASE;
	}
	if (converted_value < min_val)
	{
		DS_PRINT PRINTF_VZ_N ("value (%d) below min=%d for cmd=%s\n",converted_value ,min_val , ds_cmd[ds_db->new_cmd].short_description);
		return DS_EVENT_ILLEGAL_PHRASE;
	}

	DBG_DS PRINTF_VZ("success strtol from %s to %d for cmd=%s\n", tmp , converted_value , ds_cmd[ds_db->new_cmd].short_description);

	/*keep the value*/
	if (ds_db->new_cmd == DS_CMD_WAIT)
	{
		ds_db->ds_cmd_wait.sec_to_wait = converted_value;
		return DS_EVENT_CMD_FOUND;
	}
	else
	{
		return DS_EVENT_ILLEGAL_PHRASE;
	}

}

/*****************************************/
/*ds_parser_cmd()*/
/*****************************************/
uint ds_parser_cmd(fd_ds_db_t *ds_db)
{
	int cmd;
	uint max_parse_length , i;
	uint new_cmd = DS_CMD_MAX;
	char *cmd_found = NULL;
	char *file_ptr = &ds_file.content[ds_db->cur_position];

	/*validation*/
	if (file_ptr == NULL)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):file_ptr = NULL!!!\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*init*/
	ds_db->phrase_start = NULL;
	ds_db->new_cmd = DS_CMD_MAX;
	max_parse_length = (uint)strlen(file_ptr);
	if (max_parse_length > DS_MAX_PAYLOAD)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):Illegal max_parse_length = %d!!!\n",FUNC_LINE,max_parse_length);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*start parsing*/
	DBG_DS PRINTF_VZ("Start parsing cmd, cur_line=%d, max_parse_length=%d\n", ds_db->cur_line , max_parse_length);
	for (i=0 ; i<=max_parse_length ; i++)
	{
		switch(file_ptr[i])
		{
		case '{':
		{
			if (cmd_found)
			{/*phrase found*/
				if (ds_db->phrase_start == NULL)
				{/*found the OPEN quote*/
					DBG_DS PRINTF_VZ("(cmd=%d)Found OPEN { (line=%d, offset=%d+%d), keep searching for CLOSE quote\n",new_cmd,ds_db->cur_line, ds_db->cur_position ,i);
					ds_db->phrase_start = &file_ptr[i+1];
				}
				else
				{/*found the CLOSE quote*/
					DS_PRINT PRINTF_VZ_N ("(cmd=%d)Found OPEN { (line=%d, offset=%d+%d) while already have one... \n",new_cmd, ds_db->cur_line, ds_db->cur_position , i);
					exit_vz(EXIT_FAILURE , NULL);
				}
			}
			else
			{
				PRINTF_VZ("string not found, and arrived to OPEN { (line=%d, offset=%d+%d)\n", ds_db->cur_line , ds_db->cur_position,i);
				return DS_EVENT_PHRASE_NOT_FOUND;
			}
			continue;
		}
		case '}':
		{
			if (cmd_found)
			{/*found the CLOSE quote*/
				DBG_DS PRINTF_VZ("(cmd=%d)Found CLOSE } (line=%d, offset=%d+%d)\n",new_cmd, ds_db->cur_line, ds_db->cur_position , i);
				ds_db->phrase_length = (uint)(&file_ptr[i] - ds_db->phrase_start);
				ds_db->cur_position += i+1;
				ds_db->new_cmd = new_cmd;
				if ((ds_db->phrase_start == NULL) || (ds_db->phrase_length > DS_MAX_PAYLOAD))
				{
					DS_PRINT PRINTF_VZ_N ("**FAIL** to parse phrase (length=%d)\n%s",ds_db->phrase_length,ds_db->phrase_start);
					exit_vz(EXIT_FAILURE , NULL);
				}
				if (ds_db->new_cmd == DS_CMD_WAIT)
				{
					return ds_strtol_cmd(ds_db);
				}
				return DS_EVENT_CMD_FOUND;
			}
			continue;
		}
		case '\0':
		{
			if (!cmd_found)
			{
				DBG_DS PRINTF_VZ("success parsing file (line=%d, offset=%d+%d)\n", ds_db->cur_line ,ds_db->cur_position,i);
				return DS_EVENT_PARSE_END;
			}
			PRINTF_VZ("reached to EOF (line=%d, offset=%d+%d)\n", ds_db->cur_line ,ds_db->cur_position,i);
			return DS_EVENT_PHRASE_NOT_FOUND;
		}
		case '\n':
		{
			ds_db->cur_line++;
			continue;
		}
		default:
		{
			if (!cmd_found)
			{
				for (cmd=0 ; cmd<DS_CMD_MAX ; cmd++)
				{
					if (strncmp(&file_ptr[i] , ds_cmd[cmd].cmd_string , strlen(ds_cmd[cmd].cmd_string)) == 0)
					{
						DBG_DS PRINTF_VZ("Found cmd string (%s), (line=%d, offset=%d+%d), keep searching for OPEN quote\n", ds_cmd[cmd].cmd_string, ds_db->cur_line ,ds_db->cur_position ,i);
						cmd_found = &file_ptr[i];
						new_cmd = ds_cmd[cmd].command;
					}
				}
			}
			continue;
		}
		}
	}
	return DS_EVENT_PHRASE_NOT_FOUND;

}


/*****************************************/
/*ds_parser()*/
/*****************************************/
uint ds_parser(fd_ds_db_t *ds_db)
{
	uint event = 0 ;

	event = ds_parser_cmd(ds_db);

	switch (event)
	{
	case DS_EVENT_CMD_FOUND:
	{
		if ((ds_db->cur_cmd > DS_CMD_MAX) || (ds_db->new_cmd > DS_CMD_MAX))
		{
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):Illegal ds_parser cmd(cur=%d, new=%d)!!!\n",FUNC_LINE,ds_db->cur_cmd , ds_db->new_cmd);
			exit_vz(EXIT_FAILURE, exit_buf);
		}
		if (cmd_combinations[ds_db->cur_cmd][ds_db->new_cmd] != VALID_CMD)
		{
			snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):Illegal cur to new cmd(cur=%d(%s), new=%d(%s))!!!\n",FUNC_LINE,ds_db->cur_cmd , ds_cmd[ds_db->cur_cmd].short_description, ds_db->new_cmd, ds_cmd[ds_db->new_cmd].short_description);
			exit_vz(EXIT_FAILURE, exit_buf);
		}
		ds_db->cur_cmd = ds_db->new_cmd;
		break;
	}
	case DS_EVENT_PARSE_END:
	{
		break;
	}
	default:
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):Illegal event(%d)!!!\n",FUNC_LINE,event);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	}
	return event;
}

/*****************************************/
/*ds_handle_new_cmd()*/
/*****************************************/
void ds_handle_new_cmd(uint fd_idx)
{
	PANIC(fd_idx >= max_active_sessions);

	/*!=DS_CMD_RX*/
	if ((fd_db[fd_idx].ds_db.cur_cmd != DS_CMD_RX) &&
			(fd_db[fd_idx].rx.epoll_state != EPOLL_IN_REMOVED) &&
			(fd_db[fd_idx].gen.fd))
	{
		epoll_modify_remove_EPOLLIN(fd_idx);
	}

	/*DS_CMD_WAIT*/
	if (fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_WAIT)
	{
		fd_db[fd_idx].ds_db.ds_cmd_wait.expire_sec = run_time.sec + fd_db[fd_idx].ds_db.ds_cmd_wait.sec_to_wait;
		fd_db[fd_idx].ds_db.ds_cmd_wait.expire_100m_slice = run_time.slice_100_msec ;
	}

	/*DS_CMD_RX*/
	if ((fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_RX) && (fd_db[fd_idx].rx.epoll_state != EPOLL_IN_ADDED))
	{
		epoll_modify_add_EPOLLIN(fd_idx);
	}
}

/*****************************************/
/*ds_move_to_next_command()*/
/*****************************************/
void ds_move_to_next_command(uint fd_idx, const char *from_func , int line)
{
	uint event;
	PANIC(fd_idx > max_active_sessions);
	event = ds_parser(&fd_db[fd_idx].ds_db);

	/*finished parsing file*/
	if (event == DS_EVENT_PARSE_END)
	{
		DS_PRINT PRINTF_VZ_N ("[%s]Finished process all %s commands (total TX=%d, RX=%d)\n",elapse_time ,ds_file.file_name ,ds_file.tx_cmds ,ds_file.rx_cmds);
		close_fd_db(fd_idx , REASON_DS_FINISHED);
		exit_vz(EXIT_SUCCESS , NULL);
	}

	/*Process next command*/
	if (event != DS_EVENT_CMD_FOUND)
	{
		DS_PRINT PRINTF_VZ_N ("**FAIL** to get next command (event=%d, new_cmd=%d, cur_line=%d, cur_position=%d)\n",event, fd_db[fd_idx].ds_db.new_cmd, fd_db[fd_idx].ds_db.cur_line, fd_db[fd_idx].ds_db.cur_position);
		exit_vz(EXIT_FAILURE , NULL);
	}

	DBG_DS   PRINTF_VZ_N ("Move to next command=%s, called from: %s(%d)\n",ds_cmd[fd_db[fd_idx].ds_db.new_cmd].short_description, from_func, line);
	DS_PRINT PRINTF_VZ_N ("[%s][Move to next command=%s]\n",elapse_time ,ds_cmd[fd_db[fd_idx].ds_db.new_cmd].short_description);

	/*will prcoess the next command, which section should not be performed in validation*/
	ds_handle_new_cmd(fd_idx);

	return;
}


/*****************************************/
/*init_ds_db()*/
/*****************************************/
void init_ds_db(uint fd_idx)
{
	if (fd_db[fd_idx].ds_db.cur_position == 0)
	{/*init the last command only for the start of the DS*/
		fd_db[fd_idx].ds_db.cur_cmd = DS_CMD_MAX;
	}
	ds_move_to_next_command(fd_idx , FUNC_LINE);
}

/*****************************************/
/*ds_build_TX_pkt()*/
/*****************************************/
void ds_build_TX_pkt(char *tx_pkt, uint fd_idx)
{

	if (fd_db[fd_idx].ds_db.cur_cmd != DS_CMD_TX)
	{
		DS_PRINT PRINTF_VZ_N ("**FAIL** to get tx command (cur_cmd=%d, cur_line=%d, cur_position=%d)\n", fd_db[fd_idx].ds_db.cur_cmd, fd_db[fd_idx].ds_db.cur_line, fd_db[fd_idx].ds_db.cur_position);
		exit_vz(EXIT_FAILURE , NULL);
	}
	memcpy(tx_pkt , fd_db[fd_idx].ds_db.phrase_start , fd_db[fd_idx].ds_db.phrase_length);
	return;
}

/*****************************************/
/*ds_analyze_rx()*/
/*****************************************/
uint ds_analyze_rx(uint fd_idx)
{
	int line_cntr = 1;
	uint i;

	/*Sanity check*/
	PANIC(fd_idx >= max_active_sessions);
	if (fd_db[fd_idx].ds_db.cur_cmd != DS_CMD_RX)
	{
		return SESSION_FINISH;
	}
	if ((fd_db[fd_idx].ds_db.phrase_start == NULL) || (fd_db[fd_idx].ds_db.phrase_length > DS_MAX_PAYLOAD))
	{
		DS_PRINT PRINTF_VZ_N ("RX-Illegal RX phrase (length=%d)\n%s",fd_db[fd_idx].ds_db.phrase_length,fd_db[fd_idx].ds_db.phrase_start);
		exit_vz(EXIT_FAILURE , NULL);
	}


	/*Start searching*/
	DS_PRINT PRINTF_VZ_N (BOLDYELLOW "[%s]<--RX start (%"PRIu64" Bytes), searching phrase (%.*s)<--\n" RESET ,elapse_time ,fd_db[fd_idx].rx.rcv_bytes , fd_db[fd_idx].ds_db.phrase_length , fd_db[fd_idx].ds_db.phrase_start);
	DS_PRINT PRINTF_VZ_N (YELLOW "%s\n" RESET ,fd_db[fd_idx].buf.rcv_buf_untouched);
	DS_PRINT PRINTF_VZ_N (BOLDYELLOW "[%s]<--RX end <--\n" RESET ,elapse_time);
	for (i = 0 ; i < fd_db[fd_idx].rx.rcv_bytes ; i++)
	{
		if (strncmp(&fd_db[fd_idx].buf.rcv_buf_untouched[i] , fd_db[fd_idx].ds_db.phrase_start , fd_db[fd_idx].ds_db.phrase_length) == 0)
		{
			DS_PRINT PRINTF_VZ_N ("[%s][Successfully receive=%"PRIu64" Bytes, phrase (%.*s) found at line=%d, offset=%d]\n",elapse_time,
					fd_db[fd_idx].rx.rcv_bytes , fd_db[fd_idx].ds_db.phrase_length, fd_db[fd_idx].ds_db.phrase_start ,line_cntr,i);
			ds_move_to_next_command(fd_idx , FUNC_LINE);
			/*if next command is TX, then need to activate TX_now*/
			if (fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_TX)
			{
				zero_tx_buf(fd_idx);
				ds_build_TX_pkt(fd_db[fd_idx].buf.tx_buf , fd_idx);
				tx_add_pending_buf(fd_idx);
				fd_db[fd_idx].gen.state = STATE_SENT_GET;
			}
			return SESSION_CONTINUE;
		}
		/*line cntr*/
		if (fd_db[fd_idx].buf.rcv_buf_untouched[i] == '\n')
		{
			line_cntr++;
		}
	}
	DBG_DS PRINTF_VZ("Scanned all RX(%dB) and didnt found phrase\n",i);
	return SESSION_FINISH;
}

#if 0
/*****************************************/
/*ds_rcv_payload()*/
/*****************************************/
void ds_rcv_payload(uint fd_idx, uint cur_rcv_bytes)
{
	/*Sanity check*/
	PANIC(fd_idx >= max_active_sessions);
	PANIC(fd_db[fd_idx].buf.rcv_buf_untouched == NULL);
	/*in this point the fd_db[fd_idx].rx.rcv_bytes already updated*/
	uint cur_offset = fd_db[fd_idx].rx.rcv_bytes - cur_rcv_bytes;

	if (((fd_db[fd_idx].rx.rcv_bytes + cur_rcv_bytes)  >= RCV_BUF_SIZE) || (cur_offset >= RCV_BUF_SIZE))
	{
		DS_PRINT PRINTF_VZ_N (BOLDRED "[%s]<--RX (%d Bytes)-Receive buffer is full - dropping content...\n" RESET ,elapse_time ,cur_rcv_bytes);
		return;
	}

	/*copy from the rcv_buf, before parsing, to the untouched buf.*/
	memcpy(&fd_db[fd_idx].buf.rcv_buf_untouched[cur_offset] , &fd_db[fd_idx].buf.rcv_buf[cur_offset] , cur_rcv_bytes);
	memcpy(&fd_db[fd_idx].buf.rcv_buf_untouched[fd_db[fd_idx].rx.rcv_bytes] , "\0" , 1);/*adding terminating NULL*/
	if (cfg.int_v.bw_rx_limit.val)
	{
		DS_PRINT PRINTF_VZ_N (BOLDYELLOW "[%s]<--RX (%d Bytes) <--\n" RESET ,elapse_time ,cur_rcv_bytes);
		DS_PRINT PRINTF_VZ_N (YELLOW "%s\n" RESET , &fd_db[fd_idx].buf.rcv_buf_untouched[cur_offset]);
	}
}
#endif
