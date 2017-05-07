/*
 * data_sender.h
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  data_sender.h is part of vazaget.
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

#ifndef DATA_SENDER_H_
#define DATA_SENDER_H_

#define DS_MAX_PAYLOAD			10000 /*Bytes*/

uint	ds_disp;
#define DS_PRINT				if (ds_disp)
#define DS_MAX_COMMANDS			500

#define VALID_CMD	0
#define INVALID_CMD	1

typedef enum {
	DS_EVENT_CMD_FOUND,
	DS_EVENT_PARSE_END,
	DS_EVENT_PHRASE_NOT_FOUND,
	DS_EVENT_ILLEGAL_PHRASE,
	DS_EVENT_MAX
}DS_PARSER_EVENTS;

typedef enum {
	DS_CMD_TX,
	DS_CMD_RX,
	DS_CMD_WAIT,
	DS_CMD_MAX
}DS_COMMANDS;

typedef struct
{
	uint		command;
	int		hidden;
	uint		min_value;
	uint		max_value;
	char	cmd_string[50];
	char	short_description[100];
	char 	description[1000];
}ds_commnads_t;

typedef struct
{
	char	*content;
	char	*file_name/*[MAX_FILE_NAME_LENGTH+1]*/;
	uint 	file_size;
	uint 	num_of_lines;
	uint 	num_of_cmds;
	uint	tx_cmds;
	uint	rx_cmds;
	uint	wait_cmds;
	char	rcv_mode; /*if we have RX as the first cmd, then we need to work in RX mode*/
}ds_file_t;
ds_file_t ds_file;

uint cmd_combinations[DS_CMD_MAX][DS_CMD_MAX];

/**********FUNCTIONS*************/

/*Data Sender*/
void init_ds_db(uint fd_idx);
uint ds_parser(fd_ds_db_t *ds_db);
void init_ds_file_payload();
void init_ds_cmd_combinations();
void ds_move_to_next_command(uint fd_idx, const char *from_func , int line);
void ds_build_TX_pkt(char *tx_pkt, uint fd_idx);
uint ds_analyze_rx(uint fd_idx);
void ds_rcv_payload(uint fd_idx, uint cur_rcv_bytes);

#endif /* DATA_SENDER_H_ */
