/* db.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  db.c is part of vazaget.
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
#include <stdlib.h>
#include <string.h>
#include "global.h"
#include "rx_range.h"
#include "rx.h"

/*********************************/
void init_default_bwT_values_per_fd(uint fd_idx)
{
	int i;

	for (i = 0 ; i < NUM_OF_TIME_SLICES ; i++)
	{
		fd_db[fd_idx].bwTx.bwT[i].slice_limit = global_default_bwT[i].slice_limit;
		fd_db[fd_idx].bwTx.bwT[i].slice_usage = 0;
	}
	fd_db[fd_idx].bwTx.last_second = 0xffffffff;
}

/*********************************/
void init_default_bwR_values_per_fd(uint fd_idx)
{
	int i;

	for (i = 0 ; i < NUM_OF_TIME_SLICES ; i++)
	{
		fd_db[fd_idx].bwRx.bwR[i].slice_limit = global_default_bwR[i].slice_limit;
		fd_db[fd_idx].bwRx.bwR[i].slice_usage = 0;
	}
	fd_db[fd_idx].bwRx.last_second = 0xffffffff;
}



/*********************************/
uint add_fd_to_db (uint fd_idx , int fd)
{
	/*validate fd_idx*/
	PANIC(fd_idx >= max_active_sessions);

	/*verify fd_idx not in use*/
	if (fd_db[fd_idx].gen.fd != 0)
	{
		cntr.error.fd_idx_already_in_use++;
		return FALSE_0;
	}

	/*verify fd_idx not in use*/
	if (fd <= 2)
	{
		cntr.error.try_to_add_illegal_fd++;
		return FALSE_0;
	}
	fd_db[fd_idx].gen.fd = (int)fd;
	fd_db[fd_idx].gen.in_use = 1;
	return TRUE_1;
}

/*********************************/
void clear_parser_data(uint fd_idx)
{
	memset(&fd_db[fd_idx].parser , 0 , sizeof(fd_db[fd_idx].parser));
	fd_db[fd_idx].rx.bytes_to_rcv = 0;
	fd_db[fd_idx].rx.rcv_bytes = 0;
	fd_db[fd_idx].buf.rcv_buf[0] = '\0';
	if (cfg.str_v.data_sender[0])
	{
		fd_db[fd_idx].buf.rcv_buf_untouched[0] = '\0';
	}
}


/*********************************/
void clear_fd_db(uint fd_idx , uint clear_db_level)
{
	/*validate fd_idx*/
	if (fd_idx > max_active_sessions)
	{
		cntr.error.Illegal_fd_idx++;
		return;
	}

	switch (clear_db_level)
	{
	case CLEAR_DB_PARTIAL:
	{/*in this case we don't close the socket, only clean local database*/
		DBG_CLOSE PRINTF_VZ("fd_idx=%d, fd=%d, CLEAR_DB_PARTIAL, skipping close of fd, clear only save data...\n",fd_idx, fd_db[fd_idx].gen.fd);
		clear_parser_data(fd_idx);
		if (cfg.flag.range.val)
		{
			range_table_remove_fd(fd_idx);
		}
	}
	break;

	case CLEAR_DB_FULL:
	{
		uint cur_local_range_block_size = 0;
		DBG_CLOSE PRINTF_VZ("fd_idx=%d, fd=%d, CLEAR_DB_FULL ...\n",fd_idx, fd_db[fd_idx].gen.fd);
		if (cfg.flag.range.val)
		{
			cur_local_range_block_size = fd_db[fd_idx].rx.range.local_range_block_size;
			range_table_remove_fd(fd_idx);
		}

		/*zero chunk buf*/
		erase_all_chunk_data(fd_idx , FALSE_0);

		memset(&fd_db[fd_idx].client , 0 , sizeof(fd_client_t));
		memset(&fd_db[fd_idx].parser , 0 , sizeof(fd_parser_t));
		memset(&fd_db[fd_idx].rx , 0 , sizeof(fd_rx_t));
		memset(&fd_db[fd_idx].tx , 0 , sizeof(fd_tx_t));
		if (cfg.flag.ssl.val)
			memset(&fd_db[fd_idx].ssl_db , 0 , sizeof(fd_ssl_db_t));
		if (cfg.int_v.bw_rx_limit.val)
			memset(&fd_db[fd_idx].bwRx , 0 , sizeof(fd_bwRx_t));
		if (cfg.int_v.bw_TX_limit.val)
			memset(&fd_db[fd_idx].bwTx , 0 , sizeof(fd_bwTx_t));
		if (cfg.str_v.data_sender[0])
		{
			memset(&fd_db[fd_idx].ds_db , 0 , sizeof(fd_ds_db_t));
			fd_db[fd_idx].buf.rcv_buf_untouched[0] = '\0';
		}

		/*zero buffers*/
		fd_db[fd_idx].buf.rcv_buf[0] = '\0';
		fd_db[fd_idx].buf.tx_buf[0] = '\0';

		/*the gen_t should be zeroed last, since it holds the in_use value*/
		memset(&fd_db[fd_idx].gen , 0 , sizeof(fd_gen_t));

		if (cfg.flag.range.val)
		{	/*return the local block size, in case of restart to the socket, then it need to be as it was before*/
			fd_db[fd_idx].rx.range.local_range_block_size = cur_local_range_block_size;
		}
	}
	break;

	default:
	{
		cntr.error.unknown_clear_db_level++;
	}
	break;
	}
}


uint fd_to_fd_idx(uint fd)
{
	uint fd_idx;

	if (fd <= 2)
	{
		return INIT_IDX;
	}

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if (fd == (uint)fd_db[fd_idx].gen.fd)
		{
			return fd_idx;
		}
	}

	return INIT_IDX;
}

