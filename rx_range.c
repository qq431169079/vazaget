/* rx_range.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  rx_range.c is part of vazaget.
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
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "global.h"
#include "rx_range.h"
#include "rx.h"
#include "tx.h"
#include "prints.h"
#include "config.h"
#include "timer.h"
#include "close.h"

#define RANGE_TMP_PATH	"/tmp/vz"
#define RANGE_RETURN_CODE_NOT_206		1
#define RANGE_ACCEPT_RANGES_NOT_EXIST 	2
#define RANGE_ACCEPT_RANGES_NOT_BYTES	3


/***********range_fallback_to_normal_session**********************/
/*TODO : relase more range resources which not neeeded*/
static void range_fallback_to_normal_session(uint fd_idx, int reason)
{
	uint tx_th_idx, tx_th_idx_start = 1;

	DBG_RANGE PRINTF_VZ("session is not range, reason=%d, fallback to normal session, closing irrelevant TX threads...\n",
			reason);

	if (cfg.flag.range.val)
	{
		cntr.info.server_not_support_range++;
	}
	cfg.flag.range.val = 0;
	cfg.flag.range.config_mode = OVERWRITE_IN_RUN_TIME;

	cfg.flag.socket_resue.val = 0;
	cfg.flag.socket_resue.config_mode = OVERWRITE_IN_RUN_TIME;



	if (reason == RANGE_RETURN_CODE_NOT_206)
	{/*we get in here in case we received 200OK, then all we need is continue receiving
	on our existing socket, and finish once done*/
		tx_th_idx_start = 0;
		cfg.int_v.num_of_session.val = 1;
		cfg.int_v.num_of_session.config_mode = OVERWRITE_IN_RUN_TIME;
	}
	else
	{/*we get in here for cases we received 206, but server is not accepting ranges
	so we need to drop our data, and send new GET as normal session*/
		/*need to send another GET, put the TX sessions to 2*/
		cfg.int_v.num_of_session.val = 2;
		cfg.int_v.num_of_session.config_mode = OVERWRITE_IN_RUN_TIME;
		tx_th_db[0].sess_per_th = 2;
		/*drop the data we received(should be 100 Bytes), otherwise the new GET will append to this 100 Bytes*/
		fd_db[fd_idx].rx.wrote_buf_to_disk = 1;
		/*setting the global file size to 0 , so it should be refilled after next 200OK*/
		file_download_global.file_size = 0;
		DBG_TX PRINTF_VZ("setting tx_th_db[0].sess_per_th = %d \n", tx_th_db[0].sess_per_th);
	}

	/*delete tmp file*/
	if (IS_STRING_SET(range_global.tmp_file_name))
	{
		DBG_RANGE PRINTF_VZ("fallback to normal download, deleting tmp file = %s \n", range_global.tmp_file_name);
		remove(range_global.tmp_file_name);
	}

	/*free range_buf*/
	if (fd_db[fd_idx].buf.range_buf)
	{
		free(fd_db[fd_idx].buf.range_buf);
		fd_db[fd_idx].buf.range_buf = NULL;
	}

	/*shutting down all TX threads except TX thread 0*/
	for (tx_th_idx=tx_th_idx_start ; tx_th_idx<(uint)cfg.int_v.tx_num_of_threads.val ; tx_th_idx++)
	{
		DBG_TX PRINTF_VZ("taking down tx_th_idx %d \n", tx_th_idx);
		tx_th_db[tx_th_idx].go_down_now = 1;

		tx_now(tx_th_idx);
	}
}

/***********is_session_range**********************/
uint is_session_range(uint fd_idx)
{
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;

	if ((!(IS_STRING_SET(parsed_msg->http.return_code))) ||
			(IS_STRING_SET(parsed_msg->http.return_code) && /*checking the return code = 206*/
			(strncmp(parsed_msg->http.return_code, "206" , strlen("206")))))
	{
		range_fallback_to_normal_session(fd_idx, RANGE_RETURN_CODE_NOT_206);
		return FALSE_0;
	}

	if (!(IS_STRING_SET(parsed_msg->http.accept_ranges)))
	{
		range_fallback_to_normal_session(fd_idx, RANGE_ACCEPT_RANGES_NOT_EXIST);
		return FALSE_0;
	}

	if (strnstr(parsed_msg->http.accept_ranges ,  "bytes" , (strlen("bytes") + 4)) == NULL) /*checking the Accept-Ranges: bytes*/
	{
		range_fallback_to_normal_session(fd_idx, RANGE_ACCEPT_RANGES_NOT_BYTES);
		return FALSE_0;
	}

	return TRUE_1;

#if 0
	if ((IS_STRING_SET(parsed_msg->http.return_code) && /*checking the return code = 206*/
			(strncmp(parsed_msg->http.return_code, "206" , strlen("206")) == 0) &&  /*checking the return code = 206*/
			(IS_STRING_SET(parsed_msg->http.accept_ranges)) && /*checking the Accept-Ranges: bytes*/
			(strnstr(parsed_msg->http.accept_ranges ,  "bytes" , (strlen("bytes") + 4)) != NULL))) /*checking the Accept-Ranges: bytes*/
	{
		return TRUE_1;
	}
	cntr.info.server_not_support_range++;
	/*turn off range if we get to conclusion the server is not support it*/
	range_fallback_to_normal_session();

	return FALSE_0;
#endif
}

/***********range_block_and_wait_to_expected_file_size**********************/
/*we need to wait until first response arrive with the global file size.*/
/*so only fd_idx 0 will fetch the first request, and then the rest*/
static void block_and_wait_to_expected_file_size(uint my_fd_idx)
{
	int block_counter = 0;
	uint my_tx_th_idx = fd_db[my_fd_idx].tx.tx_th_idx;


	if (cfg.flag.range.val == 0)
	{
		return;
	}
	while ((!range_global.expected_file_size) &&
			(my_fd_idx != 0) &&
			(!tx_th_db[my_tx_th_idx].go_down_now))
	{
		if (!block_counter)
		{
			DBG_RANGE PRINTF_VZ("Blocking fd_idx(%d)...\n" , my_fd_idx);
		}
		block_counter++;
		usleep(TIMER_1MSEC_IN_USEC);
	}


	if (block_counter)
	{
		DBG_RANGE PRINTF_VZ("Release blocking for fd_idx(%d) , range_global.expected_file_size = %"PRIu64"\n" , my_fd_idx , range_global.expected_file_size);
		/*try to add 1msec break between every get in the beginning, so we'll not work in bulks*/
		usleep(my_fd_idx * /*100*/50 * TIMER_1MSEC_IN_USEC);
	}

}

/***********more_ranges_to_fetch**********************/
uint more_ranges_to_fetch()
{
	if ((range_global.expected_file_size != 0) &&
			(((range_global.last_range_fatch + 1) > range_global.expected_file_size) ||
					(range_global.cur_file_size >= range_global.expected_file_size)))
	{
		DBG_RANGE PRINTF_VZ("NO more ranges to fetch...(%"PRIu64"/%"PRIu64")\n" , range_global.last_range_fatch + 1 , range_global.expected_file_size);
		return FALSE_0;
	}
	else
	{
		DBG_RANGE PRINTF_VZ("more ranges to fetch...(%"PRIu64"/%"PRIu64")\n" , range_global.last_range_fatch + 1 , range_global.expected_file_size);
		return TRUE_1;
	}
}

void range_set_ranges_file_name(uint max_active_sessions)
{
	uint fd_idx;

	struct stat st = {0};

	/*create /tmp/vz dir*/
	if (stat(RANGE_TMP_PATH , &st) == -1)
	{
		mkdir(RANGE_TMP_PATH , 0700);
	}

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		uint name_len = (uint)sizeof(RANGE_TMP_PATH) + (uint)strlen(range_global.tmp_file_name) + 10 /*10 for the fd_idx + terminating NULL*/;

		range_global.range_table[fd_idx].range_tmp_file_name = calloc( 1 , name_len);
		if (range_global.range_table[fd_idx].range_tmp_file_name == NULL)
		{
			PRINTF_VZ("Failed malloc (len=%d)for range_tmp_file_name, fd_idx=%d.\n",
					name_len, fd_idx);
			PANIC_NO_DUMP(1);
		}
		snprintf(range_global.range_table[fd_idx].range_tmp_file_name , name_len , "%s/%s_%d" , RANGE_TMP_PATH , range_global.tmp_file_name, fd_idx);
	}
}

void range_delete_all_tmp_ranged_file(uint max_active_sessions)
{
	uint fd_idx;

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		remove(range_global.range_table[fd_idx].range_tmp_file_name);
	}
}
/***********init_range_file_name**********************/
void init_range_global_file_name(uint max_active_sessions)
{
	FILE *fp_tmp = NULL;
	uint tmp_file_name_len;

	if (IS_STRING_SET(cfg.dest_params.file_name_ptr))
	{
		tmp_file_name_len = (uint) strlen(cfg.dest_params.file_name_ptr) + (uint)sizeof(".tmp") + 2;
		range_global.final_file_name = calloc(1 , tmp_file_name_len);
		if (!range_global.final_file_name)
		{
			PANIC_NO_DUMP(1);
		}
		snprintf(range_global.final_file_name , MAX_FILE_NAME_LENGTH , "%s" , cfg.dest_params.file_name_ptr);
	}

	else if (IS_STRING_SET(cfg.dest_proxy_params.file_name_ptr))
	{
		tmp_file_name_len = (uint) strlen(cfg.dest_proxy_params.file_name_ptr) + (uint)sizeof(".tmp") + 2;
		range_global.final_file_name = calloc(1 , tmp_file_name_len);
		if (!range_global.final_file_name)
		{
			PANIC_NO_DUMP(1);
		}
		snprintf(range_global.final_file_name , MAX_FILE_NAME_LENGTH , "%s" , cfg.dest_proxy_params.file_name_ptr);
	}
	else
	{
		DBG_RANGE PRINTF_VZ("**WARNING** (should not get here, it should fail in validation) cannot work with range if file name is not specified\n");
		cfg.flag.range.val = 0;
		cfg.flag.range.config_mode = OVERWRITE_CFG;
		return;
	}

	range_global.tmp_file_name = calloc(1 , tmp_file_name_len);
	snprintf(range_global.tmp_file_name , MAX_FILE_NAME_LENGTH , "%s.tmp" , range_global.final_file_name);

	range_set_ranges_file_name(max_active_sessions);
	/*check if filename.tmp exist*/
	fp_tmp=fopen(range_global.tmp_file_name, "r");
	if (fp_tmp != NULL)
	{/*we have filename + filename.tmp, we continue from there...*/
		fseek(fp_tmp, 0, SEEK_END); // seek to end of file
		range_global.cur_file_size = (uint)ftell(fp_tmp); // get current file pointer
		DBG_RANGE PRINTF_VZ("Success found existing %s file on disk. size=%"PRIu64", continue write to it...\n",range_global.tmp_file_name , range_global.cur_file_size);
		fclose(fp_tmp);
		range_global.next_start_to_send = range_global.cur_file_size;
		range_delete_all_tmp_ranged_file(max_active_sessions);
		return;
	}
	else
	{
		fp_tmp=fopen(range_global.tmp_file_name, "w");
		if (fp_tmp != NULL)
		{
			DBG_RANGE PRINTF_VZ("Success creating new tmp file on disk=%s\n",range_global.tmp_file_name);
			fclose(fp_tmp);
		}
		else
		{
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):**Failed** creating new tmp file on disk=%s\n",FUNC_LINE ,range_global.tmp_file_name);
			exit_vz(EXIT_FAILURE, exit_buf);
		}
		range_delete_all_tmp_ranged_file(max_active_sessions);
	}
	range_global.next_start_to_send = 0;

}

/***********init_range_module**********************/
void init_range_global(uint max_active_sessions)
{
	memset (&range_global , 0 , sizeof(range_global));
	range_global.global_range_block_size = (uint)cfg.int_v.range_size.val ;

#if 0 /*the idea was that we'll not pull too much date from socket, whilr range_buf is smaller, but seems like it works, although need to check that HTTP hdr is not overflow...*/
	if (range_global.range_block_size <= RCV_BUF_SIZE)
	{
		PRINTF_VZ_N( "**WARNING**, range_block_size(%d) cannot be <= from RCV_BUF_SIZE(%d)\n" , range_global.range_block_size , RCV_BUF_SIZE);
		exit(EXIT_FAILURE);
	}
#endif

	init_range_table(max_active_sessions);

	init_range_global_file_name(max_active_sessions);
	if (cfg.flag.range_on_mem.val)
	{
		init_range_buf(0); /*alloc only for fd_idx 0 in the first stage*/
	}

}


/***********range_1_sec_timer**********************/
void range_global_1_sec_timer()
{
	uint idx;
	for (idx = 0 ; idx < max_active_sessions ; idx++)
	{
		if (range_global.range_table[idx].state)
		{
			range_global.range_table[idx].sec++;
		}
	}
}



/***********range_update_priority**********************/
void range_update_rx_priority()
{
#ifdef RANGE_RX_PRIORITY_ENA
	uint fd_idx , priority_match_found = 0;

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if ((range_global.range_table[fd_idx].range_start == range_global.cur_file_size) && (range_global.range_table[fd_idx].state > RANGE_NOT_IN_USE))
		{
			range_global.range_table[fd_idx].priority = 1;
			if (fd_idx < max_active_sessions)
			{
				if (fd_db[fd_idx].rx.epoll_arm_events)
				{
					epoll_modify_add_EPOLLIN(fd_idx);
				}
			}
			priority_match_found = 1;
		}
		/*test - mark the 2nd priority*/
		else if ((range_global.range_table[fd_idx].range_start == (range_global.cur_file_size + range_global.range_block_size)) && (range_global.range_table[fd_idx].state > RANGE_NOT_IN_USE))
		{
			range_global.range_table[fd_idx].priority = 2;
			if (fd_idx < max_active_sessions)
			{
				if (fd_db[fd_idx].rx.epoll_arm_events)
				{
					epoll_modify_add_EPOLLIN(fd_idx);
				}
			}
		}
		/*verify the old priority is 0*/
		else if (range_global.range_table[fd_idx].priority == 1)
		{
			range_global.range_table[fd_idx].priority = 0;
		}

	}

	if ((!priority_match_found) && (!shut_down_now) && (max_active_sessions > 1))
	{
		cntr.error.failed_to_update_range_priority++;
	}
#endif
	return;
}


/***********range_table_remove_fd**********************/
void range_table_remove_fd(uint fd_idx)
{

	pthread_mutex_lock(&range_global.range_table_mutex);

	/*check if need to restart range, and if so verify that the start is not behind the current - otherwise it means we already wrote it to file correctly - probably...*/
	if ((range_global.range_table[fd_idx].state == RANGE_RESTART_ON_NEW_FD) &&
			(range_global.range_table[fd_idx].range_start >= range_global.cur_file_size))
	{
		range_global.range_table[fd_idx].sec = 0;
		range_global.range_table[fd_idx].priority = 0;

		DBG_RANGE PRINTF_VZ("restarting fd_idx(%d), start(%"PRIu64") and end(%"PRIu64") stays the same\n",
				fd_idx, range_global.range_table[fd_idx].range_start, range_global.range_table[fd_idx].range_end);
	}
	else
	{
		char *range_tmp_file_name = range_global.range_table[fd_idx].range_tmp_file_name;
		memset(&range_global.range_table[fd_idx] , 0 , sizeof(range_table_t));
		range_global.range_table[fd_idx].range_tmp_file_name = range_tmp_file_name;
		DBG_RANGE PRINTF_VZ("removing fd_idx(%d)\n",fd_idx);
	}

	range_update_rx_priority();
	/*init fd_db values*/
	memset(&fd_db[fd_idx].rx.range , 0 , sizeof(range_t));

	fd_db[fd_idx].rx.wrote_buf_to_disk = 0;
	fd_db[fd_idx].rx.buffer_full = 0;
	fd_db[fd_idx].rx.rcv_bytes = 0;
	fd_db[fd_idx].rx.bytes_to_rcv = 0;
	fd_db[fd_idx].rx.epoll_state = 0;
	fd_db[fd_idx].rx.respone_fully_rcv = 1;

	pthread_mutex_unlock(&range_global.range_table_mutex);
}

/***********range_table_remove_fd**********************/
uint range_table_add_fd(uint fd_idx)
{
	uint ret = TRUE_1;
	range_t *range_local = &fd_db[fd_idx].rx.range;

	if (pthread_mutex_lock(&range_global.range_table_mutex) == 0)
	{
		DBG_RANGE PRINTF_VZ("Got MUTEX , Start allocating fd_idx=%d\n", fd_idx);
		if (more_ranges_to_fetch()==FALSE_0)
		{/*all ranges fetch , don't need any more ranges,*/
			DBG_RANGE PRINTF_VZ("All ranges being fetch ((last_range_fatch+1) %"PRIu64"  >= range_global.expected_file_size %"PRIu64"), don't need any more ranges, closing the socket...\n",
					  (range_global.last_range_fatch + 1) , range_global.expected_file_size );
			ret = FALSE_0;
		}
		else
		{ /*allocating range*/

			if ((range_global.range_table[fd_idx].state == RANGE_RESTART_ON_NEW_FD)  &&
					(range_global.range_table[fd_idx].range_start >= range_global.cur_file_size))
			{ /*in case of range restart \, keep everything as it was*/
				range_global.range_table[fd_idx].state = RANGE_IN_USE;
				cntr.info.range_restart_unfinished_range++;
			}
			else
			{
				/*set the relevant values on the range table, and on local range values*/
				range_global.range_table[fd_idx].state = RANGE_IN_USE;

				/***setting range start***/
				if (range_global.cur_file_size > range_global.last_range_fatch)
				{
					range_global.range_table[fd_idx].range_start = range_global.cur_file_size;
				}
				else if (range_global.last_range_fatch == 0)
				{/*this is the first range*/
					range_global.range_table[fd_idx].range_start = 0;
				}
				else
				{
					range_global.range_table[fd_idx].range_start = range_global.last_range_fatch + 1;
				}

				if (range_global.last_range_fatch == 0)
				{/*this is the first range*/
					range_local->local_range_block_size = 100;
				}
				else
				{
					range_local->local_range_block_size = range_global.global_range_block_size;
				}

				/***setting range END***/
				range_global.range_table[fd_idx].range_end = ((range_global.range_table[fd_idx].range_start + range_local->local_range_block_size) -1 );

				/*update the last_range_fatch*/
				if (range_global.range_table[fd_idx].range_end > range_global.last_range_fatch)
				{
					range_global.last_range_fatch = range_global.range_table[fd_idx].range_end;
				}

				/*if we on the last range chunk, then need to set the end*/
				if ((range_global.expected_file_size) && ((range_global.range_table[fd_idx].range_end + 1) > range_global.expected_file_size))
				{
					range_global.range_table[fd_idx].range_end = (range_global.expected_file_size - 1); /*in the last range don't need to decrement 1*/
					DBG_RANGE PRINTF_VZ("Seems like reached to the last range chunk, set the end to %"PRIu64"\n",  range_global.range_table[fd_idx].range_end );
				}
			}

			range_update_rx_priority();

			range_local->range_start = &range_global.range_table[fd_idx].range_start;
			range_local->range_end = &range_global.range_table[fd_idx].range_end;

			DBG_RANGE PRINTF_VZ("Range Allocated (ret=%d) for fd_idx=%d: local:start=%"PRIu64" (next_to_send=%"PRIu64"), end=%"PRIu64" , Global: cur(%"PRIu64") / fatch (%"PRIu64") / expected (%"PRIu64")\n",
					ret , fd_idx, *range_local->range_start , range_global.next_start_to_send , *range_local->range_end , range_global.cur_file_size , range_global.last_range_fatch , range_global.expected_file_size );

		}

		pthread_mutex_unlock(&range_global.range_table_mutex);
	}

	return ret;
}

/***********init_range_fd_idx**********************/
uint init_range_fd_idx(uint fd_idx)
{
	uint ret = FALSE_100_NO_MORE_RANGES_TO_GET;
	uint my_tx_th_idx = fd_db[fd_idx].tx.tx_th_idx;

	block_and_wait_to_expected_file_size(fd_idx);

	if (tx_th_db[my_tx_th_idx].go_down_now)
	{
		DBG_RANGE PRINTF_VZ("fd_idx=%d, my_tx_th_idx=%d is going down, returning FALSE_100\n",
				 fd_idx , my_tx_th_idx);
		return ret;
	}
	DBG_RANGE PRINTF_VZ("start, fd_idx=%d  range_global.cur_file_size=%"PRIu64"\n", fd_idx , range_global.cur_file_size );

	if (more_ranges_to_fetch() == TRUE_1)
	{
		if ((fd_db[fd_idx].buf.range_buf == NULL) && (cfg.flag.range_on_mem.val))
		{
			init_range_buf(fd_idx);
		}
		ret = range_table_add_fd(fd_idx);
	}
	else
	{
		DBG_RANGE PRINTF_VZ("[%d]no more ranges to fetch (range_global.cur_file_size=%"PRIu64")... \n", fd_idx , range_global.cur_file_size );
	}
	DBG_RANGE print_range_table( stderr , "--------------------------------------------------------" , 0);

	return ret;
}

/***********handle_rx_range_buf**********************/
/*extract the full expected file size, and update in global*/
/*Content-Range: bytes 122880-999999/1000000*/
uint range_global_update_expected_file_size(char *content_range)
{
	uint ch , ret = FALSE_0;
	uint expected_file_size = 0 , fd_idx;
	char *pEnd = NULL;

	if (content_range == NULL)
	{
		PRINTF_VZ("Invalid content range (NULL) what to do??? \n");
		PANIC_NO_DUMP(1);
	}

	pthread_mutex_lock(&range_global.range_table_mutex);
	if (range_global.expected_file_size == 0)
	{
		for (ch=0 ; ch<50 ; ch++)
		{
			if (content_range[ch] == '/')
			{
				expected_file_size = (uint)strtoul(&content_range[ch+1], &pEnd , 10);
				if ((expected_file_size > 0) && (range_global.expected_file_size == 0))
				{
					range_global.expected_file_size = expected_file_size;
					DBG_RANGE PRINTF_VZ("Updated range expected file size to = %"PRIu64" , \n", range_global.expected_file_size );
					/*there might be scenario where restart on the last range, so the end need to be update also*/
					for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
					{
						if (range_global.range_table[fd_idx].range_end > range_global.expected_file_size)
						{
							range_global.range_table[fd_idx].range_end = (range_global.expected_file_size - 1);
							fd_db[fd_idx].rx.range.range_end = &range_global.range_table[fd_idx].range_end;
							DBG_RANGE PRINTF_VZ("Updated range_end=%"PRIu64", fd_idx=%d \n",
									range_global.range_table[fd_idx].range_end , fd_idx);
						}
					}
					ret = TRUE_1;
				}
				break;
			}
		}
	}
	pthread_mutex_unlock(&range_global.range_table_mutex);
	return ret;
}

/***********handle_rx_range_buf**********************/
void range_file_done(uint fd_idx)
{
	char *valid_file_name = NULL;

	valid_file_name = found_valid_file_name(range_global.final_file_name);
	if (valid_file_name == NULL)
	{
		PRINTF_VZ("**FAIL** to found valid file name, original filename = %s\n", range_global.final_file_name);
		PANIC_NO_DUMP(1);
	}
	else
	{
		snprintf(range_global.final_file_name , MAX_FILE_NAME_LENGTH , "%s" , valid_file_name);
	}


	if (rename(range_global.tmp_file_name , range_global.final_file_name) == 0)
	{
		DBG_RANGE PRINTF_VZ("(%d)All range blocks arrived (%"PRIu64"/%"PRIu64"), renamed file from:%s to:%s \n",
				 fd_idx , range_global.cur_file_size,  range_global.expected_file_size,
				range_global.tmp_file_name , range_global.final_file_name);
	}
	else
	{
		DBG_RANGE PRINTF_VZ("(%d)**FAIL** rename file from:%s to:%s  (%"PRIu64"/%"PRIu64") : %s\n",
				 fd_idx ,	range_global.tmp_file_name , range_global.final_file_name,
				range_global.cur_file_size,  range_global.expected_file_size ,  strerror(errno));
	}
	shutdown_now();
}

/***********handle_rx_range_buf**********************/
uint  range_write_to_disk(uint fd_idx)
{
	range_t *range_local = &fd_db[fd_idx].rx.range;
	uint still_pending = RANGE_WROTE_TO_DISK;
	uint ret = 0;

	if (fd_db[fd_idx].rx.wrote_buf_to_disk)
	{
		return RANGE_WROTE_TO_DISK;
	}
	/*need to check if all ranges before arrived*/
	if (range_global.cur_file_size == *range_local->range_start)
	{
		if (pthread_mutex_trylock(&range_global.range_table_mutex) == 0)
		{
			if (cfg.flag.range_on_mem.val)
			{
				ret = write_to_binary_file(range_global.tmp_file_name , fd_db[fd_idx].buf.range_buf , (uint)((*range_local->range_end + 1) - *range_local->range_start)/*range_global.range_block_size*/);
			}
			else
			{
				ret = append_src_file_to_dst_file(range_global.range_table[fd_idx].range_tmp_file_name, range_global.tmp_file_name , 1);
			}
			if (ret == FALSE_0)
			{/*fail write to disk - set flag to write in next interval*/
				range_local->pending_range_to_write = RANGE_PENDING_VIA_TIMER; /*should be pending on timer*/
				range_global.range_pending_on_timer = 1;
				fd_db[fd_idx].rx.wrote_buf_to_disk = 0;
				DBG_RANGE PRINTF_VZ("[%d]**FAIL** write to file, local range: start=%"PRIu64", end=%"PRIu64", global_range_cur=%"PRIu64"/%"PRIu64"\n",
						 fd_idx , *range_local->range_start , *range_local->range_end, range_global.cur_file_size , range_global.expected_file_size);
			}
			else
			{/*success write to disk*/
				range_local->pending_range_to_write = 0;
				fd_db[fd_idx].rx.wrote_buf_to_disk = 1;
				range_global.cur_file_size += (range_local->range_cur_length);
				cntr.info.range_wrote_buf_to_disk++;
				DBG_RANGE PRINTF_VZ("[%d]Success write to file, local range: start=%"PRIu64", end=%"PRIu64", global_range_cur=%"PRIu64"/%"PRIu64"\n",
						 fd_idx , *range_local->range_start , *range_local->range_end, range_global.cur_file_size , range_global.expected_file_size);
				still_pending = RANGE_WROTE_TO_DISK;
				/*do we have all parts? rename the file*/
				if (range_global.cur_file_size == range_global.expected_file_size)
				{
					range_file_done(fd_idx);
				}
				else
				{
					range_update_rx_priority();
				}
			}
			pthread_mutex_unlock(&range_global.range_table_mutex);
		}
		else
		{/*range MUTEX is not availble*/
			still_pending = RANGE_PENDING;
			DBG_RANGE PRINTF_VZ("[%d]pending write to file, range MUTEX is not availble, local range: start=%"PRIu64", end=%"PRIu64", global_range_cur=%"PRIu64"/%"PRIu64"\n",
					 fd_idx , *range_local->range_start , *range_local->range_end, range_global.cur_file_size , range_global.expected_file_size);
		}
	}
	else
	{/*previous ranges are missing...*/
		still_pending = RANGE_PENDING;
		DBG_RANGE PRINTF_VZ("(%d)pending write to file, previous ranges are missing: start=%"PRIu64", end=%"PRIu64", global_range_cur=%"PRIu64"/%"PRIu64"\n",
				 fd_idx , *range_local->range_start , *range_local->range_end, range_global.cur_file_size , range_global.expected_file_size);
	}

	if (still_pending == RANGE_PENDING)
	{
		range_local->pending_range_to_write = RANGE_PENDING_VIA_TIMER;
		range_global.range_pending_on_timer = 1;
		fd_db[fd_idx].rx.wrote_buf_to_disk = 0;
	}

	return still_pending;
}

/***********************************************************/
/***********range_validate_retrun_code**********************/
/***********************************************************/
uint range_validate_retrun_code(uint fd_idx)
{
	if (fd_db[fd_idx].parser.parsed_msg.http.return_code[0] == '4')
		/*(strncmp(fd_db[fd_idx].parser.parsed_msg.http.return_code, "40" , strlen("40")) == 0)*/
	{
		DBG_RANGE PRINTF_VZ("[%d]**WARNING** file not found (%s), return code = %s\n" , fd_idx ,range_global.final_file_name , fd_db[fd_idx].parser.parsed_msg.http.return_code);
		return FALSE_0;
	}
	else
	{
		DBG_RANGE PRINTF_VZ("[%d]rerurn code = %c%c%c\n" , fd_idx ,
				fd_db[fd_idx].parser.parsed_msg.http.return_code[0] ,fd_db[fd_idx].parser.parsed_msg.http.return_code[1] , fd_db[fd_idx].parser.parsed_msg.http.return_code[2]);
		return TRUE_1;
	}
}


#ifdef RANGE_WRITE_TEST
/***********************************************************/
/***********range_append_to_file**********************/
/***********************************************************/
uint range_append_to_file (char *buf , uint len , uint fd_idx)
{
	char *range_file_name = range_global.range_table[fd_idx].range_tmp_file_name;

	if (range_global.range_table[fd_idx].range_file_fd <= 0)
	{
		snprintf(range_file_name , STRING_100_B_LENGTH , "%s/%s_%d", RANGE_TMP_PATH, range_global.tmp_file_name, fd_idx);
		if ((range_global.range_table[fd_idx].range_file_fd = open(range_file_name, O_RDWR | O_CREAT | O_APPEND , S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1)
		{
			PRINTF_VZ_N( "Failed to open file (%s) for writing, error = %s\n",range_file_name , strerror(errno));
			PANIC_NO_DUMP(1);
		}
	}

	if ((write(range_global.range_table[fd_idx].range_file_fd, buf , len )) != len)
	{
		PRINTF_VZ_N( "Failed to append to file (%s) %d Bytes , error = %s\n",range_file_name , len , strerror(errno));
		PANIC_NO_DUMP(1);
	}

//	close (range_global.range_table[fd_idx].range_file_fd);
	return TRUE_1;

}

#else

/***********************************************************/
/***********range_append_to_file**********************/
/***********************************************************/
uint range_append_to_file (char *buf , uint len , uint fd_idx)
{
	char *range_file_name = range_global.range_table[fd_idx].range_tmp_file_name;
	FILE *range_file_fd = NULL;

	snprintf(range_file_name , STRING_100_B_LENGTH , "%s/%s_%d", RANGE_TMP_PATH, range_global.tmp_file_name, fd_idx);
	if ((range_file_fd = fopen(range_file_name, "ab+" )) == NULL )
	{
		PRINTF_VZ_N( "Failed to open file (%s) for writing, error = %s\n",range_file_name , strerror(errno));
		PANIC_NO_DUMP(1);
	}

	if ((fwrite(buf , sizeof(char) , len , range_file_fd)) != len)
	{
		PRINTF_VZ_N( "Failed to append to file (%s) %d Bytes , error = %s\n",range_file_name , len , strerror(errno));
		PANIC_NO_DUMP(1);
	}

	fclose (range_file_fd);

	return TRUE_1;
}

#endif

/***********handle_rx_range_buf**********************/
uint handle_rx_range_buf(uint fd_idx, uint recv_bytes, char *tmp_buf)
{
	range_t *range_local = &fd_db[fd_idx].rx.range;
	http_struct *http_parse = &fd_db[fd_idx].parser.parsed_msg.http;
	uint bytes_to_copy = 0;
	char *copy_from = NULL;

	DBG_RANGE PRINTF_VZ(">>Start: fd_idx=%d , recv_bytes=%d , wrote_buf_to_disk=%d, expected_file_size=%"PRIu64"...\n",
			  fd_idx, recv_bytes , fd_db[fd_idx].rx.wrote_buf_to_disk , range_global.expected_file_size);

	/*update expected_file_size if needed*/
	if (range_global.expected_file_size == 0)
	{
		if (range_global_update_expected_file_size(http_parse->content_range) == FALSE_0)
		{
			DBG_RANGE PRINTF_VZ("**WARNING** expected_file_size not found in response\n");
		}
	}

	if ((http_parse) && (http_parse->end))
	{
		/*first payload after http_end*/
		if (range_local->wrote_first_payload_from_http_end == 0)
		{
			uint http_hdr_length = (uint) (http_parse->end - http_parse->start);
			bytes_to_copy = (uint)(fd_db[fd_idx].rx.rcv_bytes - http_hdr_length);
			copy_from = http_parse->end;
			range_local->wrote_first_payload_from_http_end = 1;
		}
		/*write as is*/
		else
		{
			copy_from = tmp_buf;
			bytes_to_copy = recv_bytes;
		}
	}
	/*we don't have the full headers yet, nothing to be done so far*/
	else
	{
		return TRUE_1;
	}

	/*sanity check for range_buffer overflow*/
	if ((range_local->range_cur_length + bytes_to_copy) > range_local->local_range_block_size/*range_global.range_block_size*/)
	{
		PRINTF_VZ("**WARNING** range_buf (%d/%d) cannot contain the recv_bytes(%d) \n",
				range_local->range_cur_length ,  range_local->local_range_block_size , bytes_to_copy);
		PANIC_NO_DUMP(1);
	}

	/*copy from tmp_buf into range_buf*/
	if (cfg.flag.range_on_mem.val)
	{
		memcpy(&fd_db[fd_idx].buf.range_buf[range_local->range_cur_length] , copy_from , bytes_to_copy); /*use memcpy and not strncpy, since it ignores the terminating NULL which parser might already inserted...*/
	}
	else
	{
		range_append_to_file(copy_from , bytes_to_copy , fd_idx);
	}

	/*keep the start RX timer*/
	if (range_local->range_cur_length == 0)
	{
		range_local->start_rx_time.slice_10_msec = run_time.slice_10_msec;
		range_local->start_rx_time.slice_100_msec = run_time.slice_100_msec;
		range_local->start_rx_time.sec = run_time.sec;
	}

	range_local->range_cur_length += bytes_to_copy;
	range_local->last_1_sec_rx_bytes += bytes_to_copy;

	/*another sanity*/
	if ((*range_local->range_start + range_local->range_cur_length) > (*range_local->range_start  + range_local->local_range_block_size /*range_global.range_block_size*/))
	{
		DBG_RANGE PRINTF_VZ("**WARNING** range_local->range_start(%"PRIu64") + range_local->range_cur_length(%d)) > range_local->range_end(%"PRIu64") \n",
				*range_local->range_start , range_local->range_cur_length , *range_local->range_end );
		PANIC_NO_DUMP(1);
	}

	DBG_RANGE PRINTF_VZ("(%d) copied %d Bytes into range_buf[] range_cur_length=%d\n" ,  fd_idx, bytes_to_copy , range_local->range_cur_length);

	/*all range collected? write it to disk*/
	if ((*range_local->range_start + range_local->range_cur_length) == (*range_local->range_end + 1))
	{
		range_local->pending_range_to_write = RANGE_PENDING_VIA_RX;
#ifdef RANGE_WRITE_TEST
		close (range_global.range_table[fd_idx].range_file_fd);
		range_global.range_table[fd_idx].range_file_fd = 0;
#endif
	}
	else
	{
		DBG_RANGE PRINTF_VZ("(%d) range is partialy received, more to recv before write to disk(start=%"PRIu64",cur=%d,end=%"PRIu64"\n" ,
				fd_idx, *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
	}
	return TRUE_1;
}


/***********handle_rx_range_buf**********************/
uint rx_range_handle_pending_buf_from_timer()
{
	uint fd_idx = 0;
	uint ret = RANGE_PENDING , pending_bufs_cntr = 0;;

	if (cfg.flag.range.val)
	{
		for (fd_idx=0 ; fd_idx < max_active_sessions ; fd_idx++)
		{
			if (fd_db[fd_idx].rx.range.pending_range_to_write == RANGE_PENDING_VIA_TIMER)
			{
				range_t *range_local = &fd_db[fd_idx].rx.range;
				DBG_RANGE PRINTF_VZ("(%d/%d) Trying to write pending full buf, pending...(start=%"PRIu64",cur=%d,end=%"PRIu64"\n" ,
						fd_idx, fd_db[fd_idx].gen.fd , *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
				if (range_write_to_disk(fd_idx) == RANGE_PENDING)
				{
					DBG_RANGE PRINTF_VZ("(%d/%d) *FAIL* write pending buf, still pending...(start=%"PRIu64",cur=%d,end=%"PRIu64"\n" ,
							fd_idx, fd_db[fd_idx].gen.fd , *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
					cntr.info.range_repending_buf_via_timer++;
					pending_bufs_cntr++;
				}
				else
				{
					DBG_RANGE PRINTF_VZ("(%d/%d) SUCCESS write pending buf (start=%"PRIu64",cur=%d,end=%"PRIu64")\n" ,
							fd_idx, fd_db[fd_idx].gen.fd , *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
					cntr.info.tmp_range_write_pending_buf_via_timer++;
					close_fd_db(fd_idx , REASON_FINISHED_PROCESS_SOCKET);
					/*add_fd_to_epoll have to be done after we closed the socket.
					 * when it was before, I had a problem where FIN was in the epoll,
					 * and caused closing the socket, and then there was another call to close_fd_db*/
					add_fd_to_epoll(fd_db[fd_idx].gen.fd , fd_idx);
					ret = RANGE_WROTE_TO_DISK;
					break;
				}
			}
		}
	}

	if (fd_idx == max_active_sessions)
	{
		cntr.stat.range_pending_bufs = (sig_atomic_t)pending_bufs_cntr;
		if (!pending_bufs_cntr)
		{
			range_global.range_pending_on_timer = 0;
		}
	}
	return ret;
}

/***********range_check_stuck_sockets**********************/
uint is_range_complited(uint fd_idx)
{
	range_t *range_local = &fd_db[fd_idx].rx.range;

	PANIC(range_local == NULL);

	if ((*range_local->range_start + range_local->range_cur_length) == (*range_local->range_end + 1))
	{
		return TRUE_1;
	}
	else
	{
		return FALSE_0;
	}
}


/***********range_check_stuck_sockets_every_x_sec**********************/

void range_check_stuck_sockets(uint my_RX_th_idx)
{

	uint fd_idx;

	for (fd_idx=0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if (my_RX_th_idx == fd_db[fd_idx].rx.rx_th_idx) /*check this fd belong to my rx_th_idx*/
		{
			range_t *range_local = &fd_db[fd_idx].rx.range;

			if ((range_global.range_table[fd_idx].state == RANGE_IN_USE) && (range_local->pending_range_to_write == 0))
			{
				if ((range_global.range_table[fd_idx].sec > 3) &&
						(!range_local->last_3_sec_rx_bytes) &&
						(!range_local->last_2_sec_rx_bytes) &&
						(!range_local->last_1_sec_rx_bytes))
				{
					range_local->last_3_sec_rx_bytes = range_local->last_2_sec_rx_bytes;
					range_local->last_2_sec_rx_bytes = range_local->last_1_sec_rx_bytes;
					range_local->displayed_last_KBytes_per_sec = (range_local->last_1_sec_rx_bytes / 1024);
					range_local->last_1_sec_rx_bytes = 0;

					cntr.info.tmp_range_stuck_socket++;
					//					epoll_modify_add_EPOLLIN(fd_idx);
#if 0
					range_global.range_table[fd_idx].state = RANGE_RESTART_ON_NEW_FD;
					close_fd_db(fd_idx , REASON_RX_RANGE_STUCK);
#endif
				}
				else
				{
					range_local->last_3_sec_rx_bytes = range_local->last_2_sec_rx_bytes;
					range_local->last_2_sec_rx_bytes = range_local->last_1_sec_rx_bytes;
					range_local->displayed_last_KBytes_per_sec = (range_local->last_1_sec_rx_bytes / 1024);
					range_local->last_1_sec_rx_bytes = 0;
				}
			}
		}
	}
}

/***********range_can_I_send_now**********************/

uint range_can_I_send_now(uint fd_idx)
{
	range_t *range_local = &fd_db[fd_idx].rx.range;
	/*need to check <= in case we have retransmision of unsuccessfull range*/
	if ((*range_local->range_start) <= range_global.next_start_to_send)
	{
		return TRUE_1;
	}
	return FALSE_0;
}

/***********range_update_next_get_to_send**********************/
void range_update_next_get_to_send(uint fd_idx)
{
	range_t *range_local = &fd_db[fd_idx].rx.range;
	/*if it was retransmision of previous range, don't update next range*/
	if (range_global.next_start_to_send == *range_local->range_start)
	{
		range_global.next_start_to_send +=  range_local->local_range_block_size/*range_global.range_block_size*/;
	}
}

