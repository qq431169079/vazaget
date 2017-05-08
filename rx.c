/* rx.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  rx.c is part of vazaget.
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
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <errno.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <wchar.h>
#include <locale.h>     /* struct lconv, setlocale, localeconv */
#include "global.h"
#include "data_sender.h"
#include "rx.h"
#include "rx_range.h"
#include "tx.h"
#include "timer.h"
#include "close.h"

#define LISTENER_BACKLOG_Q	5

sig_atomic_t 	all_RX_threads_done = 0;
sig_atomic_t 	watchdog_event_timer = 0;
sig_atomic_t 	th_rx_up = 0;
char 			available_file_name[MAX_FILE_NAME_LENGTH+1] = {'\0'};


/*********************************/
void add_fd_to_epoll(int fd , uint fd_idx)
{
	int ret;
	PANIC(fd <= 2);

	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;
	fd_db[fd_idx].rx.epoll_arm_events = EPOLLIN /*| EPOLLET | EPOLLONESHOT*/ | EPOLLHUP /*RST*/ | EPOLLRDHUP /*FIN*/;

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx; /*reuse the fd to keep the fd_idx, the fd is passed in the epoll_ctl*/
	rx_th_db[rx_th_idx].epoll.event.events = fd_db[fd_idx].rx.epoll_arm_events;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_ADD, fd, &rx_th_db[rx_th_idx].epoll.event);
	if (ret == -1)
	{
		DBG_TX PRINTF_VZ("epoll_ctl ADD error - %s\n", strerror(errno));
		cntr.warning.epoll_add_ret_errno++;
	}
	fd_db[fd_idx].rx.epoll_state = EPOLL_IN_ADDED;
	DBG_TX PRINTF_VZ("fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd , rx_th_idx);
	return;
}



/*********************************/
void epoll_modify_add_EPOLLIN(uint fd_idx)
{
	int ret;
	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;
	int fd = fd_db[fd_idx].gen.fd;

	/*turn ON only EPOLLIN BIT*/
	fd_db[fd_idx].rx.epoll_arm_events =  (fd_db[fd_idx].rx.epoll_arm_events | EPOLLIN);

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx; /*reuse the fd to keep the fd_idx, the fd is passed in the epoll_ctl*/
	rx_th_db[rx_th_idx].epoll.event.events =  fd_db[fd_idx].rx.epoll_arm_events;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_MOD, fd , &rx_th_db[rx_th_idx].epoll.event);
	if (ret == -1)
	{
		DBG_TX PRINTF_VZ("**ERROR** , failed modify epoll = add , fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd , rx_th_idx);
		//		perror ("EPOLL_CTL_MOD");
		//		PANIC_NO_DUMP(1);
	}
	else
	{
		fd_db[fd_idx].rx.epoll_state = EPOLL_IN_ADDED;
	}
	DBG_RX PRINTF_VZ("fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd , rx_th_idx);
	return;
}


/*********************************/
void epoll_modify_remove_EPOLLHUP (uint fd_idx)
{
	int ret;
	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;

	/*turn off only EPOLLHUP BIT*/
	fd_db[fd_idx].rx.epoll_arm_events = (fd_db[fd_idx].rx.epoll_arm_events &~(uint)EPOLLHUP);

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx; /*reuse the fd to keep the fd_idx, the fd is passed in the epoll_ctl*/
	rx_th_db[rx_th_idx].epoll.event.events = fd_db[fd_idx].rx.epoll_arm_events;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_MOD, fd_db[fd_idx].gen.fd , &rx_th_db[rx_th_idx].epoll.event);
	if (ret == -1)
	{
		PRINTF_VZ("EPOLL_CTL_MOD error - %s\n", strerror(errno));
		PANIC_NO_DUMP(1);
	}
	DBG_RX PRINTF_VZ("fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd_db[fd_idx].gen.fd , rx_th_idx);
	return;
}

/*********************************/
void epoll_modify_remove_EPOLLRDHUP (uint fd_idx)
{
	int ret;
	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;

	/*turn off only EPOLLRDHUP BIT*/
	fd_db[fd_idx].rx.epoll_arm_events =  (fd_db[fd_idx].rx.epoll_arm_events &~(uint)EPOLLRDHUP);

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx; /*reuse the fd to keep the fd_idx, the fd is passed in the epoll_ctl*/
	rx_th_db[rx_th_idx].epoll.event.events = fd_db[fd_idx].rx.epoll_arm_events;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_MOD, fd_db[fd_idx].gen.fd , &rx_th_db[rx_th_idx].epoll.event);
	if (ret == -1)
	{
		//		perror ("EPOLL_CTL_MOD");
		//		PANIC_NO_DUMP(1);
	}

	return;
}

/*********************************/
void epoll_modify_remove_EPOLLIN(uint fd_idx)
{
	int ret;
	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;
	int fd = fd_db[fd_idx].gen.fd;

	/*turn off only EPOLLIN BIT*/
	fd_db[fd_idx].rx.epoll_arm_events =  (fd_db[fd_idx].rx.epoll_arm_events &~(uint)EPOLLIN);

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx; /*reuse the fd to keep the fd_idx, the fd is passed in the epoll_ctl*/
	rx_th_db[rx_th_idx].epoll.event.events = fd_db[fd_idx].rx.epoll_arm_events;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_MOD, fd , &rx_th_db[rx_th_idx].epoll.event);
	if (ret == -1)
	{
		DBG_RX PRINTF_VZ("**ERROR** , errno=%d , failed modify epoll = remove_EPOLLIN , fd_idx=%d , fd=%d , rx_th_idx=%d\n",
				 errno , fd_idx , fd , rx_th_idx);
		PRINTF_VZ("EPOLL_CTL_MOD error - %s\n", strerror(errno));
		PANIC_NO_DUMP(1);
	}
	else
	{
		fd_db[fd_idx].rx.epoll_state = EPOLL_IN_REMOVED;
	}
	DBG_RX PRINTF_VZ("fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd , rx_th_idx);
	return;
}



/*********************************/
void remove_fd_from_epoll(uint fd_idx)
{
	int ret;
	int fd = fd_db[fd_idx].gen.fd;

	if (!fd_db[fd_idx].gen.in_use)
	{
		cntr.warning.try_remove_fd_which_not_in_use++;
		return;
	}

	if (fd <= 2)
	{
		PRINTF_VZ("Try to remove from epoll fd_idx=%d, where fd=%d is <= 2\n", fd_idx , fd );
		PANIC(1);
	}

	cntr.info.tmp_remove_fd_from_epoll++;
	fd_db[fd_idx].rx.epoll_arm_events = 0;
	uint rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;

	rx_th_db[rx_th_idx].epoll.event.data.fd = (int)fd_idx;
	ret = epoll_ctl (rx_th_db[rx_th_idx].epoll.efd, EPOLL_CTL_DEL, fd, &rx_th_db[rx_th_idx].epoll.event);
	if (ret==-1)
	{
		DBG_RX PRINTF_VZ("**FAIL**, %s (errno=%d), fd_idx=%d, fd=%d\n", strerror(errno) , errno ,fd_idx,fd );
		//		perror("remove_fd_from_epoll()");
		//		PANIC(ret==-1);
	}
	DBG_TX PRINTF_VZ("fd_idx=%d , fd=%d , rx_th_idx=%d\n", fd_idx , fd , rx_th_idx);
	return;
}


/*********************************/
void init_RX_slices_per_second(uint fd_idx , uint last_used_slice)
{
	DBG_RX PRINTF_VZ("(fd_idx=%d)Zero rcv slice usage, last_used_slice=%d, run_time.sec=%d,fd_db[fd_idx].bwRx.last_second=%d\n",fd_idx,last_used_slice,run_time.sec,fd_db[fd_idx].bwRx.last_second);
	/*zero all the forward slice_usage in this sec*/
	int i;
	for (i = 0 ; i < NUM_OF_TIME_SLICES ; i++)
	{
		fd_db[fd_idx].bwRx.bwR[i].slice_usage = 0;
		DBG_RX PRINTF_VZ("fd_db[fd_idx=%d].bwRx.bwR[i=%d].slice_usage=%d, slice_limit=%d\n",fd_idx , i ,
				fd_db[fd_idx].bwRx.bwR[i].slice_usage, fd_db[fd_idx].bwRx.bwR[i].slice_limit);
	}
	/*and keep the last second*/
	fd_db[fd_idx].bwRx.last_second = run_time.sec;
}



/***************calc_rcv_size_per_cur_slice******************/
uint calc_rcv_size_per_cur_slice(uint fd_idx , uint last_used_slice)
{
	uint available_rcv_size;

	if (run_time.sec != fd_db[fd_idx].bwRx.last_second)
	{
		init_RX_slices_per_second(fd_idx , last_used_slice);
	}

	if (last_used_slice >= NUM_OF_TIME_SLICES)
	{
		cntr.warning.Illegal_cur_slice++;
		return RCV_BUF_SIZE;
	}

	fd_db[fd_idx].bwRx.last_slice = last_used_slice;
	available_rcv_size = fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_limit - fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_usage;

	if (available_rcv_size > fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_limit || available_rcv_size >= RCV_BUF_SIZE)
	{/*verify that we not receive more then MAX BUF SIZE, if there is anything left, the whil loop will continuew reading it...*/
		//		cntr.Illegal_rcv_size_per_slice++;
		return RCV_BUF_SIZE;
	}

	return available_rcv_size;
}


/***********delete_file_from_disk**********************/
void delete_file_from_disk(char *file_to_del)
{
	if (IS_STRING_SET(file_to_del))
	{
		char cmd[MAX_FILE_NAME_LENGTH + 1];
		DBG_RX PRINTF_VZ("Deleting file from disk =%s\n",file_to_del);
		snprintf(cmd , MAX_FILE_NAME_LENGTH , "rm -f %s" , file_to_del);
		if (system(cmd) == -1)
		{
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):system() error - %s\n",FUNC_LINE, strerror(errno));
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}
}

uint append_src_file_to_dst_file(char *src_file , char *dst_file , uint del_src_after_copy)
{
	int ch;
	FILE* src_fp = fopen(src_file, "r");
	if (!src_fp)
	{
		PRINTF_VZ_N ( "Failed to open src file (%s) for reading, error = %s\n",src_file , strerror(errno));
		PANIC_NO_DUMP(1);
	}
	FILE* dst_fp = fopen(dst_file, "ab+");
	if (!dst_fp)
	{
		PRINTF_VZ_N( "Failed to open dst file (%s) for writing, error = %s\n",dst_file , strerror(errno));
		PANIC_NO_DUMP(1);
	}

	while (1)
	{
		ch = fgetc(src_fp);

		if (ch == EOF)
		{
			break;
		}
		else
		{
			putc(ch, dst_fp);
		}
	}

	fclose (src_fp);
	fclose (dst_fp);

	if (del_src_after_copy)
	{
		if (remove(src_file) != 0)
		{
			PRINTF_VZ_N( "Failed to delete src file (%s), error = %s\n",src_file , strerror(errno));
			PANIC_NO_DUMP(1);
		}
	}
	return TRUE_1;

}
/***********write_to_binary_file**********************/
/*will append to the file*/
uint write_to_binary_file(char* file_name , char *buf , uint length)
{
	uint ret = FALSE_0;

	if (buf == NULL || length<= 0)
	{
		return TRUE_1;
	}


	/*will append to the file*/
	FILE *fp=fopen(file_name, "ab");
	if (fp != NULL)
	{
		if (length > 0)
		{
			if (fwrite(buf, sizeof(char), length , fp) != length)
			{
				DBG_RX PRINTF_VZ("**FAIL** write to file %s, error=%s\n",file_name , strerror(errno));
				ret = FALSE_0;
			}
			else
			{
				DBG_RX PRINTF_VZ("Wrote to file (%s) %d Bytes : %x%x %x%x %x%x...\n",file_name , length,
						buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
				ret = TRUE_1;
			}
		}
		fclose(fp);
	}
	else
	{
		DBG_RX PRINTF_VZ("**FAIL** to open file %s, error=%s\n",file_name , strerror(errno));
	}
	return ret;
}

/***********found_valid_file_name**********************/
char *found_valid_file_name(char *original_filename)
{
	/*verify there is no such file*/
	uint counter = 0 , valid_name = 0;

	if (original_filename == NULL)
	{
		return NULL;
	}

	snprintf(available_file_name , MAX_FILE_NAME_LENGTH , "%s" , original_filename);

	while (!valid_name)
	{
		DBG_RANGE PRINTF_VZ("Trying file name = %s , (orig=%s)\n",available_file_name , original_filename);
		FILE *fp=fopen(available_file_name , "r");
		if (fp != NULL)
		{/*this name exist, add extra number to the name*/
			fclose(fp);
			counter++;
			sprintf(available_file_name, "%s.%d" , original_filename , counter);
			DBG_RANGE PRINTF_VZ("file name in use, will try = %s\n",available_file_name);

		}
		else
		{
			DBG_RANGE PRINTF_VZ("Success found valid file name on disk=%s\n",available_file_name);
			return available_file_name;
		}
	}
	return NULL;
}

/***********create_file_name_rcv_buf**********************/
void create_file_name_rcv_buf(uint fd_idx)
{
	char *valid_file_name = NULL;
	uint name_length = 0;
	char *src_file_name = NULL;
	char index[]={"index.html"};

	if (IS_STRING_SET(fd_db[fd_idx].buf.file_name_rcv_buf))
	{
		return;
	}

	if (IS_STRING_SET(fd_db[fd_idx].gen.dst_direct.file_name_ptr))
	{
		src_file_name = fd_db[fd_idx].gen.dst_direct.file_name_ptr;
	}
	else if (IS_STRING_SET(fd_db[fd_idx].gen.dst_proxy.file_name_ptr))
	{
		src_file_name = fd_db[fd_idx].gen.dst_proxy.file_name_ptr;
	}
	else
	{
		src_file_name = index;
	}

	name_length = (uint)strnlen(src_file_name , MAX_FILE_NAME_LENGTH);
	if ((name_length == 0) || (name_length == MAX_FILE_NAME_LENGTH))
	{
		PRINTF_VZ_N( "Invalide file name\n");
		PANIC_NO_DUMP(1);
	}

	fd_db[fd_idx].buf.file_name_rcv_buf = malloc(name_length + 1);
	if (fd_db[fd_idx].buf.file_name_rcv_buf == NULL)
	{
		PRINTF_VZ_N( "Failed malloc for file_name_rcv_buf (%s)\n", src_file_name);
		PANIC_NO_DUMP(1);
	}

	snprintf(fd_db[fd_idx].buf.file_name_rcv_buf , name_length + 1 , "%s" ,  src_file_name);

	valid_file_name = found_valid_file_name(fd_db[fd_idx].buf.file_name_rcv_buf);
	if (!valid_file_name)
	{
		PRINTF_VZ("**FAIL** to found valid file name, original filename = %s\n", fd_db[fd_idx].buf.file_name_rcv_buf);
		PANIC_NO_DUMP(1);
	}
	else
	{
		snprintf(fd_db[fd_idx].buf.file_name_rcv_buf, MAX_FILE_NAME_LENGTH , "%s" , valid_file_name);
		FILE *fp=fopen(fd_db[fd_idx].buf.file_name_rcv_buf, "w");
		if (fp != NULL)
		{
			fclose(fp);
		}
		else
		{
			PRINTF_VZ("**FAIL** to create file name, filename = %s (original filename=%s)\n", valid_file_name , fd_db[fd_idx].buf.file_name_rcv_buf);
			PANIC_NO_DUMP(1);
		}
	}
	DBG_RX PRINTF_VZ("[%d]Success creating local empty file on disk = %s\n", fd_idx, fd_db[fd_idx].buf.file_name_rcv_buf);
}


/***********rx_to_disk**********************/
uint rx_to_disk(uint fd_idx, uint recv_bytes, char *tmp_buf)
{
	uint ret = FALSE_0, bytes_to_disk;
	http_struct *http_parse = &fd_db[fd_idx].parser.parsed_msg.http;
	char *ptr_to_buf = NULL;

	if ((cfg.flag.save_to_file.val == 0) ||
			(fd_db[fd_idx].rx.wrote_buf_to_disk == 1)/* ||
			((cfg.flag.range.val) && (fd_db[fd_idx].rx.rx_range_handled == 1))*/)
	{/*these flags required so packet will not be handled twice in writing to disk*/
		return TRUE_1;
	}

	DBG_RX PRINTF_VZ("Start: fd_idx=%d , recv_bytes=%d , wrote_buf_to_disk=%d...\n",  fd_idx, recv_bytes , fd_db[fd_idx].rx.wrote_buf_to_disk);

	if (!(IS_STRING_SET(fd_db[fd_idx].buf.file_name_rcv_buf)) && (!cfg.flag.range.val))
	{/*Create new file name */
		create_file_name_rcv_buf(fd_idx);
	}

	/*handling write of RANGE via RX*/
	if (cfg.flag.range.val)
	{
		range_t *range_local = &fd_db[fd_idx].rx.range;
		DBG_RANGE PRINTF_VZ("(%d) range fully received, try writing to disk(start=%"PRIu64",cur=%d,end=%"PRIu64"\n",
				fd_idx, *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);

		if (range_local->pending_range_to_write == RANGE_PENDING_VIA_RX)
		{
			if (range_write_to_disk(fd_idx) == RANGE_PENDING)
			{
				DBG_RANGE PRINTF_VZ("(%d/%d) CANNOT write to disk, pending...(start=%"PRIu64",cur=%d,end=%"PRIu64"\n",
						fd_idx, fd_db[fd_idx].gen.fd , *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
				remove_fd_from_epoll(fd_idx);
				cntr.info.range_pending_move_to_timer_handle++;
			}
			/*success write to disk via RX*/
			else
			{
				DBG_RANGE PRINTF_VZ("(%d/%d) success write to disk (start=%"PRIu64",cur=%d,end=%"PRIu64")\n",
						fd_idx, fd_db[fd_idx].gen.fd , *range_local->range_start , range_local->range_cur_length ,*range_local->range_end);
				cntr.info.tmp_range_wrote_to_disk_via_rx++;
			}
		}
	}

	/*writing to disk only if we already have the http->end*/
	else if ((http_parse) && (http_parse->end))
	{
		/*this is not the first packet, need to be written into rcv_buf*/
		if (fd_db[fd_idx].rx.wrote_buf_from_http_end==0)
		{
			uint http_hdr_length = (uint) (fd_db[fd_idx].parser.parsed_msg.http.end - fd_db[fd_idx].parser.parsed_msg.http.start);
			ptr_to_buf = http_parse->end ;
			bytes_to_disk = (uint)(fd_db[fd_idx].rx.rcv_bytes - http_hdr_length);
			fd_db[fd_idx].rx.wrote_buf_from_http_end = 1;
		}
		else
		{
			ptr_to_buf = tmp_buf;
			bytes_to_disk = recv_bytes;
		}

		/*NEED here better handling for chunks and ranges - not to be written twice*/
		ret = write_to_binary_file(fd_db[fd_idx].buf.file_name_rcv_buf , ptr_to_buf , bytes_to_disk);

		/*mark the flag that we already wrote buf to disk*/
		if (!cfg.flag.range.val)
		{/*for range download, we handle it in handle_rx_range_buf()*/
			fd_db[fd_idx].rx.wrote_buf_to_disk = 1;
		}

	}
	return ret;
}

/***********rx_concatenate_to_rcv_buf**********************/
void rx_concatenate_to_rcv_buf(uint fd_idx, uint recv_bytes, char *tmp_buf)
{
	uint recv_buf_offset = fd_db[fd_idx].parser.rcv_buf_usage;

	if ((fd_db[fd_idx].rx.buffer_full) || ((fd_db[fd_idx].parser.rcv_buf_usage + recv_bytes) >= RCV_BUF_SIZE))
	{
		if (!cfg.flag.save_to_file.val)
		{
			cntr.info.rcv_buf_full_write_to_disk++;
		}
		fd_db[fd_idx].rx.buffer_full = 1;
		DBG_RX PRINTF_VZ("**Warning**-rcv buffer is full,rcv_buf_usage=%d, recv_bytes=%d\n", fd_db[fd_idx].parser.rcv_buf_usage , recv_bytes);
	}
	else
	{
		memcpy(&fd_db[fd_idx].buf.rcv_buf[recv_buf_offset] , tmp_buf , recv_bytes); /*use memcpy and not strncpy, since it ignores the terminating NULL which parser might already inserted...*/
		fd_db[fd_idx].parser.rcv_buf_usage += recv_bytes;
		fd_db[fd_idx].buf.rcv_buf[fd_db[fd_idx].parser.rcv_buf_usage + 1] = '\0';/*add terminating NULL in the end of the string*/
		DBG_RX PRINTF_VZ("Concatenating tmp_buf(len=%d) new total length=%d/%"PRIu64"\n",
				recv_bytes , fd_db[fd_idx].parser.rcv_buf_usage, fd_db[fd_idx].rx.bytes_to_rcv);
	}
}




/*************************/
/***rx_proc_copy_buf***/
/*************************/
uint rx_proc_copy_buf(uint fd_idx, uint recv_bytes, char *tmp_buf , uint recv_to_tmp_buf)
{
	if (recv_to_tmp_buf)
	{
		rx_concatenate_to_rcv_buf(fd_idx, recv_bytes, tmp_buf);
	}
#if 0
	uint ret_rx_to_disk = 0;
	http_struct *http_parse = &fd_db[fd_idx].parser.parsed_msg.http;
	{/*this is not the first packet, need to be written into rcv_buf*/
		if (http_parse->end)
		{/*if we already have the http_parse->end , then simply write all the content into the file*/
			ret_rx_to_disk = rx_to_disk(fd_idx , recv_bytes , tmp_buf);
			if (ret_rx_to_disk == FALSE_0)
			{
				DBG_RX PRINTF_VZ("**FAIL** writing to disk, closing session fd_idx=%d\n", fd_idx);
				close_fd_db(fd_idx , REASON_FAILED_WRITE_TO_DISC);
				return READ_DONE;
			}
			rx_concatenate_to_rcv_buf(fd_idx, recv_bytes, tmp_buf);
		}
		/* http_parse->end not founded yet...*/
		else
		{
			if ((fd_db[fd_idx].parser.rcv_buf_usage + recv_bytes) >= RCV_BUF_SIZE)
			{/*don't have place to receive buf, saving everything to disk, should not get in here...*/
				if (!cfg.flag.save_to_file.val)
				{
					cntr.info.rcv_buf_full_write_to_disk++;
				}
				fd_db[fd_idx].rx.buffer_full = 1;
				DBG_RX PRINTF_VZ("**WARNING**-rcv buffer is full,rcv_buf_usage=%d, recv_bytes=%d, writing all Bytes to disk...\n", fd_db[fd_idx].parser.rcv_buf_usage , recv_bytes);
				ret_rx_to_disk = rx_to_disk(fd_idx , recv_bytes , tmp_buf);
				if (ret_rx_to_disk == FALSE_0)
				{
					DBG_RX PRINTF_VZ("**FAIL** writing to disk, closing session fd_idx=%d\n", fd_idx);
					close_fd_db(fd_idx , REASON_FAILED_WRITE_TO_DISC);
					return READ_DONE;
				}
			}
			else
			{/*concatenate to rcv_buf*/
				rx_concatenate_to_rcv_buf(fd_idx, recv_bytes, tmp_buf);
			}
		}
	}
#endif
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_parse_http***/
/*************************/
uint rx_proc_parse_http(uint fd_idx)
{
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;
	uint ret = READ_NOT_DONE;

	/*parse HTTP*/
	parsed_msg->last_http_parsed_line = http_parse(fd_db[fd_idx].buf.rcv_buf , parsed_msg , fd_db[fd_idx].parser.rcv_buf_usage);
	DBG_PARSER PRINTF_VZ(" last_http_parsed_line=%p --> %s\n", parsed_msg->last_http_parsed_line, parsed_msg->last_http_parsed_line);

	/*analyze the HTTP header*/
	if ((fd_db[fd_idx].parser.parsed_msg.analyzed_http == 0) && (fd_db[fd_idx].parser.parsed_msg.http.end))
	{/*verify we analyze the HTTP only once, otherwise with fragments it will reanalyze packet few times*/
		http_status_code_counters(&fd_db[fd_idx].parser.parsed_msg);

		if ((cfg.flag.range.val) && (range_validate_retrun_code(fd_idx) == FALSE_0))
		{
			DBG_RANGE PRINTF_VZ("[%d]**WARNING** recveived 4xx code , shutting down...\n", fd_idx );
			shutdown_now();
			ret = READ_DONE;
		}

		if (fd_db[fd_idx].parser.parsed_msg.http.set_cookie[0])
		{
			save_cookie_from_reply(&fd_db[fd_idx].parser.parsed_msg , (uint)fd_idx);
		}

		fd_db[fd_idx].parser.parsed_msg.analyzed_http = 1;
	}
	return ret;
}

/*************************/
/***rx_proc_decrypt_payload***/
/*************************/
uint rx_proc_decrypt_payload(uint fd_idx)
{
	/*NOT support yet*/
	DBG_SSL PRINTF_VZ(" fd_idx=%d, start ssl decrypt...\n", fd_idx);
	return READ_NOT_DONE;
}


/*************************/
/***rx_proc_decomp_payload***/
/*************************/
uint rx_proc_decomp_payload(uint fd_idx)
{
	/*parse HTML*/
	if (is_content_length_fully_received(fd_idx) == TRUE_1)
	{
		parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;

		/*handling GZIP decompression*/
		if ((parsed_msg->http.content_encoding) &&
				(strncmp(parsed_msg->http.content_encoding ,  "gzip" , strlen("gzip")) == 0) &&
				(fd_db[fd_idx].rx.bytes_to_rcv == fd_db[fd_idx].rx.rcv_bytes))
		{
			/*will decompress, and extract into extract_buf*/
			PANIC(fd_db[fd_idx].buf.extract_buf == NULL);
			fd_db[fd_idx].buf.extract_buf[0] = '\0';/*zero the first char*/
			fd_db[fd_idx].rx.gzip.extracted_bytes = decompress_gzip(fd_idx , parsed_msg , fd_db[fd_idx].buf.extract_buf);
		}
	}
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_chunks***/
/*************************/
/*NEED TO BE RECHECKED*/
uint rx_proc_chunks(uint fd_idx , uint recv_bytes, char *tmp_buf)
{
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;
	char *payload_ptr = NULL;
	uint bytes_to_process = 0;
	static uint first_time = 1;

	/*Chunks handling*/
	if ((!cfg.flag.chunks_dis.val) && (is_session_chunk(fd_idx) == TRUE_1))
	{

		/*for the FIRST packet we need to point to the http.end ptr*/
		if ((parsed_msg->http.end) && (first_time))
		{
			uint http_hdr_length = (uint) (parsed_msg->http.end - parsed_msg->http.start);
			bytes_to_process = (uint) (fd_db[fd_idx].rx.rcv_bytes - http_hdr_length);
			payload_ptr = parsed_msg->http.end;
			if (!(IS_STRING_SET(fd_db[fd_idx].buf.file_name_rcv_buf)) && (!cfg.flag.range.val))
			{/*Create new file name */
				create_file_name_rcv_buf(fd_idx);
			}
			first_time = 0;
		}
		else
		{/*not first packet*/
			bytes_to_process = recv_bytes;
			payload_ptr = tmp_buf;
		}
		if (handle_rx_chunk_buf(fd_idx, bytes_to_process, payload_ptr) ==  SUCCESS_FOUND_LAST_CHUNK_4)
		{
			shutdown_now();
			return READ_DONE;
		}
	}
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_ranges***/
/*************************/
/*NEED TO BE RECHECKED*/
uint rx_proc_ranges(uint fd_idx , uint recv_bytes, char *tmp_buf)
{
	/*ranges handling*/
	if ((cfg.flag.range.val) && (is_session_range(fd_idx) == TRUE_1))
	{
		handle_rx_range_buf(fd_idx, recv_bytes, tmp_buf);
	}
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_save_to_disk***/
/*************************/
/*NOT WORK YET - NEED TO BE RECHECKED*/
uint rx_proc_save_to_disk(uint fd_idx , uint recv_bytes, char *tmp_buf)
{
	if (is_session_chunk(fd_idx) == FALSE_0)
	{
		rx_to_disk(fd_idx, recv_bytes, tmp_buf);
	}
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_parse_html***/
/*************************/
uint rx_proc_parse_html(uint fd_idx)
{
	/*don't need to do html parse for ranges*/
	if (cfg.flag.range.val)
	{
		return READ_NOT_DONE;
	}
	/*parse HTML*/
	if (is_content_length_fully_received(fd_idx) == TRUE_1)
	{
		uint http_hdr_length = 0;
		parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;
		char *html_start = parsed_msg->http.end ;
		uint html_max_chars_to_parse = (uint)(atoi(fd_db[fd_idx].parser.parsed_msg.http.content_length));

		/*Update html_max_chars_to_parse in case rcv_buffer is full*/
		if (fd_db[fd_idx].rx.buffer_full)
		{
			http_hdr_length = (uint)(fd_db[fd_idx].parser.parsed_msg.http.end - fd_db[fd_idx].parser.parsed_msg.http.start);
			html_max_chars_to_parse = fd_db[fd_idx].parser.rcv_buf_usage - http_hdr_length;
		}

		/*gzip extracted*/
		if ((fd_db[fd_idx].buf.extract_buf) && (fd_db[fd_idx].rx.gzip.extracted_bytes))
		{
			html_start = fd_db[fd_idx].buf.extract_buf;
			html_max_chars_to_parse = fd_db[fd_idx].rx.gzip.extracted_bytes;
		}

		/*HTML parse*/
		parsed_msg->last_html_parsed_tag = html_parse(html_start , parsed_msg , html_max_chars_to_parse);
	}
	return READ_NOT_DONE;
}

/*************************/
/***rx_proc_analyze_content***/
/*************************/
uint rx_proc_analyze_content(uint fd_idx)
{
	return rx_analyze_payload_content(fd_idx);
}

/*************************/
/***rx_proc_pkt_main***/
/*************************/
uint rx_proc_pkt_main(uint fd_idx, uint recv_bytes, char *tmp_buf , uint recv_to_tmp_buf)
{
	uint read_done = READ_NOT_DONE /*, ret_rx_to_disk = 0*/;
	int fd = fd_db[fd_idx].gen.fd;

	fd_db[fd_idx].rx.rcv_bytes += recv_bytes;
	fd_db[fd_idx].rx.wrote_buf_to_disk = 0;
	//	fd_db[fd_idx].rx.rx_range_handled = 0;
	char *payload_ptr = recv_to_tmp_buf ? tmp_buf : fd_db[fd_idx].buf.rcv_buf;

	/*Prints...*/
	DBG_RX PRINTF_VZ_N("==============NEW RX packet=============================\n");
	DBG_RX PRINTF_VZ("(fd=%d) (recv_to_tmp_buf=%d)new_recv_bytes=%d, total rcv_bytes=%"PRIu64"/%"PRIu64"\n",
			 fd , recv_to_tmp_buf ,recv_bytes, fd_db[fd_idx].rx.rcv_bytes, fd_db[fd_idx].rx.bytes_to_rcv);
	DBG_RX PRINTF_VZ("RX pkt:\n%s\n",payload_ptr);

	/*copy / concatenate from tmp_buf into rcv buf*/
	if (rx_proc_copy_buf(fd_idx, recv_bytes,  payload_ptr , recv_to_tmp_buf)== READ_DONE)
	{
		return READ_DONE;
	}

	/*parse HTTP headers*/
	if (rx_proc_parse_http(fd_idx)== READ_DONE)
	{
		return READ_DONE;
	}

	/*SSL decryption - not support yet*/
	if (rx_proc_decrypt_payload(fd_idx)== READ_DONE)
	{
		return READ_DONE;
	}

	if (rx_proc_decomp_payload(fd_idx)== READ_DONE)
	{
		return READ_DONE;
	}

	if (rx_proc_chunks(fd_idx , recv_bytes, payload_ptr)== READ_DONE)
	{
		return READ_DONE;
	}

	if (rx_proc_ranges(fd_idx , recv_bytes, payload_ptr)== READ_DONE)
	{
		return READ_DONE;
	}

	/*saving content to disk before pkt get trashed*/
	if (rx_proc_save_to_disk(fd_idx , recv_bytes, payload_ptr)== READ_DONE)
	{
		return READ_DONE;
	}

	/*parsing the HTML will trash the packet so it should be after saving content to disk*/
	if (rx_proc_parse_html(fd_idx)== READ_DONE)
	{
		return READ_DONE;
	}

	if (rx_proc_analyze_content(fd_idx)== READ_DONE)
	{
		return READ_DONE;
	}

	return read_done;

}



/***********update_rcv_slice_usage**********************/
uint update_rcv_slice_usage(uint fd_idx , uint recv_bytes , uint last_used_slice)
{

	PANIC(last_used_slice >= NUM_OF_TIME_SLICES);
	fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_usage += recv_bytes;
	if (fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_usage < fd_db[fd_idx].bwRx.bwR[last_used_slice].slice_limit)
	{
		return READ_NOT_DONE; /*continue reading from socket read_done = 0*/
	}

	return READ_DONE; /*stop reading from socket - read_done = 1*/
}


/*************************/
/***rx_check_rcv_Q***/
/*************************/
int rx_check_rcv_Q(uint fd_idx)
{
	int bytes_in_queue = 0;

	if ( ioctl (fd_db[fd_idx].gen.fd ,FIONREAD, &bytes_in_queue) < 0 )
	{
		DBG_RX PRINTF_VZ("errno=%d\n",errno);
		return errno;
	}

	return bytes_in_queue;
}


/*************************/
/***read_from_socket***/
/*************************/
void read_from_socket(uint fd_idx , uint events , uint last_used_slice)
{
	uint read_done = 0;
	char tmp_buf[RCV_BUF_SIZE + 1];
	static uint tmp_cntr = 0; /*xxx - tbr*/
	PANIC(fd_idx >= max_active_sessions);

	int fd = fd_db[fd_idx].gen.fd;
	tmp_cntr++;

	if (fd <= 2)
	{/*verify legal FD*/
		cntr.error.try_to_read_illegal_fd++;
		read_done = 1;/*Don't read from FD - it stuck evertything...*/
		//		char tmp_str[500];
		//		sprintf(tmp_str , "%s(%d):try_to_read_illegal_fd(%d),fd_idx=%d,fd=%d, in_use=%d,events=%d,last_used_slice=%d\n",cntr.try_to_read_illegal_fd,fd_idx,fd, fd_db[fd_idx].gen.in_use,events, last_used_slice);
		//		print_to_file(tmp_str);
		//		close_fd_db(fd_idx , 1);
	}
	else if (fd_db[fd_idx].gen.state == STATE_CLOSE)
	{
		cntr.warning.try_to_read_write_from_closing_socket++;
		//		epoll_modify_remove_EPOLLIN(fd_idx); /*test*/
		remove_fd_from_epoll(fd_idx); /*test*/
		return;
	}


	/*try to aquire tx_rx_lock*/
	if (pthread_mutex_trylock(&fd_db[fd_idx].gen.tx_rx_mutex) == 0)
	{
		verify_buf_guards(fd_idx);
		while (!read_done)
		{
			ssize_t recv_bytes = 0;
			uint avail_rcv_size = RCV_BUF_SIZE;
			uint recv_to_tmp_buf = 0; /*flag to mark that content received into tmp_buf*/

			if (cfg.int_v.bw_rx_limit.val)
			{
				avail_rcv_size = calc_rcv_size_per_cur_slice(fd_idx , last_used_slice);
				DBG_RX PRINTF_VZ("avail_rcv_size = %d, fd_idx=%d, last_used_slice=%d\n",avail_rcv_size, fd_idx, last_used_slice);
			}

			DBG_RX PRINTF_VZ("TMP - fd_idx=%d, avail_rcv_size=%d, tmp_cntr=%d, \n", fd_idx ,avail_rcv_size, tmp_cntr); /*xxx - tbr*/

			if (avail_rcv_size > 0)
			{
				if (fd_db[fd_idx].ssl_db.is_ssl)
				{/*SSL*/
					/*the call back of the SSL need this mutex*/
					pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);
					if (fd_db[fd_idx].buf.rcv_buf[0] != '\0')
					{/*buf already in use, rcv to tmp_buf, and then concatenate to rcv_buf*/
						recv_bytes = mbedtls_ssl_read(&fd_db[fd_idx].ssl_db.ssl , (unsigned char *)tmp_buf, avail_rcv_size /*sizeof(tmp_buf)*/);	/* get reply & decrypt */
						recv_to_tmp_buf = 1;
						//						DBG_RX printf("\n%s(%d):(fd_idx=%d, fd=%d)RX-continue, ssl_read, recv_bytes=%d\n", fd_idx , fd, recv_bytes);
					}
					else
					{/*rcv_buf is available*/
						recv_bytes = mbedtls_ssl_read(&fd_db[fd_idx].ssl_db.ssl , (unsigned char *)fd_db[fd_idx].buf.rcv_buf, avail_rcv_size /*sizeof(fd_db[fd_idx].buf.rcv_buf)*/);	/* get reply & decrypt */
						fd_db[fd_idx].parser.rcv_buf_usage = (uint)recv_bytes; /*we cannot use strlen since we parser insert \0 which terminate  the lines, and strlen then give false length*/
						//						DBG_RX printf("\n%s(%d):(fd_idx=%d, fd=%d)RX-1st pkt, ssl_read, recv_bytes=%d\n", fd_idx , fd,recv_bytes);
					}
					/*need to take it again, so processing the content will be with mutex*/
					//					pthread_mutex_lock(&fd_db[fd_idx].gen.tx_rx_mutex);
					DBG_RX PRINTF_VZ("TMP - fd_idx=%d, read - recv_bytes=%zd , errno = %d\n", fd_idx ,recv_bytes, errno); /*xxx - tbr*/
				}
				else
				{/*normal TCP*/
					if (fd_db[fd_idx].buf.rcv_buf[0] != '\0')
					{/*buf already in use, rcv to tmp_buf, and then concatenate to rcv_buf*/
						recv_bytes = read(fd, tmp_buf, avail_rcv_size);
						recv_to_tmp_buf = 1;
					}
					else
					{/*rcv_buf is available*/
						recv_bytes = read(fd, fd_db[fd_idx].buf.rcv_buf, avail_rcv_size);
						fd_db[fd_idx].parser.rcv_buf_usage = (uint)recv_bytes;
					}
				}


				/****Finished reading from socket, start analysing date****/

				watchdog_event_timer = WATCHDOG_TIMER_IN_SEC; /*ReArm watchdog*/
				if (cfg.int_v.bw_rx_limit.val)
				{
					read_done = update_rcv_slice_usage(fd_idx , (uint)recv_bytes , last_used_slice);
				}

				if (/*recv_bytes == -1*/ recv_bytes < 0)
				{/* If errno == EAGAIN, that means we have read all data. So go back to the main loop. */
					if (errno != EAGAIN)
					{
						DBG_RX PRINTF_VZ("recv_bytes = %zd, errno=%d\n",recv_bytes, errno);
						close_fd_db(fd_idx , REASON_RX_READ_ERROR);
						read_done = 1;
					}
					else
					{
						//						DBG_RX perror("read errno=EAGAIN");
						DBG_RX PRINTF_VZ("read errno=EAGAIN : %s\n",strerror(errno));
						//						cntr.read_err_eAgain++;
						read_done = 1;
					}
				}
				else if (recv_bytes == 0)
				{/* End of file. The Server has closed the connection. */
					cntr.info.tmp_rcv_bytes_0++;
					if ((events == 0) && (cfg.int_v.bw_rx_limit.val))
					{/*we might get in here from bwr where we don't know if reached to the end of the content to read*/
						read_done = 1;
					}
					else
					{
						if (fd_db[fd_idx].rx.rcv_bytes != 0) /*test*/
						{
							remove_fd_from_epoll(fd_idx);
							close_fd_db(fd_idx , REASON_RX_EOF);
						}
						read_done = 1;
					}
				}
				else if (recv_bytes > 0)
				{/*Process the payload*/
					cntr.stat.RX_bytes += (int)recv_bytes;
					read_done = rx_proc_pkt_main(fd_idx , (uint)recv_bytes , tmp_buf , recv_to_tmp_buf);
					tmp_buf[0]='\0';
					if (read_done) {
						DBG_RX PRINTF_VZ("finished rx_proc_pkt_main(), read_done=%d\n",read_done);
					}
				}
			}
			else
			{/*avail_rcv_size = 0*/
				epoll_modify_remove_EPOLLIN(fd_idx);/*remove the fd from epoll, so it'll not bather us, will be rearmed every 100 msec*/
				read_done = 1;
			}
		} /*end of while loop*/
		verify_buf_guards(fd_idx);

		if (!fd_db[fd_idx].ssl_db.is_ssl)
		{
			pthread_mutex_unlock(&fd_db[fd_idx].gen.tx_rx_mutex);
		}
		/*in case we created packet to be sent, send it now(done to prevent dead locks*/
		if (PENDING_TX_LEN(fd_idx))
		{
			tx_now(fd_db[fd_idx].tx.tx_th_idx);
		}
		return;
	}
	else
	{
		//		DBG_RX PRINTF_VZ("**FAIL** to aquire tx_rx_mutex, fd_idx=%d,\n", fd_idx);
		cntr.info.skip_read_from_socket_due_to_mutex_lock++;
		return;
	}
}


/***************read_bwr_sockets******************/
void read_bwr_sockets(uint last_used_slice)
{
	uint fd_idx;

	DBG_RX PRINTF_VZ("last_used_slice=%d\n",last_used_slice);

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if ((fd_db[fd_idx].gen.in_use) &&
				(fd_db[fd_idx].rx.epoll_state == EPOLL_IN_REMOVED) &&
				(fd_db[fd_idx].ds_db.cur_cmd != DS_CMD_WAIT))
		{
			epoll_modify_add_EPOLLIN(fd_idx);
		}
	}
}


/*************check_close_delay_sockets********************/
void check_close_delay_sockets(uint last_used_sec)
{
	uint fd_idx;

	DBG_RX PRINTF_VZ("last_used_sec=%d\n",last_used_sec);

	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
		if ((fd_db[fd_idx].gen.in_use) && (fd_db[fd_idx].gen.state == STATE_CLOSE) && (fd_db[fd_idx].rx.close_time == last_used_sec))
		{
			close_fd_db(fd_idx , REASON_FINISHED_PROCESS_SOCKET);
		}
	}
}


/*************handle_timer_events********************/
static void handle_timer_events(uint *last_used_slice , uint *last_used_sec , uint my_RX_th_idx)
{
	uint tmp_skip_check_stuck = 0;
	/*handle 1 sec events*/
	if (*last_used_sec != run_time.sec)
	{
		*last_used_sec = run_time.sec;
		if (cfg.int_v.delay_close_sec.val)
		{
			check_close_delay_sockets(*last_used_sec);
		}
		if (cfg.flag.range.val)
		{
			if (!tmp_skip_check_stuck)
			{
				range_check_stuck_sockets(my_RX_th_idx);
			}
		}
	}

	/*Handle BWR sockets every 100msec*/
	if (*last_used_slice != run_time.slice_100_msec)
	{/*read pending IDXs*/
		if (run_time.slice_100_msec > (*last_used_slice +1))
		{
			cntr.info.tmp_large_slice_delta++;
		}
		*last_used_slice = run_time.slice_100_msec;
		if (cfg.int_v.bw_rx_limit.val)
		{
			read_bwr_sockets(*last_used_slice);
		}
	}
}


/***********handle_epoll_hangout_events**********************/

uint handle_epoll_hangout_events(uint fd_idx , uint32_t cur_events , int num_of_events)
{
	/*Handle epoll sockets*/
	if ((cur_events & EPOLLERR) ||
			(cur_events & EPOLLHUP /*RST*/) ||
			(cur_events & EPOLLRDHUP /*FIN*/) ||
			(!(cur_events & EPOLLIN)))
	{/* An error has occured on this fd, or the socket is not ready for reading (why were we notified then?) */
		/*verify we not closing already closed fd, need to think on better check to verify we close the correct FD */
		if (fd_db[fd_idx].gen.state == STATE_READY)
		{/*if we get here, it's a problem, since don't know what fd to delete*/
			cntr.warning.epoll_hangup_on_unused_fd_in_state_ready++;
			return WHILE_RET_CONTINUE;
		}

		if (fd_db[fd_idx].gen.state == STATE_CLOSE)
		{
			cntr.warning.epoll_hangup_on_unused_fd_in_state_close++;
			remove_fd_from_epoll(fd_idx);
			return WHILE_RET_CONTINUE;
		}

		if (cur_events & EPOLLERR)
		{
			DBG_RX PRINTF_VZ("(fd_idx=%d),cur_events=0x%x, erron=%s\n",fd_idx , cur_events , strerror(errno));
			//			DBG_RX perror ("epoll_wait()\n");
			close_fd_db(fd_idx , REASON_RX_EPOLL_ERROR);
			//			cntr.error.epoll_error++;
			return WHILE_RET_CONTINUE;
		}
		else if (cur_events & EPOLLHUP)
		{/*RST*/
			DBG_RX PRINTF_VZ("(fd_idx=%d),epoll HangUp (probably RST), event=-0x%x\n",fd_idx , cur_events);
			DBG_DS fprintf (stderr, "[socket=%d closed by remote (probably RST)]\n",fd_db[fd_idx].gen.fd);

			int bytes_in_rcv_q = 0;
			if ((bytes_in_rcv_q = rx_check_rcv_Q(fd_idx)) > 0)
			{
				DBG_RX PRINTF_VZ("(fd_idx=%d)More Bytes on rcvQ (%d), continue reading from socket , (num_of_events=%d)\n",fd_idx , bytes_in_rcv_q, num_of_events);
				epoll_modify_remove_EPOLLHUP(fd_idx);
			}
			else
			{
				close_fd_db(fd_idx , REASON_RX_TCP_RST);
				return WHILE_RET_CONTINUE;
			}
		}
		else if (cur_events & EPOLLRDHUP)
		{/*FIN*/
			int bytes_in_rcv_q = 0;
			DBG_RX PRINTF_VZ("(fd_idx=%d),epoll EPOLLRDHUP (probably FIN) , event=-0x%x\n",fd_idx , cur_events);
			DS_PRINT fprintf (stderr, "[%s][socket=%d (fd_idx=%d) closed by remote (probably FIN)]\n",elapse_time,fd_db[fd_idx].gen.fd ,fd_idx);
			if ((bytes_in_rcv_q = rx_check_rcv_Q(fd_idx)) > 0)
			{
				DBG_RX PRINTF_VZ("(fd_idx=%d)More Bytes on rcvQ (%d), continue reading from socket , (num_of_events=%d)\n",fd_idx , bytes_in_rcv_q, num_of_events);
				epoll_modify_remove_EPOLLRDHUP(fd_idx);
			}
			else
			{
				if (cfg.flag.range.val)
				{
					epoll_modify_remove_EPOLLRDHUP(fd_idx);
				}
				close_fd_db(fd_idx , REASON_RX_TCP_FIN);
				return WHILE_RET_CONTINUE;
			}
		}
	}
	return WHILE_RET_NOTHING;
}

/***********thread_RX**********************/
void *thread_RX(void *arg)
{
	//	 my_RX_th_idx = /*(int)arg*/ 0;
	RX_gen_t *rx_gen = arg;
	uint my_RX_th_idx = (uint)rx_gen->local_RX_th_idx;

	uint last_used_slice=0 , last_used_sec=0;
	uint all_sockets_done = 0;

	rx_th_db[my_RX_th_idx].epoll.efd = epoll_create1 (0);
	if (rx_th_db[my_RX_th_idx].epoll.efd == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):epoll_create error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	rx_th_db[my_RX_th_idx].epoll.events = calloc (MAXEVENTS, sizeof rx_th_db[my_RX_th_idx].epoll.event);

	th_rx_up++;
	while (!all_sockets_done)
	{
		int num_of_events, i;
		num_of_events = epoll_wait (rx_th_db[my_RX_th_idx].epoll.efd, rx_th_db[my_RX_th_idx].epoll.events, MAXEVENTS, 10);

		if (num_of_events < 0)
		{
			DBG_RX PRINTF_VZ(" **FAIL** epoll_wait errno, num_of_events = %d (%s)\n",num_of_events , strerror(errno));
			//			exit(EXIT_FAILURE); /*if enable this line the debugger fly here, need to mask it in case of debugger...*/
		}

		/*Handle timer events*/
		handle_timer_events(&last_used_slice , &last_used_sec , my_RX_th_idx);

		/*Handle epoll sockets*/
		for (i = 0; i < num_of_events ; i++)
		{
			uint32_t cur_events = rx_th_db[my_RX_th_idx].epoll.events[i].events;
			uint fd_idx = (uint)rx_th_db[my_RX_th_idx].epoll.events[i].data.fd; /*reusing the fd to keep the fd_idx*/

			if (num_of_events > 0)
			{
				if (handle_epoll_hangout_events(fd_idx , cur_events, num_of_events) == WHILE_RET_CONTINUE)
				{
					continue;
				}

				/* We have data on the fd waiting to be read*/
				read_from_socket(fd_idx , cur_events , last_used_slice);
			}
		}/*finish epoll loop*/

		/*verify all sockets done & TX threads are down*/
		if (((cntr.stat.open_sockets == cfg.int_v.num_of_session.val) &&
				(cntr.stat.open_sockets == cntr.stat.close_sockets) &&
				(cntr.stat.TX_threads == 0))	||
				(shut_down_now))
		{/*finish --> exit*/
			DBG_RX printf("\n%s(%d):RX - all sockets done(%d)-exiting, open=%d, num_of_session=%d\n",FUNC_LINE,cntr.stat.close_sockets,cntr.stat.open_sockets,cfg.int_v.num_of_session.val);
			all_sockets_done=1;
		}
	}

	all_RX_threads_done ++;
	DBG_RX	PRINTF_VZ("RX thread done, cntr.TX_threads=%d, exiting...\n",cntr.stat.TX_threads);
	pthread_exit(NULL);
	return(0);
}

/***********thread_RX_accept**********************/
void *thread_RX_listener()
{
	int fd_listener, new_fd , optval=1;
	struct sockaddr_in serv_addr, client_addr;
	socklen_t client_len = sizeof(client_addr);

	fd_listener = socket((int)ip_ver, SOCK_STREAM, IPPROTO_TCP);
	if (fd_listener < 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):ERROR creating fd_listener - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*Reuse address*/
	if (setsockopt(fd_listener , SOL_SOCKET, SO_REUSEADDR ,&optval , sizeof(optval)) < 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):setsockopt SO_REUSEADDR() error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = (ushort)ip_ver;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons((ushort)cfg.int_v.port.val);

	if (bind(fd_listener, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		char bind_ip_addr[INET6_ADDRSTRLEN+1] = {'\0'};
		inet_ntop(serv_addr.sin_family , &(serv_addr.sin_addr.s_addr) , bind_ip_addr , INET6_ADDRSTRLEN);
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):**FAIL** bind listening to %s : %d, probably other application occupies it... error = %s\n",FUNC_LINE,
				bind_ip_addr , cfg.int_v.port.val, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	if (listen(fd_listener , LISTENER_BACKLOG_Q) < 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):listen error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	while (all_RX_threads_done != cfg.int_v.rx_num_of_threads.val)
	{
		new_fd = accept(fd_listener, (struct sockaddr *) &client_addr, &client_len);
		if (new_fd < 0)
		{
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):accept error - %s\n",FUNC_LINE, strerror(errno));
			exit_vz(EXIT_FAILURE, exit_buf);
		}

		/*get_available_tx_thread*/
		if (accept_new_fd(new_fd) != TRUE_1)
		{/***FAIL** to found available TX thread*/
			DBG_LISTEN	PRINTF_VZ("**FAIL** to found available TX thread, closing socket %d\n",new_fd);
			close(new_fd);
		}
		else
		{
			DBG_LISTEN	PRINTF_VZ("Success accepted new_fd=%d\n", new_fd);
		}
	}

	close(fd_listener);
	DBG_LISTEN	PRINTF_VZ("thread_RX_accept done, exiting...\n");

	return(0);/*Don't use pthread_exit, since then it kill's all sockets related to this thread...*/
}



/*********************************/
void RX_threads_creator()
{
	int rx_th_idx;

	for (rx_th_idx=0 ; rx_th_idx<cfg.int_v.rx_num_of_threads.val ; rx_th_idx++)
	{
		DBG_RX PRINTF_VZ("RX_threads_creator(%d)\n", rx_th_idx);

		rx_th_db[rx_th_idx].gen.active = 1;
		rx_th_db[rx_th_idx].gen.local_RX_th_idx = rx_th_idx;

		/*RX thread*/
		if (pthread_create(&rx_th_db[rx_th_idx].gen.RX_th_id , NULL, thread_RX, /*(void *)rx_th_idx*/ &(rx_th_db[rx_th_idx].gen)) != 0)
		{
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() for thread thread_RX error - %s\n",FUNC_LINE, strerror(errno));
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}
}




