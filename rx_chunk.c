/* rx_chunk.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  rx_chunk.c is part of vazaget.
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
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <wchar.h>
#include <locale.h>     /* struct lconv, setlocale, localeconv */
#include "global.h"
#include "rx.h"
#include "prints.h"
#include "config.h"

#define CHUNK_BUF_TMP_FILE "chunk_buf_tmp_file"
#define CHUNK_BUF_TMP_FILE_2 "chunk_buf_tmp_file_2"

/*how chunk works
 * http header cannot tell the exact length the HTTP payload is going to be.
 * so it build the content from chunks, where every chunk start with number that represent the chunk length
 * so we copy the recv data to chunk buf
 * the chunk_buf[0] have to point to the beginning of the ascii number that represent the chunk length
 * then we process the chunk buf
 * find chunk data start, right after the chunk length,
 * write it to the disk (without the chunk length)
 * then delete this chunk from chunk_buf using memmove
 * and process next chunk (chunk_buf[0]).
 *
 * to be honest, I don't like this mechanism, it's complicate, hard to debug, and memove is expansive - but it works now.
 * once I'll have timje, I'll change it to link list, where I put every chunk on link list,
 * once finish, release the chunk, without free the malloc, so I will be able to use it again,
 * then I don't need to do the memmove
 * and seems to be easier to debug...*/




/***********dbg_print_to_file_chunk_buf**********************/
void dbg_print_to_file_chunk_buf(char *chunk_buf)
{
	char cmd[MAX_FILE_NAME_LENGTH + 1];
	void* tmp_fp = fopen(CHUNK_BUF_TMP_FILE , "w");
	if (tmp_fp == NULL)
	{
		return;
	}

	DBG_FILE print_to_file_name(CHUNK_DBG_FILE , "---Printing chunk buf content---\n");
	/*write chunk buf into file*/
	fprintf(tmp_fp , "%s" , chunk_buf);
	fclose (tmp_fp);

	/*print the chunk buf in hex format*/
	snprintf(cmd , MAX_FILE_NAME_LENGTH , "hexdump %s -C > %s" , CHUNK_BUF_TMP_FILE , CHUNK_BUF_TMP_FILE_2);
	if (system(cmd) == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):system() error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*append it to debug file*/
	snprintf(cmd , MAX_FILE_NAME_LENGTH , "cat %s >> %s" , CHUNK_BUF_TMP_FILE_2 , CHUNK_DBG_FILE);
	if (system(cmd) == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):system() error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*del tmp files*/
	snprintf(cmd , MAX_FILE_NAME_LENGTH , "rm %s %s" , CHUNK_BUF_TMP_FILE , CHUNK_BUF_TMP_FILE_2 );
	if (system(cmd) == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):system() error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}

/***********is_session_chunk**********************/
uint is_session_chunk(uint fd_idx)
{
	parser_struct *parsed_msg = &fd_db[fd_idx].parser.parsed_msg;

	if ((parsed_msg->http.transfer_encoding) &&
			/*(strncmp(parsed_msg->http.transfer_encoding ,  "chunked" , strlen("chunked")) == 0)*/
			(strnstr(parsed_msg->http.transfer_encoding ,  "chunked" , (strlen("chunked") + 4)) != NULL))
	{
		return TRUE_1;
	}
	return FALSE_0;
}


/***********update_chunk_malloc_size**********************/
uint update_chunk_malloc_size (uint fd_idx , uint new_size)
{
	if (new_size > MAX_CHUNK_BUF_SIZE)
	{
		PRINTF_VZ("**Warning** new_size(%d) > MAX_CHUNK_BUF_SIZE (%d)\n" , new_size , MAX_CHUNK_BUF_SIZE);
		cntr.warning.chunk_buf_reached_max_size++;
		erase_all_chunk_data(fd_idx , TRUE_1);
		return FALSE_0;
	}

	if (new_size > fd_db[fd_idx].rx.chunk.size_of_buf)
	{ /*first time buffer allocation*/
		DBG_RX PRINTF_VZ("Realloc chunk_buf(%p): from size %d to %d\n" , fd_db[fd_idx].buf.chunk_buf, fd_db[fd_idx].rx.chunk.size_of_buf , new_size);
		fd_db[fd_idx].buf.chunk_buf = realloc(fd_db[fd_idx].buf.chunk_buf , new_size+1);
		if (fd_db[fd_idx].buf.chunk_buf  == NULL)
		{/***FAIL** calloc*/
			PRINTF_VZ(" **FAIL** realloc() : %s\n" , strerror(errno));
			cntr.warning.chunk_failed_malloc++;
			erase_all_chunk_data(fd_idx , TRUE_1);
			return FALSE_0;
		}
		fd_db[fd_idx].rx.chunk.size_of_buf = new_size;
		DBG_RX PRINTF_VZ("Success Realloc chunk_buf(%p) to %d\n" , fd_db[fd_idx].buf.chunk_buf, fd_db[fd_idx].rx.chunk.size_of_buf);
	}
	return TRUE_1;
}

/***********copy_tmp_buf_into_chunk_buf**********************/
uint copy_tmp_buf_into_chunk_buf(uint fd_idx, uint recv_bytes, char *tmp_buf)
{
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;

	DBG_RX PRINTF_VZ(" Going to copy %d Bytes , to cur buf %d\n" ,
			recv_bytes , chunk->buf_usage );

	/*verfiy we have enough space on chunk_buf*/
	if ((chunk->buf_usage + recv_bytes) > chunk->size_of_buf)
	{
		DBG_RX PRINTF_VZ(" (chunk.buf_usage(%d)+recv_bytes(%d)) > size_of_buf(%d) , increasing buf size\n" ,
				chunk->buf_usage , recv_bytes , chunk->size_of_buf);

		if (update_chunk_malloc_size(fd_idx , (chunk->buf_usage + recv_bytes)) == FALSE_0)
		{
			return FALSE_0;
		}
	}

	memcpy(&fd_db[fd_idx].buf.chunk_buf[chunk->buf_usage] , tmp_buf , recv_bytes); /*use memcpy and not strncpy, since it ignores the terminating NULL which parser might already inserted...*/
	chunk->buf_usage += recv_bytes;

	DBG_RX PRINTF_VZ("Concatenating tmp_buf(len=%d) new chunk_buf usage =%d/%d\n",
			recv_bytes , chunk->buf_usage , chunk->size_of_buf);

	return TRUE_1;
}

/***********erase_all_chunk_data**********************/
void erase_all_chunk_data(uint fd_idx, uint stop_procsess_chunks)
{
	DBG_RX PRINTF_VZ("Start , fd_idx=%d, stop_procsess_chunks=%d\n" , fd_idx , stop_procsess_chunks );
	memset(&fd_db[fd_idx].rx.chunk , 0 , sizeof(fd_db[fd_idx].rx.chunk));
	if (fd_db[fd_idx].buf.chunk_buf)
	{
		free(fd_db[fd_idx].buf.chunk_buf);
	}
	fd_db[fd_idx].buf.chunk_buf = NULL;

	if (stop_procsess_chunks)
	{
		cntr.warning.chunk_stop_processing++;
		cfg.flag.chunks_dis.val = FALSE_0;
		cfg.flag.chunks_dis.config_mode = OVERWRITE_CFG;
	}


}

/***********parse_chunk_handle_close_CR**********************/
uint parse_chunk_handle_close_CR(uint fd_idx)
{
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;

	/*Closing CR - need to verify that this is CR of the end of the chunk, and not CR inside chunk*/
	DBG_RX PRINTF_VZ("Reached to CR, after found OPEN LF, last_parsed_ch=%d , data_start_offset=%d , cur_chunk_length=%d\n",
			 chunk->last_parsed_ch,
			chunk->cur_chunk_data_start_offset,
			chunk->cur_chunk_length);
	if ((chunk->last_parsed_ch - (chunk->cur_chunk_data_start_offset-1)) >=  chunk->cur_chunk_length)
	{
		DBG_RX PRINTF_VZ("Found CLOSE CR, ch = %d\n", chunk->last_parsed_ch);
		chunk->cur_chunk_data_end_offset = chunk->last_parsed_ch;
		chunk->cur_chunk_parse_state = CHUNK_PARSE_CLOSE_CR_FOUND;
		if ((chunk->cur_chunk_data_end_offset - chunk->cur_chunk_data_start_offset) > (chunk->cur_chunk_length + 20))
		{
			DBG_RX PRINTF_VZ("**FAIL** LAST LF offset (end(%d)-start(%d)=%d)is not equal to length(%d)\n"
					, chunk->cur_chunk_data_end_offset
					, chunk->cur_chunk_data_start_offset
					, (chunk->cur_chunk_data_end_offset - chunk->cur_chunk_data_start_offset)
					, chunk->cur_chunk_length);
			DBG_RX PRINTF_VZ_N("end-2=0x%x , end-1=0x%x , end=0x%x , end+1=0x%x , end+2=0x%x , end+3=0x%x\n",
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch - 2] ,
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch - 1] ,
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch - 0] ,
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 1] ,
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 2] ,
					fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 3]);
			cntr.warning.chunk_failed_parse_close_CR_offsset++;
			erase_all_chunk_data(fd_idx , TRUE_1);
			return FALSE_0;
		}
		else
		{
			DBG_RX PRINTF_VZ("SUCCESS validate Trailer LF offset (end(%d)-start(%d)=%d)is not more then 10 Bytest bigger then length(%d)\n"
					, chunk->cur_chunk_data_end_offset
					, chunk->cur_chunk_data_start_offset
					, (chunk->cur_chunk_data_end_offset - chunk->cur_chunk_data_start_offset)
					, chunk->cur_chunk_length);
		}
	}

	return TRUE_1;
}

/***********parse_chunk_handle_open_CR**********************/
uint parse_chunk_handle_open_CR(uint fd_idx)
{
	char *ptr_end = NULL;
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;


	if (isdigit(fd_db[fd_idx].buf.chunk_buf[/*chunk->last_parsed_ch*/ 0]) == 0)
	{
		char dbg_buf[DEBUG_BUF_SIZE + 1];
		snprintf(dbg_buf , DEBUG_BUF_SIZE , "%s(%d):**FAIL** First char in chunk is not digit, buf[0]=0x%x(%c)\n",
				FUNC_LINE, fd_db[fd_idx].buf.chunk_buf[0] , fd_db[fd_idx].buf.chunk_buf[0]);
		DBG_RX PRINTF_VZ_N("%s",dbg_buf);
		DBG_FILE print_to_file_name(CHUNK_DBG_FILE , dbg_buf);
		DBG_FILE dbg_print_to_file_chunk_buf(fd_db[fd_idx].buf.chunk_buf);

		cntr.warning.chunk_first_char_is_not_digit++;
		erase_all_chunk_data(fd_idx , TRUE_1);

		exit_vz(EXIT_FAILURE , dbg_buf); /*XXX - TBR*/
		return FALSE_0;
	}


	if (chunk->last_parsed_ch > CHUNK_OPEN_CR_MAX_OFFSET)
	{
		DBG_RX PRINTF_VZ("**FAIL** parsing, chunk->last_parsed_ch(%d) > CHUNK_OPEN_CR_MAX_OFFSET(%d)\n",
				 chunk->last_parsed_ch , CHUNK_OPEN_CR_MAX_OFFSET);
		cntr.warning.chunk_failed_parse_open_CR_long_offset++;
		erase_all_chunk_data(fd_idx , TRUE_1);
		return FALSE_0;
	}
	fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch] = '\0'; /*set NULL terminating, before atoi*/
	errno = 0;
	chunk->cur_chunk_length = (uint)strtoul(fd_db[fd_idx].buf.chunk_buf , &ptr_end , 16); /*strtol for the length , HEX*/

	if (((chunk->cur_chunk_length == 0) && (errno != 0)) ||
			(ptr_end == NULL) || (ptr_end != &fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch]) ||
			(fd_db[fd_idx].buf.chunk_buf[0]=='\r') || (fd_db[fd_idx].buf.chunk_buf[0]=='\n'))
	{
		char dbg_buf[DEBUG_BUF_SIZE + 1];

		snprintf(dbg_buf , DEBUG_BUF_SIZE , "%s(%d):**FAIL** parsing chunk length, http_chunks=%d, string=%s, strtoul=%d , errno(%d):%s\n",
				FUNC_LINE, cntr.stat.http_chunks,  fd_db[fd_idx].buf.chunk_buf , chunk->cur_chunk_length , errno , strerror(errno));
		DBG_RX PRINTF_VZ_N("%s",dbg_buf);
		DBG_FILE print_to_file_name(CHUNK_DBG_FILE , dbg_buf);

		snprintf(dbg_buf , DEBUG_BUF_SIZE ,"0x%x[%c],0x%x[%c],0x%x[%c],0x%x[%c],0x%x[%c],0x%x[%c],0x%x[%c],0x%x[%c]",
				fd_db[fd_idx].buf.chunk_buf[0],fd_db[fd_idx].buf.chunk_buf[0],
				fd_db[fd_idx].buf.chunk_buf[1],fd_db[fd_idx].buf.chunk_buf[1],
				fd_db[fd_idx].buf.chunk_buf[2],fd_db[fd_idx].buf.chunk_buf[2],
				fd_db[fd_idx].buf.chunk_buf[3],fd_db[fd_idx].buf.chunk_buf[3],
				fd_db[fd_idx].buf.chunk_buf[4],fd_db[fd_idx].buf.chunk_buf[4],
				fd_db[fd_idx].buf.chunk_buf[5],fd_db[fd_idx].buf.chunk_buf[5],
				fd_db[fd_idx].buf.chunk_buf[6],fd_db[fd_idx].buf.chunk_buf[6],
				fd_db[fd_idx].buf.chunk_buf[7],fd_db[fd_idx].buf.chunk_buf[7]
				);
		DBG_RX PRINTF_VZ_N("%s",dbg_buf);
		DBG_FILE print_to_file_name(CHUNK_DBG_FILE , dbg_buf);

		DBG_FILE dbg_print_to_file_chunk_buf(fd_db[fd_idx].buf.chunk_buf);

		cntr.warning.chunk_failed_parse_illegal_strtoul++;
		erase_all_chunk_data(fd_idx , TRUE_1);
		return FALSE_0;

	}
	DBG_RX PRINTF_VZ("-->Found OPEN CR-->New cur chunk handling--> 0x%s==>%d\n", fd_db[fd_idx].buf.chunk_buf , chunk->cur_chunk_length);
	chunk->cur_chunk_parse_state = CHUNK_PARSE_OPEN_CR_FOUND;

	return TRUE_1;
}

/***********parse_chunk_buf**********************/
uint parse_chunk_buf(uint fd_idx)
{
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;

	DBG_RX PRINTF_VZ(" cur_chunk_length=%d , last_parsed_ch=%d, state=%d :  (0x%x)%c,%c,%c,%c,%c,%c,%c,%c...\n"
			 ,  chunk->cur_chunk_length , chunk->last_parsed_ch , chunk->cur_chunk_parse_state
			, fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 0] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 0] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 1] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 2] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 3] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 4] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 5] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 6] ,
			fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch + 7] );

	/*start parsing chunk buf*/
	for (/*chunk->last_parsed_ch*/ ; chunk->last_parsed_ch < chunk->buf_usage ; chunk->last_parsed_ch++)
	{
		switch((fd_db[fd_idx].buf.chunk_buf[chunk->last_parsed_ch]))
		{
		/*CR*/
		case 0xd:
		{
			if (chunk->cur_chunk_parse_state == CHUNK_PARSE_START)
			{/*OPEN CR*/
				if (parse_chunk_handle_open_CR(fd_idx) == FALSE_0)
				{
					return FALSE_0;
				}
			}
			else if (chunk->cur_chunk_parse_state == CHUNK_PARSE_OPEN_LF_FOUND)
			{/*Closing CR - need to verify that this is CR of the end of the chunk, and not CR inside chunk*/
				if (parse_chunk_handle_close_CR(fd_idx) == FALSE_0)
				{
					return FALSE_0;
				}
			}
			continue;
		}
		/*LF*/
		case 0xa:
		{
			if (chunk->cur_chunk_parse_state == CHUNK_PARSE_OPEN_CR_FOUND)
			{/*first LF*/
				chunk->cur_chunk_data_start_offset = chunk->last_parsed_ch + 1;
				chunk->cur_chunk_parse_state = CHUNK_PARSE_OPEN_LF_FOUND;
				DBG_RX PRINTF_VZ("Found OPEN LF, cur_ch=%d, cur_chunk_data_start_offset=%d\n", chunk->last_parsed_ch , chunk->cur_chunk_data_start_offset);
			}
			else if (chunk->cur_chunk_parse_state == CHUNK_PARSE_CLOSE_CR_FOUND)
			{
				DBG_RX PRINTF_VZ("Found CLOSE LF, Reached to the end of chunk, last_parsed_ch = %d , cur_chunk_length=%d\n", chunk->last_parsed_ch , chunk->cur_chunk_length);
				chunk->cur_chunk_trailer_end_offset = chunk->last_parsed_ch;
				chunk->cur_chunk_parse_state = CHUNK_PARSE_CLOSE_LF_FOUND;
				return TRUE_1;
			}
			continue;
		}

		default:
			continue;
		}
	}

	return TRUE_1;
}


/***********analyze_chunk_buf**********************/
uint analyze_chunk_buf(uint fd_idx)
{
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;

	if (chunk->cur_chunk_parse_state == CHUNK_PARSE_CLOSE_LF_FOUND)
	{
		if (chunk->cur_chunk_length == 0)
		{
			DBG_RX PRINTF_VZ("Last chunk FOUND\n" );
			return SUCCESS_FOUND_LAST_CHUNK_4;
		}
		if (write_to_binary_file(fd_db[fd_idx].buf.file_name_rcv_buf , &fd_db[fd_idx].buf.chunk_buf[chunk->cur_chunk_data_start_offset] , chunk->cur_chunk_length) == TRUE_1)
		{
			return CUR_CHUNK_DONE_CONTINUE_TO_NEXT_CHUNK_3;
		}
	}

	return CUR_CHUNK_NOT_DONE_MORE_TO_BUFFER_2;
}

/***********handle_chunk_buf**********************/
void remove_cur_chunk_from_chunk_buf(uint fd_idx)
{
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;
	uint buf_usage_offset = chunk->buf_usage - 1;
	uint left_data_on_buf =  (buf_usage_offset - (chunk->cur_chunk_data_end_offset+1)) ;

	DBG_RX PRINTF_VZ("buf_usage before remove=%d/%d ,cur_chunk_data_end_offset=%d, left_data_on_buf=%d\n"
			 , chunk->buf_usage , chunk->size_of_buf , chunk->cur_chunk_data_end_offset, left_data_on_buf);

	if (left_data_on_buf > chunk->size_of_buf)
	{
		PRINTF_VZ("**FAIL** size_to_remove(%d) > chunk->buf_usage(%d)\n",
				 left_data_on_buf , chunk->buf_usage);
		PANIC_NO_DUMP(1);
//		exit(EXIT_FAILURE);
	}

	memmove(&fd_db[fd_idx].buf.chunk_buf[0] , &fd_db[fd_idx].buf.chunk_buf[chunk->cur_chunk_data_end_offset + 2 /*\r\n*/] , left_data_on_buf);

	chunk->buf_usage = left_data_on_buf;
	chunk->last_parsed_ch = 0;
	chunk->cur_chunk_length = 0;
	chunk->cur_chunk_parse_state = CHUNK_PARSE_START;
	chunk->cur_chunk_data_start_offset = 0;
	chunk->cur_chunk_data_end_offset = 0;
	chunk->cur_chunk_trailer_end_offset = 0;
	DBG_RX PRINTF_VZ("--->Finished remove chunk, new buf usage=%d/%d : %c,%c,%c,%c,%c...\n"
			 , chunk->buf_usage , chunk->size_of_buf
			, fd_db[fd_idx].buf.chunk_buf[0] , fd_db[fd_idx].buf.chunk_buf[1] ,fd_db[fd_idx].buf.chunk_buf[2] , fd_db[fd_idx].buf.chunk_buf[3] , fd_db[fd_idx].buf.chunk_buf[4]);
}

/***********handle_chunk_buf**********************/
uint handle_rx_chunk_buf(uint fd_idx, uint recv_bytes, char *tmp_buf)
{
	uint chunks_cntr , ret;
	chunk_t *chunk = &fd_db[fd_idx].rx.chunk;

	DBG_RX PRINTF_VZ("Start: fd_idx=%d , recv_bytes=%d , wrote_buf_to_disk=%d...\n" ,  fd_idx, recv_bytes , fd_db[fd_idx].rx.wrote_buf_to_disk);

	/*first time chunk buf init*/
	if (chunk->size_of_buf == 0)
	{
		if (update_chunk_malloc_size (fd_idx , RCV_BUF_SIZE) == FALSE_0)
		{
			return FALSE_0;
		}
	}

	if (chunk->cur_chunk_length > chunk->size_of_buf)
	{/*when using memove,To avoid overflows, the size of the arrays pointed by both the destination and source parameters,
	shall be at least num bytes, otherwise memove will crash... */
		if (update_chunk_malloc_size (fd_idx , ((chunk->cur_chunk_length * 2) + RCV_BUF_SIZE)) == FALSE_0)
		{
			return FALSE_0;
		}
	}

	/*copy tmp_buf into chunk buf*/
	if (copy_tmp_buf_into_chunk_buf(fd_idx, recv_bytes, tmp_buf) == FALSE_0)
	{
		return FALSE_0;
	}

	/*processing chunk buf*/
	for (chunks_cntr = 0 ; chunks_cntr < MAX_CHUNKS_ON_SINGLE_BUF ; chunks_cntr++)
	{
		if (parse_chunk_buf(fd_idx) == FALSE_0)
		{
			return FALSE_0;
		}
		ret = analyze_chunk_buf(fd_idx) ;
		if (ret == CUR_CHUNK_DONE_CONTINUE_TO_NEXT_CHUNK_3)
		{
			cntr.stat.http_chunks++;
			remove_cur_chunk_from_chunk_buf(fd_idx);
		}
		else if (ret == SUCCESS_FOUND_LAST_CHUNK_4)
		{
			erase_all_chunk_data(fd_idx , FALSE_0);
			return SUCCESS_FOUND_LAST_CHUNK_4;
		}
		else
		{/*keep on collecting data...*/
			break;
		}
	}

	/*Sanity */
	if (chunks_cntr >= MAX_CHUNKS_ON_SINGLE_BUF)
	{
		DBG_RX PRINTF_VZ("**Warning**-(fd_idx=%d) Reached to max_chunks_on_single_buf=%d\n", fd_idx , chunks_cntr);
		cntr.warning.max_chunks_on_single_buf++;
	}

	return TRUE_1;
}
