/* buf_manager.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *  All rights reserved.
 *
 *  buf_manager.c is part of vazaget.
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
#include "global.h"

#define BUF_MAX_SIZE	1000000
#define BUF_DEFAULT_SIZE	1024

typedef struct buf_link_list_t
{
	buf_element_t			*head;
	buf_element_t			*tail;
	uint64_t				counter; /*counting num of elements*/
}buf_link_list_t;

typedef enum {
	BUF_SUCCESS = 0,
	BUF_NOT_FOUND

}BUF_STATUS;

buf_link_list_t buf_free_list = {0};
buf_link_list_t buf_use_list = {0};

typedef struct buf_trace_desc_t
{
	char 	desc[STRING_100_B_LENGTH];
}buf_trace_desc_t;

buf_trace_desc_t buf_trace_desc[] =
{
		{"buf not in use"},		/*BUF_NOT_IN_USE*/
		{"buf get"},			/*BUF_GET*/
		{"buf return"},			/*BUF_RETURN*/

		{"buf MAX trace idx"}	/*BUF_MAX*/
};

/*********buf_remove_from_list()*******/

static STATUS buf_remove_from_list(buf_link_list_t *list , buf_element_t *buf_to_remove)
{
	buf_element_t *buf_ptr = list->head;

	while (buf_ptr)
	{
		if (buf_ptr == buf_to_remove)
		{/*found the buf to be removed*/
			buf_element_t *before_buf = buf_to_remove->before;
			buf_element_t *next_buf = buf_to_remove->next;

			if (before_buf)
			{/*update before buf*/
				before_buf->next = next_buf;
			}
			if (next_buf)
			{/*update next buf*/
				next_buf->before = before_buf;
			}
			if (list->head == buf_to_remove)
			{/*update head*/
				list->head = next_buf;
			}
			if (list->tail == buf_to_remove)
			{/*update tail*/
				list->tail = before_buf;
			}

			/*zero buffer pointers*/
			buf_to_remove->before = NULL;
			buf_to_remove->next = NULL;

			/*update list counters*/
			list->counter--;
			if (list->counter == 0)
			{
				list->head = NULL;
				list->tail = NULL;
			}

			return TRUE_1;
		}
		buf_ptr = buf_ptr->next;
	}
	return FALSE_0;
}


/*********buf_add_to_list()*******/
/*adding to list by size - head will be the smallest,
 * tail is the bigger*/

static STATUS buf_add_to_list_by_size(buf_link_list_t *list , buf_element_t *buf_to_add)
{
	buf_element_t *buf_ptr = list->head;

	if (list->head == NULL)
	{/*first buf in the list*/
		buf_to_add->before = NULL;
		buf_to_add->next = NULL;
		list->head = buf_to_add;
		list->tail = buf_to_add;
		list->counter++;
		return TRUE_1;
	}

	/*if we get here, we already have head*/
	while (buf_ptr)
	{
		if (buf_ptr->max_size < buf_to_add->max_size)
		{/*buffer too big, continue to next buf*/
			if (buf_ptr->next == NULL)
			{/*we are in the tail, insert to tail*/
				buf_ptr->next = buf_to_add;
				buf_to_add->before = buf_ptr;
				buf_to_add->next = NULL;
				list->tail = buf_to_add;
				list->counter++;
				return TRUE_1;
			}
			/*continue to next buf*/
			buf_ptr = buf_ptr->next;
		}
		else
		{/*insert the buf_to_add before buf_ptr*/
			buf_to_add->before = buf_ptr->before;
			buf_ptr->before = buf_to_add;
			buf_to_add->next = buf_ptr;
			list->counter++;
			return TRUE_1;
		}
	}

	return FALSE_0;
}

/*********buf_fast_clear()*******/
/*clear first bit only*/
void buf_fast_clear(buf_element_t *buf)
{
	buf->buf[0] = '\0';
	buf->cur_size = 0;
	return;
}

/*********buf_zero()*******/
void buf_zero(buf_element_t *buf)
{
	memset (buf->buf , 0 , buf->max_size);
	buf->cur_size = 0;
	return;
}


/*********buf_verify_list()*******/
/*in use just for debugging...*/

STATUS buf_verify_list(buf_link_list_t *list)
{
	uint64_t actual_counter = 0, previous_buf_size = 0;

	buf_element_t *buf = list->head;

	while(buf)
	{
		actual_counter++;
		if (previous_buf_size > buf->max_size)
		{
			DBG_BUF PRINTF_VZ("**FAIL** previous_buf_size %"PRIu64" > buf->max_size %"PRIu64" (actual_counter=%"PRIu64")",
					previous_buf_size, buf->max_size, actual_counter);
			return FALSE_0;
		}
		previous_buf_size = buf->max_size;
		buf = buf->next;
	}

	if (actual_counter != list->counter)
	{
		DBG_BUF PRINTF_VZ("**FAIL** list counter not correct : actual_counter %"PRIu64" != list %"PRIu64")", actual_counter, list->counter);
		return FALSE_0;
	}
	return TRUE_1;
}


/*********buf_get_prev_trace_idx()*******/
uint buf_get_prev_trace_idx(uint cur_trace_idx)
{
	uint prev_trace_idx = cur_trace_idx;
	if (prev_trace_idx == 0)
	{
		prev_trace_idx = (BUF_TRACE_SIZE - 1);
	}
	else
	{
		prev_trace_idx--;
	}
	return prev_trace_idx;
}

/*********buf_get_next_trace_idx()*******/
uint buf_get_next_trace_idx(uint cur_trace_idx)
{
	uint next_trace_idx = cur_trace_idx;
	if (next_trace_idx == (BUF_TRACE_SIZE - 1))
	{
		next_trace_idx = 0;
	}
	else
	{
		next_trace_idx++;
	}
	return next_trace_idx;
}


/*********buf_dump_trace_history()*******/
char *buf_dump_trace_history(buf_element_t *buf)
{
	char tmp_buf[STRING_100_B_LENGTH] = {0};
	static char output_buf[STRING_500_B_LENGTH] = {0};
	output_buf[0] = '\0';

	if (!buf)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): buf = NULL || output_buf = NULL\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	uint trace_idx = buf->cur_trace_idx;
	uint counter = 1;
	sprintf(output_buf , "buf trace history :\n");

	sprintf(tmp_buf , "%d : (%d)%s%s\n", counter , buf->trace[trace_idx] ,
			buf_trace_desc[buf->trace[trace_idx]].desc,
			buf->trace_extra_info[trace_idx]);
	strcat (output_buf , tmp_buf);

	trace_idx = buf_get_prev_trace_idx(trace_idx);
	while (trace_idx != buf->cur_trace_idx)
	{
		counter++;
		sprintf(tmp_buf , "%d : (%d)%s%s\n", counter , buf->trace[trace_idx] ,
				buf_trace_desc[buf->trace[trace_idx]].desc,
				buf->trace_extra_info[trace_idx]);
		strcat (output_buf , tmp_buf);
		trace_idx = buf_get_prev_trace_idx(trace_idx);
	}
	return output_buf;
}


/*********buf_set_trace()*******/
void buf_set_trace(buf_element_t *buf, BUF_TRACE trace_number, char *extra_info)
{
	if (!buf)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): buf = NULL\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	buf->cur_trace_idx = buf_get_next_trace_idx(buf->cur_trace_idx);
	buf->trace[buf->cur_trace_idx] = trace_number;
	if (extra_info)
	{
		snprintf(buf->trace_extra_info[buf->cur_trace_idx] , STRING_100_B_LENGTH , "%s" , extra_info);
	}
	return;
}


/*********buf_free_alloc_mem()*******/
static STATUS buf_free_alloc_mem(buf_element_t *buf)
{
	if (!buf)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): called to buf_free_alloc_mem with empty buf\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
		return FALSE_0;
	}

	/*try search buf on buf_use_list, and then on buf_free_list*/
	if ((buf_remove_from_list(&buf_use_list, buf) == FALSE_0) &&
			(buf_remove_from_list(&buf_free_list, buf) == FALSE_0))
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): trying to buf_free_alloc_mem, but couln't found buf on any list...\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
		return FALSE_0;
	}

	free(buf->buf);
	free (buf);
	return TRUE_1;
}

/*********buf_free_alloc_all_buffers()*******/
void buf_free_alloc_all_buffers()
{

	buf_element_t *buf_ptr = buf_use_list.head;

	/*free the buf_use_list*/
	while (buf_ptr)
	{
		buf_free_alloc_mem(buf_ptr);
		/*buf_use_list->head shouild hold now the next buf*/
		buf_ptr = buf_use_list.head;
	}

	/*free the buf_free_list*/
	buf_ptr = buf_free_list.head;
	while (buf_ptr)
	{
		buf_free_alloc_mem(buf_ptr);
		/*buf_use_list->head shouild hold now the next buf*/
		buf_ptr = buf_free_list.head;
	}
}

/*********buf_return()*******/
STATUS buf_return(buf_element_t *buf, char *file, uint line)
{
	char buf_extra_info[STRING_100_B_LENGTH];

	if (!buf)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): called to buf_return with empty buf\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	if (buf_remove_from_list(&buf_use_list, buf) == FALSE_0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAILED** buf_remove_from_list(), buf_use_list.\n%s",
				FUNC_LINE, buf_dump_trace_history(buf));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	if (buf_add_to_list_by_size(&buf_free_list, buf) == FALSE_0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAILED** buf_add_to_list_by_size(), buf_free_list.\n%s",
				FUNC_LINE, buf_dump_trace_history(buf));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	sprintf(buf_extra_info, "(%s,%d)", file, line);
	buf_set_trace(buf, BUF_RETURN , buf_extra_info);

	return TRUE_1;
}

/*********buf_get()*******/
buf_element_t *buf_get(uint64_t required_buf_size , char *file, uint line)
{
	buf_element_t *ret_buf = NULL;
	char buf_extra_info[STRING_100_B_LENGTH];

	if (required_buf_size > BUF_MAX_SIZE)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): requested buf too big %"PRIu64" > %u\n", FUNC_LINE, required_buf_size, BUF_MAX_SIZE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	ret_buf = buf_free_list.head;
	while (ret_buf)
	{/*search for buf in the already allocated free buffers list*/
		if (required_buf_size > ret_buf->max_size)
		{/*need bigger buffer - try next one...*/
			ret_buf = ret_buf->next;
		}
		else
		{/*buffer size fit*/
			if (buf_remove_from_list(&buf_free_list , ret_buf) == FALSE_0)
			{
				snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAILED** buf_remove_from_list(), buf_free_list\n", FUNC_LINE);
				exit_vz(EXIT_FAILURE, exit_buf);
			}
			if (buf_add_to_list_by_size(&buf_use_list , ret_buf)  == FALSE_0)
			{
				snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAILED** buf_add_to_list_by_size(), buf_use_list\n", FUNC_LINE);
				exit_vz(EXIT_FAILURE, exit_buf);
			}
			buf_fast_clear(ret_buf);
			sprintf(buf_extra_info, "(%s,%d)", file, line);
			buf_set_trace(ret_buf, BUF_GET , buf_extra_info);
			return ret_buf;
		}
	}

	/*if we get here, we didn't found buffer in required size under the free list,
	 * so need to malloc such buf*/
	ret_buf = calloc(1 , sizeof(buf_element_t));
	if (ret_buf == NULL)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): out of memory, failed calloc buf\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	ret_buf->buf = malloc(required_buf_size);
	if (ret_buf->buf == NULL)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): out of memory, failed malloc buf size %"PRIu64"\n", FUNC_LINE, required_buf_size);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	ret_buf->max_size = required_buf_size;
	if (buf_add_to_list_by_size(&buf_use_list , ret_buf) == FALSE_0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAILED** buf_add_to_list_by_size(), buf_use_list\n", FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	buf_fast_clear(ret_buf);

	return ret_buf;
}

