/* main.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  main.c is part of vazaget.
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
#include <signal.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/timerfd.h>
#include <stdint.h>        /* Definition of uint64_t */
#include <sys/resource.h>
#include <execinfo.h>
#include "global.h"
#include "data_sender.h"
#include "rx.h"
#include "rx_range.h"
#include "ssl_vazaget.h"
#include "tx.h"
#include "prints.h"
#include "timer.h"
#include "config.h"
#include "close.h"

/*****************Release Notes********************/

/*****************Release Notes-END********************/
//TODO:
// 1. replace static buffers in dynamic buffers

/*****************Eclipse workspace settings********************/
/*Compiler:*/
/*-----------------*/
/*project-->properties-->settings-->cross GCC compiler-->warnings*/
/*-Wall , -Wextra , -Werror , -Wconversion */

/*linker:*/
/*-----------------*/
/*project-->properties-->settings-->cross GCC linker-->Libraries*/
/*-lrt , -lpthread , -lz*/
/*project-->properties-->settings-->cross GCC linker-->Miscellenious*/
/* -rdynamic*/
/***********************************************************************/

/*************Additional Issues****************************/
/*1. there is debug print in rx_chunk.c that uses hexdump, recommend installing it : apt-get install hexdump */
/*2. I also use wireshark , apache2 , eclipse-cdt , filezilla */
/**/
/*Bottom line : apt-get install wireshark apache2 eclipse-cdt filezilla hexdump*/
/**********************************************************/

/*************MBEDTLS****************************/
/*
 * current mbedtls version 2.2.4
 * how to integrate it into vazaget
 * 1. download sources
 * 2. NOT IN USE...goto mbedtls-2.2.1/include/mbedtls/config.h and remove the remark from these 2 defines :
 * 		MBEDTLS_THREADING_C
 * 		MBEDTLS_THREADING_PTHREAD
 * 3. compile :
 * 	3a. mbedtls-2.2.4/cmake .
 * 	3b. mbedtls-2.2.4/make
 * 4. copy the 3 created libs (cd mbedtls-2.2.4/library/) to vazaget project
 * 		cp libmbedcrypto.a libmbedtls.a libmbedx509.a  vazaget_workspace/vazaget/lib/
 * 5. beginning from 2.4.0, add the following softlink :
 * 		a. cd /disk2/projects/vazaget_workspace/vazaget/include_mbedtls
 * 		b. ln -s ../include_mbedtls/ ./mbedtls
 * 5. recompile vazaget
 */
/**********************************************************/

struct timespec start_time;
time_t starting_time;
time_t ending_time;
//pthread_t th_rx;
pthread_t th_rx_listener;
pthread_t th_queue_process; /*mainly uses for close*/

char original_full_command[STRING_200_B_LENGTH + 1] = {'\0'};
extern sig_atomic_t watchdog_event_timer;
extern pthread_t th_main_timer;

char exit_buf[EXIT_BUF_LEN] = {'\0'};
char errno_exit_buf[EXIT_BUF_LEN] = {'\0'};

#define TX_THRESHOLD_PRECENT	60

/*********************************/
void signal_handler(int rcv_signal)
{
	PRINTF_VZ_N ( "!!! Terminated by signal %d!!!\n",rcv_signal);
	void* fp = fopen(LOG_FILE_NAME , "a");
	if (fp != NULL)
	{
		fprintf(fp , "!!! Terminated by signal %d !!!, see below results...\n",rcv_signal);
		fclose(fp);
	}
	print_final_summary();
	if (rcv_signal == SIGSEGV)
	{
		backtrace_disp( NULL , __LINE__ , 1);
	}
	exit_vz(EXIT_FAILURE, NULL);
}


/*********backtrace_disp************************/
/*remember to add -rdynamic in the linker options,*/
/*in the eclipse it would be under : project-->properties-->settings-->cross GCC linker-->Miscellenious --> -rdynamic*/
/*********************************/
void backtrace_disp(char *func , int line, int create_core_dump)
{
#define TRACE_SIZE	100
	void *trace[TRACE_SIZE];
	char **messages = (char **)NULL;
	int i, trace_size = 0;

	PRINTF_VZ_N ( "!!!PANIC!!!(ver=%s%s) function=%s(), line=%d\n",VAZAGET_VERSION, BUILD_PLATFORM ,func , line);
	trace_size = backtrace(trace, TRACE_SIZE);
	messages = backtrace_symbols(trace, trace_size);
	printf("[bt] Execution path:\n");
	for (i=0; i<trace_size; ++i)
	{
		PRINTF_VZ_N ( "[bt] %s\n", messages[i]);
	}

	if (create_core_dump)
	{
		abort();
	}
	else
	{
		exit_vz(EXIT_FAILURE , NULL);
	}
}

/***************shutdown_now()******************/
void shutdown_now()
{
	DBG_RX_TX PRINTF_VZ_N ( "Starting shutdown procedure...\n");
	shut_down_now = 1;
}

/***************exit_vz()******************/
void exit_vz(int exit_code, char* string_to_print)
{
	if (string_to_print)
	{
		PRINTF_VZ_N ( "%s\n",string_to_print);
	}
	exit(exit_code);
}

/***************init_srv_values()******************/
void init_srv_values()
{
	int i;
	for (i = 0 ; i < MAX_REAL_DST_SERVERS ; i++)
	{
		memset(srv_dst_ip , 0 , sizeof(srv_dst_ip_struct));
		memset(srv_dst_port , 0 , sizeof(srv_dst_port_struct));
	}
}


/*********************************/
/*init_untouched_rc_buf()*/
/*********************************/
void init_untouched_rcv_buf(uint max_active_sessions)
{
	uint i;
	for (i=0 ; i<max_active_sessions ; i++)
	{
		fd_db[i].buf.rcv_buf_untouched = calloc (1 , RCV_BUF_SIZE+1);
		if (fd_db[i].buf.rcv_buf_untouched == NULL)
		{/***FAIL** calloc*/
			snprintf(exit_buf, EXIT_BUF_LEN,  "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}
}

/*********************************/
/*init_range_table()*/
/*********************************/
void init_range_table(uint max_active_sessions)
{
	range_global.range_table  = calloc (max_active_sessions , sizeof(range_table_t));
	if (range_global.range_table == NULL)
	{/***FAIL** malloc*/
		snprintf(exit_buf, EXIT_BUF_LEN,  "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	pthread_mutex_init(&range_global.range_table_mutex , NULL);
}

/*********************************/
/*init_range_buf()*/
/*********************************/

uint init_range_buf(uint fd_idx)
{
	if (fd_db[fd_idx].buf.range_buf)
	{
		PRINTF_VZ_N ( "fd_ifdx=%d , range_buffer already allocated...\n" ,fd_idx);
		return TRUE_1;
	}

	fd_db[fd_idx].buf.range_buf = calloc (1 , range_global.global_range_block_size+1);
	if (fd_db[fd_idx].buf.range_buf == NULL)
	{/***FAIL** calloc*/
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	return TRUE_1;
}

/*********************************/
/*init_extarct_buf()*/
/*extract_buf - will be allocated only for gzip sessions, to extract payload (maybe will need use it to ssl also) */
/*********************************/
void init_extarct_buf(uint max_active_sessions)
{
	uint i;
	for (i=0 ; i<max_active_sessions ; i++)
	{
		fd_db[i].buf.extract_buf = calloc (1 , RCV_BUF_SIZE+1);
		if (fd_db[i].buf.extract_buf == NULL)
		{/***FAIL** calloc*/
			snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}
}

/*********************************/
/*init_fd_db_t()*/
/*********************************/
void init_fd_db_t(uint max_active_sessions)
{
	uint i;
	fd_db = calloc (max_active_sessions , sizeof(fd_db_t));
	if (fd_db == NULL)
	{/***FAIL** malloc*/
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	/*init buf guards*/
	for (i=0 ; i<max_active_sessions ; i++)
	{
		fd_db[i].buf.buf_guard_1 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_2 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_3 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_4 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_5 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_6 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_7 = BUF_GUARD_NUM;
		fd_db[i].buf.buf_guard_8 = BUF_GUARD_NUM;
	}
}

/*********************************/
void init_TX_thread_db_t(uint tx_num_of_threads)
{
	tx_th_db = calloc (tx_num_of_threads , sizeof(TX_thread_db_t));
	if (tx_th_db == NULL)
	{/***FAIL** malloc*/
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}


/*********************************/
void init_RX_thread_db_t(uint rx_num_of_threads)
{
	rx_th_db = calloc (rx_num_of_threads , sizeof(RX_thread_db_t));
	if (rx_th_db == NULL)
	{/***FAIL** calloc*/
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d): **FAIL** calloc()\n",FUNC_LINE);
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}

/*********************************/
void init_global_default_bwT_limits()
{
	uint slice_num, mod_result, per_slice_bwt , spread_mod_result;
	per_slice_bwt = (uint)cfg.int_v.bw_TX_limit.val / NUM_OF_TIME_SLICES;
	mod_result = (uint)cfg.int_v.bw_TX_limit.val % NUM_OF_TIME_SLICES;

	for (slice_num=0 ; slice_num<NUM_OF_TIME_SLICES ; slice_num++)
	{
		if (slice_num < mod_result)
		{
			spread_mod_result = 1;
		}
		else
		{
			spread_mod_result = 0;
		}
		global_default_bwT[slice_num].slice_limit = per_slice_bwt + spread_mod_result;
		global_default_bwT[slice_num].slice_usage = 0;
		DBG_CONF PRINTF_VZ("default_bwT[%d].slice_limit=%d, slice_usage=%d\n", slice_num ,
				global_default_bwT[slice_num].slice_limit , global_default_bwT[slice_num].slice_usage);
	}
}

/*********************************/
void init_global_default_bwR_limits()
{
	uint slice_num, mod_result, per_slice_bwr , spread_mod_result;
	per_slice_bwr = (uint)cfg.int_v.bw_rx_limit.val / NUM_OF_TIME_SLICES;
	mod_result = (uint)cfg.int_v.bw_rx_limit.val % NUM_OF_TIME_SLICES;

	for (slice_num=0 ; slice_num<NUM_OF_TIME_SLICES ; slice_num++)
	{
		if (slice_num < mod_result)
		{
			spread_mod_result = 1;
		}
		else
		{
			spread_mod_result = 0;
		}
		global_default_bwR[slice_num].slice_limit = per_slice_bwr + spread_mod_result;
		global_default_bwR[slice_num].slice_usage = 0;
		DBG_CONF PRINTF_VZ("global_default_bwR[%d].slice_limit=%d, slice_usage=%d\n", slice_num ,
				global_default_bwR[slice_num].slice_limit , global_default_bwR[slice_num].slice_usage);
	}
	avg_bytes_per_slice = per_slice_bwr + 1;
}

/*********************************/
void write_buf_to_stdout(char buf[])
{
	int s;
	uint count = (uint)strlen(buf);
	/* Write the buffer to standard output */
	s = (int)write (1, buf, count);
	if (s == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):write error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	return;
}

/*********************************/
void keep_original_full_command(int argc, char **argv)
{
	uint argc_iter = 0, avail_dst_buf_length = 0;

	while (argc_iter < (uint)argc)
	{
		avail_dst_buf_length = (uint)sizeof(original_full_command) - (uint)strlen(original_full_command);
		if (avail_dst_buf_length)
		{
			strncat(original_full_command , argv[argc_iter] , avail_dst_buf_length);
			strcat(original_full_command , " ");
		}
		argc_iter++;
	}

}

/*********************************/
void init(int argc, char **argv)
{
	struct rlimit core_limit;
	core_limit.rlim_cur = RLIM_INFINITY;
	core_limit.rlim_max = RLIM_INFINITY;

	if(setrlimit(RLIMIT_CORE, &core_limit) < 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"setrlimit: %s\n **WARNING**: core dumps may be truncated or non-existant\n", strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	memset(&cntr , 0 , sizeof (cntr_t));
	memset(&last , 0 , sizeof (last));
	memset(&global_ssl , 0 , sizeof (global_ssl));
	memset(&run_time , 0 , sizeof (run_time));
	memset(&file_download_global , 0 , sizeof (file_download_global));

	clock_gettime( CLOCK_REALTIME , &start_time);
	time (&starting_time);

	keep_original_full_command(argc, argv);
	shut_down_now = 0;
	vaza_server_found = 0;
	tx_threshold = (uint)((cfg.int_v.tx_th_active_sessions.val * TX_THRESHOLD_PRECENT) / 100);
	max_active_sessions = (uint)(cfg.int_v.tx_num_of_threads.val * cfg.int_v.tx_th_active_sessions.val);
	watchdog_event_timer = WATCHDOG_TIMER_IN_SEC;
	init_fd_db_t(max_active_sessions);
	init_RX_thread_db_t((uint)cfg.int_v.rx_num_of_threads.val);
	init_TX_thread_db_t((uint)cfg.int_v.tx_num_of_threads.val);
	init_srv_values();


	if (cfg.flag.ssl.val)
	{
		init_ssl_cert();
	}
	if (cfg.flag.http_parse_test.val)
	{
		test_http_parse();
	}
	if (cfg.flag.encoding_gzip.val)
	{
		init_extarct_buf(max_active_sessions);
	}
	if (cfg.int_v.bw_rx_limit.val)
	{
		init_global_default_bwR_limits(max_active_sessions);
	}
	if (cfg.int_v.bw_TX_limit.val)
	{
		init_global_default_bwT_limits(max_active_sessions);
	}
	if (cfg.str_v.data_sender[0])
	{
		init_untouched_rcv_buf(max_active_sessions);
	}
	if (cfg.flag.range.val)
	{
		init_range_global(max_active_sessions);
	}
	if ((cfg.flag.range.val == 0) && (cfg.flag.range.config_mode == OVERWRITE_CFG))
	{
		cntr.info.range_config_disabled++;
	}


	signal(SIGTERM , signal_handler);
	//	signal(SIGABRT , signal_handler); /*sig abort will create the core dump, don't catch it.*/
	signal(SIGINT , signal_handler);
	signal(SIGSEGV , signal_handler);
	signal(SIGILL , signal_handler);
	signal(SIGTSTP , signal_handler);

#if 0 /*don't need this part any more, since we use now the SO_LINGER, which closes the connection immidiatly*/
	result = system("echo 0 > /proc/sys/net/ipv4/tcp_tw_recycle");
	if (result < 0)
	{
		perror("/proc/sys/net/ipv4/tcp_tw_recycle\n");
		exit(EXIT_FAILURE);
	}

	result = system("echo 0 > /proc/sys/net/ipv4/tcp_tw_reuse");
	if (result < 0)
	{
		perror("/proc/sys/net/ipv4/tcp_tw_reuse\n");
		exit(EXIT_FAILURE);
	}
#endif
}

/*********************************/
void free_all_resources()
{
	uint fd_idx, cookie_idx;

	/*free all sockets, fd_db*/
	for (fd_idx = 0 ; fd_idx < max_active_sessions ; fd_idx++)
	{
#if 0
		/*remove this close, since it caused to long delay when finish and shut down...close the socket, if exist*/
		if ((fd_db[fd_idx].gen.in_use) && (fd_db[fd_idx].gen.fd > 2))
		{
			close(fd_db[fd_idx].gen.fd);
			fd_db[fd_idx].gen.fd = 0;
		}
#endif
		/*free rcv_buf_untouched*/
		if (fd_db[fd_idx].buf.rcv_buf_untouched)
		{
			free(fd_db[fd_idx].buf.rcv_buf_untouched);
			fd_db[fd_idx].buf.rcv_buf_untouched = NULL;
		}

		/*free extract_buf*/
		if (fd_db[fd_idx].buf.extract_buf)
		{
			free(fd_db[fd_idx].buf.extract_buf);
			fd_db[fd_idx].buf.extract_buf = NULL;
		}

		/*free chunk_buf*/
		if (fd_db[fd_idx].buf.chunk_buf)
		{
			free(fd_db[fd_idx].buf.chunk_buf);
			fd_db[fd_idx].buf.chunk_buf = NULL;
		}

		/*free range_buf*/
		if (fd_db[fd_idx].buf.range_buf)
		{
			free(fd_db[fd_idx].buf.range_buf);
			fd_db[fd_idx].buf.range_buf = NULL;
		}

		if (fd_db[fd_idx].buf.file_name_rcv_buf)
		{
			free(fd_db[fd_idx].buf.file_name_rcv_buf);
			fd_db[fd_idx].buf.file_name_rcv_buf = NULL;
		}

		for (cookie_idx = 0 ; cookie_idx < MAX_PARSED_COOKIES ; cookie_idx++)
		{
			if (fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_ptr)
			{
				free(fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_ptr);
				fd_db[fd_idx].non_del.cookie_struct[cookie_idx].cookie_alloc_length = 0;
			}

		}

	}

	if (cfg.flag.ssl.val)
	{
		mbedtls_x509_crt_free( &global_ssl.cacert );	/* release context */
		mbedtls_entropy_free( &global_ssl.entropy);
	}

	/*free all buffers*/
	buf_free_alloc_all_buffers();

	/*free fd_db*/
	free(fd_db);
	fd_db = NULL;

	/*free ds_file buffer*/
	if (ds_file.content)
	{
		free(ds_file.content);
		ds_file.content = NULL;
	}

	/*free all rx_th_db*/
	free(rx_th_db);
	rx_th_db = NULL;


	/*free all TX tx_th_db*/
	free(tx_th_db);
	tx_th_db = NULL;

}

/*********************************/
void set_my_thread_to_highes_priority()
{

	int ret;

	/*We'll operate on the currently running thread.*/
	pthread_t this_thread = pthread_self();

	/*struct sched_param is used to store the scheduling priority*/
	struct sched_param params;
	/* We'll set the priority to the maximum.*/
	params.sched_priority = sched_get_priority_max(SCHED_FIFO);


	/* Attempt to set thread real-time priority to the SCHED_FIFO policy*/
	ret = pthread_setschedparam(this_thread, SCHED_FIFO, &params);
	if (ret != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **FAIL** to set highest pthread priority (%s)\n",FUNC_LINE , strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}


/*********************************/
int main (int argc, char *argv[])
{
	fill_default_param();
	/*parse parameters*/
	params_parser(argc , argv);
	/*validate mandatory values*/
	validate_config_values();
	init(argc , argv);

	/*timers threads*/
	timer_threads_creator();

	/*RX threads*/
	RX_threads_creator();

	/*TX threads*/
	TX_threads_creator();

	/*RX listener thread*/
	if (ds_file.rcv_mode == 1)
	{
		if (pthread_create(&th_rx_listener, 0, thread_RX_listener, NULL ) != 0)
		{
			snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):pthread_create() thread_RX_listener error - %s\n",FUNC_LINE, strerror(errno));
			exit_vz(EXIT_FAILURE, exit_buf);
		}
	}

	/*queue thread*/
	if (pthread_create(&th_queue_process, 0, thread_queue_processing, NULL ) != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() thread_queue_processing error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/*wait till RX thread done*/
//	pthread_join(th_rx, NULL);
	pthread_join(th_main_timer, NULL);
	if (ds_file.rcv_mode == 1)
	{
		pthread_join(th_rx_listener, NULL);
	}

	/*queue thread*/
	shutdown_queue_thread();
	pthread_join(th_queue_process, NULL);


	if (!cfg.str_v.data_sender[0])
	{
		print_overlap_values(stdout);
		print_final_summary();
	}
	free_all_resources();
	exit_vz(EXIT_SUCCESS , NULL);

	return EXIT_SUCCESS;
}


