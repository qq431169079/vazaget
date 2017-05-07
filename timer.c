/* timer.c
 *
 * \author Shay Vaza <shayvaza@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  timer.c is part of vazaget.
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
#include <sys/timerfd.h>
#include "global.h"
#include "data_sender.h"
#include "rx_range.h"
#include "tx.h"
#include "prints.h"
#include "timer.h"

//#define TIMER_TEST

pthread_t th_main_timer;
pthread_t th_10_msec_process;
pthread_t th_100_msec_process;
pthread_t th_1_sec_process;

pthread_mutex_t mutex_timer_10_msec_process; /*mutex to trigger thread of 10msec*/
pthread_mutex_t mutex_timer_100_msec_process; /*mutex to trigger thread of 100msec*/
pthread_mutex_t mutex_timer_1_sec_process; /*mutex to trigger thread of 1 sec*/

/*************EXTERN********************/
extern sig_atomic_t 	all_RX_threads_done;
extern sig_atomic_t 	watchdog_event_timer;

/*********************************/
void watchdog_handler()
{
	watchdog_event_timer--;
	if (watchdog_event_timer <= 0)
	{
		char tmp_str[100];
		sprintf(tmp_str , "watchdog timer (%d sec.) expired, terminating...\n",WATCHDOG_TIMER_IN_SEC);
		print_to_file(tmp_str);
		fprintf(stderr , "%s", tmp_str);
		raise(SIGINT);
	}
	return;
}


/*********************************/
void update_elapsed_time_string()
{
	uint min = 0;
	uint sec = run_time.sec;
	uint msec = run_time.slice_100_msec * 10;

	if (run_time.sec >= 60)
	{
		min = (run_time.sec / 60);
		sec = (run_time.sec % 60);
	}

	if (elapse_time == &elapse_time_1[0])
	{
		sprintf(elapse_time_2 , "%02d:%02d:%02d",min, sec , msec);
		elapse_time = &elapse_time_2[0];
	}
	else if (elapse_time == &elapse_time_2[0])
	{
		sprintf(elapse_time_1 , "%02d:%02d:%02d",min, sec , msec);
		elapse_time = &elapse_time_1[0];
	}
	else
	{
		sprintf(elapse_time_1 , "%02d:%02d:%02d",min, sec , msec);
		elapse_time = &elapse_time_1[0];
	}
}


/*********************************/
/*thread_main_timer - Work in resolution of 10msec*/
/*********************************/
void *thread_10_msec_process()
{
	uint run_again;

	while (!shut_down_now)
	{
		pthread_mutex_lock(&mutex_timer_10_msec_process);
		{
			if (shut_down_now)
			{
				break;
			}
			if (cfg.flag.range.val)
			{
				if (range_global.range_pending_on_timer)
				{
					run_again = max_active_sessions;
					while (run_again)
					{
						if (rx_range_handle_pending_buf_from_timer() == RANGE_WROTE_TO_DISK)
						{/*if managed to write buf, then run the loop again, to verify there is no other ready pending buf*/
							run_again--;
						}
						else
						{
							run_again = 0;
						}

						if (!range_global.range_pending_on_timer)
						{
							run_again = 0;
						}
					}
				}

				//			wake_up_all_tx_thread();/*test*/
				check_and_wake_tx_threads();
			}
		}
	}
	DBG_RX	PRINTF_VZ_N (":done, exiting...\n");
	pthread_exit(NULL);
	return(0);
}

/*********************************/
/*thread_main_timer - Work in resolution of 100msec*/
/*********************************/
void *thread_100_msec_process()
{
	uint fd_idx;
	while (!shut_down_now)
	{
		pthread_mutex_lock(&mutex_timer_100_msec_process);
		{
			if (shut_down_now)
			{
				break;
			}
			update_elapsed_time_string();

			/*TX BW limit, every 100 msec*/
			if ((cfg.int_v.bw_TX_limit.val) || (cfg.flag.range.val))
			{
				//			wake_up_all_tx_thread();
				range_global.get_sent_in_last_100msec_slice = 0;
				check_and_wake_tx_threads();
			}

			/*data sender*/
			if (cfg.str_v.data_sender[0])
			{
				uint sec_changed = 0;
				static uint last_sec = 0;
				if (last_sec != run_time.sec)
				{
					last_sec = run_time.sec;
					sec_changed = 1;
				}

				for (fd_idx=0 ; fd_idx < max_active_sessions ; fd_idx++)
				{
					if ((fd_db[fd_idx].gen.in_use) && (fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_WAIT))
					{
						if (sec_changed)
						{
							DS_PRINT PRINTF_VZ_N (CYAN "[%s] WAIT %d sec." RESET "\n" ,elapse_time , (fd_db[fd_idx].ds_db.ds_cmd_wait.expire_sec - run_time.sec));
							DBG_DS PRINTF_VZ_N ("cur=%d.%d, expire=%d.%d\n" ,run_time.sec , run_time.slice_100_msec , fd_db[fd_idx].ds_db.ds_cmd_wait.expire_sec , fd_db[fd_idx].ds_db.ds_cmd_wait.expire_100m_slice);
						}

						if ((run_time.sec > fd_db[fd_idx].ds_db.ds_cmd_wait.expire_sec) ||
								((run_time.sec == fd_db[fd_idx].ds_db.ds_cmd_wait.expire_sec) &&
										(run_time.slice_100_msec >= fd_db[fd_idx].ds_db.ds_cmd_wait.expire_100m_slice)))
						{
							ds_move_to_next_command(fd_idx , FUNC_LINE);
							if (fd_db[fd_idx].ds_db.cur_cmd == DS_CMD_TX)
							{
								zero_tx_buf(fd_idx);
								ds_build_TX_pkt(fd_db[fd_idx].buf.tx_buf , fd_idx);
								tx_add_pending_buf(fd_idx);
								fd_db[fd_idx].gen.state = STATE_SENT_GET;
								tx_now(fd_db[fd_idx].tx.tx_th_idx);
							}
						}
					}
				}
			}

			if ((!cfg.dbg_v.dbg) &&
					(!cfg.str_v.data_sender[0]) &&
					(!cfg.int_v.ssl_debug_flag.val))
			{
				print_overlap_values(stdout);
			}
		}
	}
	DBG_RX	PRINTF_VZ_N (":done, exiting...\n");
	pthread_exit(NULL);
	return(0);
}

/*********************************/
/*thread_main_timer - Work in resolution of 10msec*/
/*********************************/
void *thread_1_sec_process()
{
	while (!shut_down_now)
	{
		pthread_mutex_lock(&mutex_timer_1_sec_process);
		{
			if (shut_down_now)
			{
				break;
			}
			calc_cps();
			if (!ds_file.rcv_mode)
			{
				watchdog_handler();
			}
			if (cfg.flag.range.val)
			{
				range_global_1_sec_timer();
			}
		}
	}
	DBG_RX	PRINTF_VZ_N (":done, exiting...\n");
	pthread_exit(NULL);
	return(0);
}


/*********************************/
/*thread_main_timer - Work in resolution of 10msec*/
/*********************************/
void *thread_main_timer()
{
	int fd;
	struct itimerspec new_value;
	struct timespec now;
	uint64_t exp;
	ssize_t res;

	/* Get the current time*/
	if (clock_gettime(CLOCK_REALTIME, &now) == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):clock_gettime error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	/* Create a CLOCK_REALTIME absolute timer with initial expiration and interval */
	new_value.it_value.tv_sec = now.tv_sec;
	new_value.it_value.tv_nsec = now.tv_nsec;
	new_value.it_interval.tv_sec = 0;
	new_value.it_interval.tv_nsec = TIMER_10MSEC_IN_NSEC;

	fd = timerfd_create(CLOCK_REALTIME, 0);
	if (fd == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):timerfd_create error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
	if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &new_value, NULL) == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):timerfd_settime error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	while (all_RX_threads_done != cfg.int_v.rx_num_of_threads.val)
	{ /*will be performed every 10msec*/
		res = read(fd, &exp, sizeof(uint64_t));

		if (res != sizeof(uint64_t))
		{
			snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d):timerfd read error - %s\n",FUNC_LINE, strerror(errno));
			exit_vz(EXIT_FAILURE, exit_buf);
		}

		uint slice_100_msec_changed = 0;
		uint silce_1_sec_changed = 0;


		/*increment run_time 10 msec*/
		if (run_time.slice_10_msec == 99)
		{
			run_time.slice_10_msec = 0;
		}
		else
		{
			run_time.slice_10_msec++;
		}

		/*increment run_time 100msec*/
		if ((run_time.slice_10_msec % 10) == 0)
		{
			slice_100_msec_changed  = 1;
			if (run_time.slice_10_msec == 0)
			{ /*eliminate the ++ not to reach to 10, since other threads will look on this counter, and context switch may cause the counter to be 10*/
				run_time.slice_100_msec = 0;
			}
			else
			{
				run_time.slice_100_msec++;
			}
		}

		/*increment run_time 1 sec*/
		if ((slice_100_msec_changed) && (run_time.slice_100_msec == 0))
		{
			silce_1_sec_changed = 1;
			run_time.sec++;
		}

		/*wake up 10msec processor thread*/
		if (cfg.flag.range.val)
		{/*for now, the only one uses 10msec processing is range*/
			pthread_mutex_unlock(&mutex_timer_10_msec_process);
		}

		/*wake up 100msec processor thread*/
		if (slice_100_msec_changed)
		{
			pthread_mutex_unlock(&mutex_timer_100_msec_process);
		}

		/*wake up 1 sec processor thread*/
		if (silce_1_sec_changed)
		{
			pthread_mutex_unlock(&mutex_timer_1_sec_process);
		}
	}

	shutdown_now();
	pthread_mutex_unlock(&mutex_timer_1_sec_process);
	pthread_join(th_1_sec_process, NULL);

	pthread_mutex_unlock(&mutex_timer_100_msec_process);
	pthread_join(th_100_msec_process, NULL);

	pthread_mutex_unlock(&mutex_timer_10_msec_process);
	pthread_join(th_10_msec_process, NULL);

	DBG_RX	PRINTF_VZ_N (":done, exiting...\n");
	pthread_exit(NULL);
	return(0);
}

void timer_threads_creator()
{
	pthread_mutex_init(&mutex_timer_10_msec_process , NULL);
	pthread_mutex_init(&mutex_timer_100_msec_process , NULL);
	pthread_mutex_init(&mutex_timer_1_sec_process , NULL);

	pthread_mutex_lock(&mutex_timer_10_msec_process);
	pthread_mutex_lock(&mutex_timer_100_msec_process);
	pthread_mutex_lock(&mutex_timer_1_sec_process);

	if (pthread_create(&th_main_timer, 0, thread_main_timer, NULL ) != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() thread_timer error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	if (pthread_create(&th_10_msec_process, 0, thread_10_msec_process, NULL ) != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() thread_10_msec_process error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	if (pthread_create(&th_100_msec_process, 0, thread_100_msec_process, NULL ) != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() thread_100_msec_process error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	if (pthread_create(&th_1_sec_process, 0, thread_1_sec_process, NULL ) != 0)
	{
		snprintf(exit_buf, EXIT_BUF_LEN, "%s(%d):pthread_create() thread_1_sec_process error - %s\n",FUNC_LINE, strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}
}
