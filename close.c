/* close.c
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  close.c is part of vazaget.
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
#include <fcntl.h>
#include <mqueue.h>
#include <unistd.h>
#include "global.h"
#include "data_sender.h"
#include "rx.h"
#include "rx_range.h"
#include "tx.h"
#include "close.h"

/**GLOBAL**/
mqd_t thread_msg_q = 0;               // message queue

typedef struct
{
	uint	code;
	uint	data;
}msg_q_msg_t;


typedef enum {
	CODE_SHUTDOWN,
	CODE_CLOSE_SOCKET,
	CODE_WAKE_UP_TX,
	CODE_MAX
}QUEUE_CODES;


/*********send_fd_to_close_thread()*******/
uint send_fd_to_close_thread(uint fd)
{
	int status;
	msg_q_msg_t msg_tx;

	msg_tx.code = CODE_CLOSE_SOCKET;
	msg_tx.data = fd;

	status = mq_send(thread_msg_q, (char *)(&msg_tx), sizeof(msg_tx), 1);
	if (status == -1)
	{
		DBG_CLOSE PRINTF_VZ("**ERROR** failed to send_fd_to_close_thread(fd=%d)\n", fd);
		cntr.error.failed_to_send_data_to_queue_thread++;
		return FALSE_0;
	}
	return TRUE_1;
}

/*********rearm_tx_now()*******/
uint rearm_tx_now(uint fd_idx)
{
	int status;
	msg_q_msg_t msg_tx;

	msg_tx.code = CODE_WAKE_UP_TX;
	msg_tx.data = fd_idx;

	status = mq_send(thread_msg_q, (char *)(&msg_tx), sizeof(msg_q_msg_t), 1);
	if (status == -1)
	{
		DBG_CLOSE PRINTF_VZ("**ERROR** failed to send to queue thread(fd_idx=%d), errno=%d\n", fd_idx,errno);
		cntr.error.failed_to_send_data_to_queue_thread++;
		return FALSE_0;
	}
	return TRUE_1;
}

/*********shutdown_close_thread()*******/
uint shutdown_queue_thread()
{
	int status;
	msg_q_msg_t msg_tx;

	msg_tx.code = CODE_SHUTDOWN;
	msg_tx.data = 0;

	status = mq_send(thread_msg_q, (char *)(&msg_tx), sizeof(msg_tx), 1);
	if (status == -1)
	{
		DBG_CLOSE PRINTF_VZ("**ERROR** failed to shutdown_close_thread\n");
		cntr.error.failed_to_send_data_to_queue_thread++;
		return FALSE_0;
	}
	return TRUE_1;
}


/*********thread_queue_processing()*******/
void *thread_queue_processing()
{
	struct mq_attr attr;      // message queue attributes
	//	uint rcv_msg = 0;
	msg_q_msg_t rcv_msg;
	uint running = 1;

	// Specify message queue attributes.
	attr.mq_flags = 0;                // blocking read/write
	attr.mq_maxmsg = 10;              // maximum number of messages allowed in queue
	attr.mq_msgsize = sizeof(msg_q_msg_t);    // messages are contents of an int
	attr.mq_curmsgs = 0;              // number of messages currently in queue

	// Create the message queue with some default settings.
	thread_msg_q = mq_open(THREAD_QUEUE_NAME, O_CREAT | O_RDWR , 0644, &attr);

	// -1 indicates an error.
	if (thread_msg_q == -1)
	{
		snprintf(exit_buf, EXIT_BUF_LEN,"%s(%d): **Failed** to create queue : %s\n", FUNC_LINE,strerror(errno));
		exit_vz(EXIT_FAILURE, exit_buf);
	}

	while (running)
	{
		mq_receive(thread_msg_q, (char *)(&rcv_msg), sizeof(rcv_msg), NULL); /*blocked*/

		switch (rcv_msg.code)
		{
		case CODE_SHUTDOWN:
		{
			DBG_CLOSE PRINTF_VZ("received CLOSE_THREAD_SHUTDOWN msg, exiting...\n");
			running = 0;
			break;
		}

		case CODE_CLOSE_SOCKET:
		{
			uint fd = rcv_msg.data;

			if (fd > LINUX_MAX_FD)
			{
				DBG_CLOSE PRINTF_VZ("**ERROR** close illegal fd=%d\n",fd);
				cntr.error.illegal_fd_to_close++;
			}
			else
			{
				DBG_CLOSE PRINTF_VZ("Closing fd=%d\n",fd);
				if (close((int)fd) != 0 /*shutdown(rcv_msg , SHUT_RDWR)*/)
				{
					cntr.error.close_error++;
					DBG_CLOSE PRINTF_VZ("**ERROR** failed close fd=%d : %s\n",fd , strerror(errno));
				}
			}
			break;
		}

		case CODE_WAKE_UP_TX:
		{
			uint fd_idx = rcv_msg.data;
			PANIC(fd_idx >= max_active_sessions);
			cntr.info.tmp_rearm_tx_from_queue_thread++;
			tx_now(fd_db[fd_idx].tx.tx_th_idx);
			break;
		}

		default:
		{
			DBG_CLOSE PRINTF_VZ("**ERROR** unknow msg_code=%d , data=%d\n",rcv_msg.code , rcv_msg.data);
			cntr.error.unknown_msg_q_code++;
			break;
		}
		}
	}

	/*shut down procedure*/
	mq_close(thread_msg_q);
	mq_unlink(THREAD_QUEUE_NAME);

	pthread_exit(NULL);
	return(0);/*just to remove warning*/
}

/*********************************************/
/***********inc_close_sockets_cntr()**********************/
/*********************************************/
void inc_close_sockets_cntr(uint tx_th_idx , uint rx_th_idx)
{
	cntr.stat.close_sockets++;

	if ( CUR_ACTIVE_SESSION < 0)
	{
		cntr.warning.align_close_cntr++;
		cntr.stat.close_sockets = cntr.stat.open_sockets;
	}

	/*TX active sessions*/
	if (tx_th_db[tx_th_idx].th_active_sessions > 0)
	{
		tx_th_db[tx_th_idx].th_active_sessions--;
	}

	rx_th_db[rx_th_idx].cntr.closed_sockets++;
}

/*********************************************/
/***********check_sleep_timer()**********************/
/*********************************************/
int check_sleep_timer(uint fd_idx)
{
	/*validate fd_idx*/
	PANIC(fd_idx >= max_active_sessions);

	if (fd_db[fd_idx].rx.close_time == 0)
	{
		fd_db[fd_idx].rx.close_time = run_time.sec + (uint)cfg.int_v.delay_close_sec.val;
	}

	if (run_time.sec >= fd_db[fd_idx].rx.close_time)
	{/*timer expired, close session*/
		DBG_RX PRINTF_VZ("Wait close timer expired - closing: fd=%d, fd_idx=%d, run_time.sec=%d, fd_db[fd_idx].rx.close_time=%d \n",
				fd_db[fd_idx].gen.fd , fd_idx ,run_time.sec, fd_db[fd_idx].rx.close_time);
		return FALSE_0;
	}
	DBG_RX PRINTF_VZ("Wait timer NOT expired - waiting...: fd=%d, fd_idx=%d, run_time.sec=%d, fd_db[fd_idx].rx.close_time=%d \n",
			fd_db[fd_idx].gen.fd , fd_idx ,run_time.sec, fd_db[fd_idx].rx.close_time);
	return TRUE_1; /*wait more*/
}


/*********************************************/
/***********close_fd_db_check_range()*********/
/*********************************************/
static uint close_fd_db_handle_special_cases(uint fd_idx )
{
	if (cfg.flag.range.val)
	{
		/*the range is fully fetched and waiting to be written - don't close yet*/
		if(fd_db[fd_idx].rx.range.pending_range_to_write)
		{
			DBG_RANGE PRINTF_VZ("fd_idx=%d, there is pending range to be written, stop closing procedure, and removing from epoll...\n", fd_idx);

			remove_fd_from_epoll(fd_idx);
			cntr.info.range_pending_to_write_in_close++;
			//		wake_up_tx_thread(tx_th_idx);
			return STOP_CLOSE_FLOW;
		}

		/*the range is fully fetched and written to disk*/
		else if ((fd_db[fd_idx].rx.range.pending_range_to_write == 0) && (fd_db[fd_idx].rx.wrote_buf_to_disk == 1))
		{
			if (range_global.range_table[fd_idx].state == RANGE_HTTP_CLOSE)
			{
				DBG_RANGE PRINTF_VZ("fd_idx=%d, range fully received and written to disk, range state=%d(RANGE_HTTP_CLOSE), continue with CLOSE_SOCKET_CLEAER_DB\n",
						fd_idx  , range_global.range_table[fd_idx].state);
				return CLOSE_SOCKET_CLEAR_DB;
			}
			else
			{
				DBG_RANGE PRINTF_VZ("fd_idx=%d, range fully received and written to disk. range state=%d, continue with CLEAER_DB_ONLY\n",
						fd_idx , range_global.range_table[fd_idx].state);
				return CLEAER_DB_ONLY;
			}
		}
		/*not 200OK*/
		else if((IS_STRING_SET(fd_db[fd_idx].parser.parsed_msg.http.return_code) &&
				(strncmp(fd_db[fd_idx].parser.parsed_msg.http.return_code, "20" , strlen("20")) != 0)))
		{
			DBG_RANGE PRINTF_VZ("fd_idx=%d, ,(http return code = %s)handle only 20x return codes \n",
					fd_idx ,fd_db[fd_idx].parser.parsed_msg.http.return_code);
			return CLOSE_SOCKET_CLEAR_DB;
		}
		/*the range partially fetched and not written to disk*/
		else
		{
			range_global.range_table[fd_idx].state = RANGE_RESTART_ON_NEW_FD;
			DBG_RANGE PRINTF_VZ("fd_idx=%d, range partially fetched and not written to disk. set range state=%d(RANGE_RESTART_ON_NEW_FD), continue with CLOSE_SOCKET_CLEAER_DB\n",
					fd_idx , range_global.range_table[fd_idx].state);
			cntr.info.range_rx_restart++;
			return CLOSE_SOCKET_CLEAR_DB;
		}
	}

	cntr.warning.range_unknown_close_action++;
	DBG_RX PRINTF_VZ("fd_idx=%d, **ERROR** should not get here , continue with CLOSE_SOCKET_CLEAER_DB\n",	fd_idx);
	return CLOSE_SOCKET_CLEAR_DB;
}


/*********************************************/
/***********close_fd_db_handle_reason()**********************/
/*********************************************/
uint close_fd_db_handle_reason(uint reason)
{
	uint skip_shutdown = 0;

	switch (reason)
	{
	case REASON_RX_TCP_FIN:
	{
		cntr.info.server_close_by_FIN++;
		skip_shutdown = 0;
		break;
	}
	case REASON_RX_TCP_RST:
	{
		cntr.info.server_close_by_RST++;
		skip_shutdown = 0;
		break;
	}
	case REASON_RX_EOF:
	{
		cntr.warning.close_by_server++;
		skip_shutdown = 1;
		break;
	}
	case REASON_RX_READ_ERROR:
	{
		cntr.error.read_error++;
		skip_shutdown = 0;
		break;
	}
	case REASON_RX_EPOLL_ERROR:
	{
		cntr.error.epoll_error++;
		skip_shutdown = 0;
		break;
	}
	case REASON_RX_HTTP_CLOSE:
	{
		skip_shutdown = 0;
		break;
	}
	case REASON_CONTENT_LENGTH_FULLY_ARRIVED:
	{
		cntr.info.tmp_close_content_complete++;
		skip_shutdown = 0;
		break;
	}
	case REASON_FINISHED_PROCESS_SOCKET:
	{
		skip_shutdown = 0;
		break;
	}
	case REASON_FAILED_WRITE_TO_DISC:
	{
		cntr.warning.failed_writing_to_disk++;
		skip_shutdown = 0;
		break;
	}
	case REASON_TX_FAILED_CREATING_NEW_FD:
	{
		cntr.error.create_new_fd_db++;
		skip_shutdown = 1;
		break;
	}
	case REASON_TX_NO_MORE_CONNECTIONS_REQUIRED:
	{
		skip_shutdown = 1;
		break;
	}
	case REASON_TX_FAILED_RESOLVE_IP_ADDRESS:
	{
		cntr.error.inet_pton_error++;
		skip_shutdown = 0;
		break;
	}
	case REASON_TX_CONNECT_ERROR:
	{
		cntr.error.connect_error++;
		skip_shutdown = 0;
		break;
	}
	case REASON_TX_SEND_ERROR:
	{
		cntr.error.send_error++;
		skip_shutdown = 0;
		break;
	}
	case REASON_RX_RANGE_STUCK:
	{
		cntr.warning.range_stuck_force_restart++;
		skip_shutdown = 0;
		break;
	}
	default:
	{
		cntr.warning.unknow_close_reason++;
		skip_shutdown = 0;
		break;
	}
	}
	return skip_shutdown;
}

/*********************************************/
/***********close_socket()**********************/
/*********************************************/
void close_socket(uint fd_idx, uint skip_shutdown)
{
	DBG_CLOSE PRINTF_VZ("Trying to Close fd=%d, fd_idx=%d, skip_shutdown=%d, cntr.stat.close_sockets=%d\n",fd_db[fd_idx].gen.fd , fd_idx, skip_shutdown ,cntr.stat.close_sockets);

	if (skip_shutdown == 0)
	{/*close will also remove fd from epoll*/
		DS_PRINT PRINTF_VZ_N ("[%s][Closing socket %d...]\n",elapse_time,fd_db[fd_idx].gen.fd);
		PANIC_NO_DUMP(fd_db[fd_idx].gen.fd <= 2);

		if (fd_db[fd_idx].ssl_db.is_ssl)
		{
			int ret = mbedtls_ssl_close_notify( &fd_db[fd_idx].ssl_db.ssl );
			mbedtls_ssl_free( &fd_db[fd_idx].ssl_db.ssl );
			DBG_SSL PRINTF_VZ(" fd_idx=%d, ssl_close_notify() ret = %d\n", fd_idx , ret);
		}

		/*send sockets to close on close thread*/
		if (!cfg.flag.close_thread_dis.val)
		{
			remove_fd_from_epoll(fd_idx); /*will need to remove it from epoll, can't tell when close will be*/
			send_fd_to_close_thread((uint)fd_db[fd_idx].gen.fd);
		}
		/*close the socket from current thread (rx)*/
		else
		{
			if (close(fd_db[fd_idx].gen.fd) != 0 /*shutdown(fd_db[fd_idx].gen.fd , SHUT_RDWR)*/)
			{
				cntr.error.close_error++;
				DBG_CLOSE PRINTF_VZ("close error fd=%d, fd_idx=%d - %s\n",fd_db[fd_idx].gen.fd , fd_idx ,  strerror(errno));
			}
			else
			{
				DBG_CLOSE PRINTF_VZ("Closing fd=%d, fd_idx=%d, cntr.stat.close_sockets=%d\n",fd_db[fd_idx].gen.fd , fd_idx ,cntr.stat.close_sockets);
			}
		}
	}
	else
	{
		if ((fd_db[fd_idx].gen.fd > 2) && (!cfg.flag.socket_resue.val))
		{
			remove_fd_from_epoll(fd_idx);
		}
		cntr.info.close_skip_shutdown++;
	}
}

/*********************************************/
/***********close_fd_db()**********************/
/*********************************************/
void close_fd_db(uint fd_idx , uint reason)
{/* Closing the descriptor will make epoll remove it from the set of descriptors which are monitored. */
	uint tx_th_idx , rx_th_idx , ret, clear_db_level = CLEAR_DB_FULL;
	uint skip_shutdown = 0;

	/*validate fd_idx*/
	if (fd_idx > max_active_sessions)
	{
		cntr.error.Illegal_fd_idx++;
		return;
	}

	if (fd_db[fd_idx].gen.state == STATE_CLOSE)
	{
		cntr.warning.double_close++;
		return;
	}

	cntr.info.tmp_clsoe_fd_db_start++;

	skip_shutdown = close_fd_db_handle_reason(reason);

	DBG_CLOSE PRINTF_VZ("fd_idx=%d, reason=%u , skip_shutdown=%u\n",	fd_idx , reason , skip_shutdown);

	tx_th_idx = fd_db[fd_idx].tx.tx_th_idx;
	rx_th_idx = fd_db[fd_idx].rx.rx_th_idx;

	/*handle range close*/
	if (((cfg.flag.range.val) || (cfg.flag.socket_resue.val))
			&& (fd_db[fd_idx].gen.fd > 2))
	{
		ret = close_fd_db_handle_special_cases(fd_idx);
		switch(ret)
		{
		case CLOSE_SOCKET_CLEAR_DB:
		{
			skip_shutdown = 0;
			clear_db_level = CLEAR_DB_FULL;
			cntr.info.tmp_clsoe_clear_db_full++;
			break;
		}
		case CLEAER_DB_ONLY:
		{
			skip_shutdown = 1;
			clear_db_level = CLEAR_DB_PARTIAL;
			cntr.info.tmp_clsoe_clear_db_partial++;
			break;
		}
		case STOP_CLOSE_FLOW:
			return;
		default:
			break;
		}
		DBG_RANGE PRINTF_VZ("Start Closing fd_idx=%d , ret=%d, skip_shutdown=%d...\n", fd_idx ,ret , skip_shutdown );
	}

	if (cfg.int_v.delay_close_sec.val)
	{
		int wait_more = check_sleep_timer(fd_idx);
		if (wait_more)
		{
			return;
		}
	}

	/*from this point there is no way back, data base clear, and fd will be close if needed...*/
	fd_db[fd_idx].gen.state = STATE_CLOSE;

	if (fd_db[fd_idx].gen.fd <= 2) /*2=STDERR cannot be smaller then this */
	{
		if (reason != REASON_TX_NO_MORE_CONNECTIONS_REQUIRED)
		{
			cntr.error.Illegal_fd_to_close++;
			skip_shutdown = 1;
		}
	}

	/*start closing process*/
	DBG_CLOSE PRINTF_VZ("fd_idx=%d, fd=%d, calling to close_socket(skip_shutdown=%d)\n",
			 fd_idx, fd_db[fd_idx].gen.fd , skip_shutdown);
	close_socket(fd_idx, skip_shutdown);


	clear_fd_db(fd_idx , clear_db_level);

	if (reason != REASON_TX_NO_MORE_CONNECTIONS_REQUIRED)
	{
		inc_close_sockets_cntr(tx_th_idx , rx_th_idx);
	}
	wake_up_tx_thread(tx_th_idx);

	return;
}



