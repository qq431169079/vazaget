/*
 * close.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *
 *  All rights reserved.
 *
 *  close.h is part of vazaget.
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

#ifndef CLOSE_H_
#define CLOSE_H_

typedef enum {
	REASON_RX_TCP_FIN, 		/*0*/
	REASON_RX_TCP_RST,		/*1*/
	REASON_RX_EOF,			/*2*/
	REASON_RX_READ_ERROR,	/*3*/
	REASON_RX_EPOLL_ERROR,	/*4*/
	REASON_RX_RANGE_STUCK,	/*5*/
	REASON_RX_HTTP_CLOSE,	/*6*/
	REASON_CONTENT_LENGTH_FULLY_ARRIVED,/*7*/
	REASON_FINISHED_PROCESS_SOCKET,/*8*/
	REASON_FAILED_WRITE_TO_DISC,/*9*/
	REASON_TX_FAILED_CREATING_NEW_FD,/*10*/
	REASON_TX_NO_MORE_CONNECTIONS_REQUIRED,/*11*/
	REASON_TX_FAILED_RESOLVE_IP_ADDRESS,/*12*/
	REASON_TX_CONNECT_ERROR,/*13*/
	REASON_TX_SEND_ERROR,	/*15*/
	REASON_DS_FINISHED,		/*16*/
	REASON_MAX
}CLOSE_REASON;

/*close */
uint shutdown_queue_thread();
void *thread_queue_processing();

#endif /* CLOSE_H_ */
