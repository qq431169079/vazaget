/* buf_manager.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  buf_manager.h is part of vazaget.
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

#ifndef BUF_MANAGER_H_
#define BUF_MANAGER_H_

typedef enum {
	BUF_NOT_IN_USE = 0,
	BUF_GET ,
	BUF_RETURN ,

	BUF_MAX
}BUF_TRACE;




#endif /* BUF_MANAGER_H_ */
