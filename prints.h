/*
 * prints.h
 *
 * \author Shay Vaza <vazaget@gmail.com>
 *
 *  All rights reserved.
 *
 *  prints.h is part of vazaget.
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

#ifndef PRINTS_H_
#define PRINTS_H_


/*********PRINT COLORS*******/
#define RESET   "\033[0m"
#define BLACK   "\033[30m"      /* Black */
#define RED     "\033[31m"      /* Red */
#define GREEN   "\033[32m"      /* Green */
#define YELLOW  "\033[33m"      /* Yellow */
#define BLUE    "\033[34m"      /* Blue */
#define MAGENTA "\033[35m"      /* Magenta */
#define CYAN    "\033[36m"      /* Cyan */
#define WHITE   "\033[37m"      /* White */
#define BOLDBLACK   "\033[1m\033[30m"      /* Bold Black */
#define BOLDRED     "\033[1m\033[31m"      /* Bold Red */
#define BOLDGREEN   "\033[1m\033[32m"      /* Bold Green */
#define BOLDYELLOW  "\033[1m\033[33m"      /* Bold Yellow */
#define BOLDBLUE    "\033[1m\033[34m"      /* Bold Blue */
#define BOLDMAGENTA "\033[1m\033[35m"      /* Bold Magenta */
#define BOLDCYAN    "\033[1m\033[36m"      /* Bold Cyan */
#define BOLDWHITE   "\033[1m\033[37m"      /* Bold White */

/*prints*/
void calc_cps();
void print_parse_results(parser_struct *parsed_msg);
void print_final_summary();
void print_overlap_values(void* dst_output);
void print_to_file(char *string);
void print_to_file_name(char * file_name , char *buf_to_print);
void get_tcp_info(uint fd_idx);
char* calc_time_diff(char *buf , uint size_of_buf , struct timespec start , struct timespec stop);
void print_range_table(void* dst_output , char *slide_bar , int cur_prcent);

#endif /* PRINTS_H_ */
