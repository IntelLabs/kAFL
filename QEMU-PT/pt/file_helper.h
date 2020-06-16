/* 
# This file is part of Redqueen.
#
# Sergej Schumilo, 2019 <sergej@schumilo.de> 
# Cornelius Aschermann, 2019 <cornelius.aschermann@rub.de> 
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

//doesn't take ownership of path, num_addrs or addrs
void parse_address_file(char* path, size_t* num_addrs, uint64_t** addrs);

//doesn't take ownership of buf
void write_re_result(char* buf);

//doesn't take ownership of buf
void write_se_result(char* buf);

//doesn't take ownership of buf
void write_trace_result(char* buf);

//doesn' take ownership of buf
void write_debug_result(char* buf);

void delete_redqueen_files(void);

void delete_trace_files(void);
