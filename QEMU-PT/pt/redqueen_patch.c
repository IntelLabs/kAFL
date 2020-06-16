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

#include "redqueen_patch.h"
#include "redqueen.h"
#include "patcher.h"
#include "file_helper.h"
#include "debug.h"

///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Declarations
///////////////////////////////////////////////////////////////////////////////////

void _load_and_set_patches(patcher_t* self);

///////////////////////////////////////////////////////////////////////////////////
// Public Functions
///////////////////////////////////////////////////////////////////////////////////

void pt_enable_patches(patcher_t *self){
  _load_and_set_patches(self);
  patcher_apply_all(self);
}

void pt_disable_patches(patcher_t *self){
  patcher_restore_all(self);
}


///////////////////////////////////////////////////////////////////////////////////
// Private Helper Functions Definitions
///////////////////////////////////////////////////////////////////////////////////


void _load_and_set_patches(patcher_t* self){
  size_t num_addrs = 0;
  uint64_t *addrs = NULL;
  parse_address_file(redqueen_workdir.redqueen_patches, &num_addrs, &addrs);
  if(num_addrs){
    patcher_set_addrs(self, addrs, num_addrs);
    free(addrs);
  }
}
