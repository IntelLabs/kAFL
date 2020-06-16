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

#ifndef __VMX_PT_H__
#define __VMX_PT_H__

#include "vmx.h"

struct vcpu_vmx_pt;

int vmx_pt_create_fd(struct vcpu_vmx_pt *vmx_pt_config);

bool vmx_pt_vmentry(struct vcpu_vmx_pt *vmx_pt);
bool vmx_pt_vmexit(struct vcpu_vmx_pt *vmx_pt);

int vmx_pt_setup(struct vcpu_vmx *vmx, struct vcpu_vmx_pt **vmx_pt_config);
void vmx_pt_destroy(struct vcpu_vmx *vmx, struct vcpu_vmx_pt **vmx_pt_config);

void vmx_pt_init(void);
void vmx_pt_exit(void);

int vmx_pt_enabled(void);

#endif

