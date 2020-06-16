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

#include "qemu/osdep.h"
#include <linux/kvm.h>
#include "qemu-common.h"
#include "pt/memory_access.h"
#include "pt/hypercall.h"
#include "pt/printk.h"

enum reg_types{RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8, R9, R10, R11, R12, R13, R14, R15, RIP};

uint8_t types[] = {RSI, RDX, RCX, R8, R9} ;
/* calling convention: RDI, RSI, RDX, RCX, R8, R9 */

/* https://www.kernel.org/doc/Documentation/printk-formats.txt :-( */

bool kafl_linux_printk(CPUState *cpu){
	X86CPU *x86_cpu = X86_CPU(cpu);
    CPUX86State *env = &x86_cpu->env;

	char printk_buf[0x1000];

	uint8_t rsp_buf[0x1000];
	uint8_t rdi_buf[0x1000];
	uint8_t rsi_buf[0x1000];
	uint8_t rdx_buf[0x1000];
	uint8_t rcx_buf[0x1000];
	uint8_t r8_buf[0x1000];
	uint8_t r9_buf[0x1000];

	read_virtual_memory((uint64_t)env->regs[RSP], (uint8_t*)rsp_buf, 0x1000, cpu);
	read_virtual_memory((uint64_t)env->regs[RDI], (uint8_t*)rdi_buf, 0x1000, cpu);

	uint8_t* buf[] = {rsi_buf, rdx_buf, rcx_buf, r8_buf, r9_buf};

	

	for(uint16_t i = 0, type = 0; i < 0x1000 && rdi_buf[i] != '\x00'; i++){

		if(i > 1 && rdi_buf[i-2] == '%' && rdi_buf[i-1] != '%'){
			
			if(rdi_buf[i-1] == 's' || rdi_buf[i-1] == 'p' || rdi_buf[i-1] == '.'){

				
				if(rdi_buf[i] == 'B'){
					rdi_buf[i-1] = 'l';
					rdi_buf[i] = 'x';
					buf[type] = (uint8_t*)env->regs[types[type]];
				}

				else if(rdi_buf[i-1] == 'p' && rdi_buf[i] == 'V'){
					rdi_buf[i-1] = 's';
					rdi_buf[i] = ' ';
					read_virtual_memory((uint64_t)env->regs[types[type]],  (uint8_t*)buf[type], 0x1000, cpu);
					uint64_t tmp = *((uint64_t*)buf[type]);
					read_virtual_memory(tmp,  (uint8_t*)buf[type], 0x1000, cpu);

				}
				else if(rdi_buf[i-1] == 'p'){
					rdi_buf[i-1] = 'l';
					memmove(rdi_buf+i+1, rdi_buf+i, 0x1000-i-1);
					rdi_buf[i] = 'x';
					buf[type] = (uint8_t*)env->regs[types[type]];
					
				}
				else {
					read_virtual_memory((uint64_t)env->regs[types[type]],  (uint8_t*)buf[type], 0x1000, cpu);
				}
			}
			else{
				buf[type] = (uint8_t*)env->regs[types[type]];
			}

			type++;


			if(type > 4){
				rdi_buf[i] = '\n';
				rdi_buf[i+1] = '\x00';
				break;
			}
		}

	}

	snprintf(printk_buf, 0x1000, (char*)rdi_buf, buf[0], buf[1], buf[2], buf[3], buf[4]);
	
	if(printk_buf[0] == 0x1){
		//printf("%s", rdi_buf+2);
		hprintf(printk_buf+2);
		//printf("%s", printk_buf+2);
		if(!strncmp(printk_buf+2, "---[ end Kernel panic", 21)){
			return true;
		}
	}
	else {
		//printf("%s", rdi_buf);
		hprintf(printk_buf);
		//printf("%s", printk_buf);
		if(!strncmp(printk_buf, "---[ end Kernel panic", 21)){
			return true;
		}
	}
	return false;
	
}
