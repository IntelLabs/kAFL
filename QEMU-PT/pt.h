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

#ifndef PT_H
#define PT_H

void pt_sync(void);
void pt_reset_bitmap(void);
void pt_setup_bitmap(void* ptr);

int pt_enable(CPUState *cpu, bool hmp_mode);
int pt_disable(CPUState *cpu, bool hmp_mode);
#ifdef CONFIG_REDQUEEN
int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, uint64_t ip_a, uint64_t ip_b, bool redqueen, bool hmp_mode);
#else
int pt_enable_ip_filtering(CPUState *cpu, uint8_t addrn, uint64_t ip_a, uint64_t ip_b, bool hmp_mode);
#endif
int pt_disable_ip_filtering(CPUState *cpu, uint8_t addrn, bool hmp_mode);
int pt_set_cr3(CPUState *cpu, uint64_t val, bool hmp_mode);

void pt_kvm_init(CPUState *cpu);
void pt_pre_kvm_run(CPUState *cpu);
void pt_post_kvm_run(CPUState *cpu);

void pt_handle_overflow(CPUState *cpu);
void pt_dump(CPUState *cpu, int bytes);
void pt_bitmap(uint64_t addr);
#endif
