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

#ifndef HYPERCALL_H
#define HYPERCALL_H

#define PAYLOAD_BUFFER_SIZE		26
#define PRINTK_PAYLOAD_SIZE		4

#define KAFL_MODE_64	0
#define KAFL_MODE_32	1
#define KAFL_MODE_16	2

typedef struct{
	uint64_t ip[4];
	uint64_t size[4];
	uint8_t enabled[4];
} kAFL_ranges; 

//#define PANIC_DEBUG

/*
 * Panic Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x8
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define PANIC_PAYLOAD "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x08\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x0F\x01\xC1\xF4"

/*
 * KASAN Notifier Payload (x86-64)
 * fa                      cli
 * 48 c7 c0 1f 00 00 00    mov    rax,0x1f
 * 48 c7 c3 08 00 00 00    mov    rbx,0x9
 * 48 c7 c1 00 00 00 00    mov    rcx,0x0
 * 0f 01 c1                vmcall
 * f4                      hlt
 */
#define KASAN_PAYLOAD "\xFA\x48\xC7\xC0\x1F\x00\x00\x00\x48\xC7\xC3\x09\x00\x00\x00\x48\xC7\xC1\x00\x00\x00\x00\x0F\x01\xC1\xF4"

/*
 * printk Notifier Payload (x86-64)
 * 0f 01 c1                vmcall
 * c3                      retn
 */
#define PRINTK_PAYLOAD "\x0F\x01\xC1\xC3"

void pt_setup_program(void* ptr);
void pt_setup_payload(void* ptr);
void pt_setup_snd_handler(void (*tmp)(char, void*), void* tmp_s);
void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end, void* filter_bitmap, void* tfilter_bitmap);
void pt_setup_enable_hypercalls(void);

void pt_disable_wrapper(CPUState *cpu);

void hypercall_submit_address(uint64_t address);
bool hypercall_check_tuple(uint64_t current_addr, uint64_t prev_addr);
void hypercall_check_in_range(uint64_t* addr);


bool hypercall_check_transition(uint64_t value);
void hypercall_submit_transition(uint32_t value);

void hypercall_enable_filter(void);
void hypercall_disable_filter(void);
void hypercall_commit_filter(void);

bool pt_hypercalls_enabled(void);

void hypercall_unlock(void);
void hypercall_reload(void);

void handle_hypercall_kafl_acquire(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_get_payload(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_get_program(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_release(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_cr3(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_submit_panic(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_submit_kasan(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_panic(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_kasan(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_timeout(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_lock(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_info(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_printf(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_printk_addr(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_printk(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_user_range_advise(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_user_submit_mode(struct kvm_run *run, CPUState *cpu);
void handle_hypercall_kafl_user_abort(struct kvm_run *run, CPUState *cpu);

void hprintf(char* msg);
void enable_hprintf(void);
void enable_notifies(void);
void enable_reload_mode(void);
void pt_setup_disable_create_snapshot(void);

bool handle_hypercall_kafl_next_payload(struct kvm_run *run, CPUState *cpu);
void hypercall_reset_hprintf_counter(void);
bool hypercall_snd_char(char val);

#ifdef CONFIG_REDQUEEN


bool handle_hypercall_kafl_hook(struct kvm_run *run, CPUState *cpu);
bool handle_hypercall_kafl_mtf(struct kvm_run *run, CPUState *cpu);
void pt_enable_rqo(CPUState *cpu);
void pt_disable_rqo(CPUState *cpu);
void pt_enable_rqi(CPUState *cpu);
void pt_disable_rqi(CPUState *cpu);
void pt_enable_rqi_trace(CPUState *cpu);
void pt_disable_rqi_trace(CPUState *cpu);
void pt_set_redqueen_instrumentation_mode(CPUState *cpu, int redqueen_instruction_mode);
void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval);
void pt_set_enable_patches_pending(CPUState *cpu);
void pt_set_disable_patches_pending(CPUState *cpu);
#endif
#endif
