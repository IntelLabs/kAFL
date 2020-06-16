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
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "qemu-common.h"
#include "exec/memory.h"
#include "sysemu/kvm_int.h"
#include "sysemu/kvm.h"
#include "pt.h"
#include "pt/hypercall.h"
#include "pt/filter.h"
#include "pt/memory_access.h"
#include "pt/interface.h"
#include "pt/printk.h"
#include "pt/debug.h"
#include "pt/synchronization.h"

#ifdef CONFIG_REDQUEEN
#include "pt/redqueen.h"
#endif

bool hprintf_enabled = false;
bool notifiers_enabled = false;
uint32_t hprintf_counter = 0;

bool create_snapshot_enabled = true;
bool hypercall_enabled = false;
void* payload_buffer = NULL;
void* payload_buffer_guest = NULL;
void* program_buffer = NULL;
char info_buffer[INFO_SIZE];
char hprintf_buffer[HPRINTF_SIZE];
void* argv = NULL;

static bool init_state = true;

void (*handler)(char, void*) = NULL; 
void* s = NULL;

uint64_t filter[INTEL_PT_MAX_RANGES][2];
bool filter_enabled[INTEL_PT_MAX_RANGES] = {false, false, false, false};
/* vertex filter */
filter_t *det_filter[INTEL_PT_MAX_RANGES] = {NULL, NULL, NULL, NULL};
/* edge filter */
filter_t *det_tfilter = NULL;
bool det_filter_enabled[INTEL_PT_MAX_RANGES] = {false, false, false, false};

//static void hypercall_lock(void);

void pt_setup_disable_create_snapshot(void){
	create_snapshot_enabled = false;
}

bool pt_hypercalls_enabled(void){
	return hypercall_enabled;
}

void pt_setup_enable_hypercalls(void){
	hypercall_enabled = true;
}

void pt_setup_snd_handler(void (*tmp)(char, void*), void* tmp_s){
	s = tmp_s;
	handler = tmp;
}

bool hypercall_snd_char(char val){
	if (handler != NULL){
		handler(val, s);
		return true;
	}
	return false;
}

void hypercall_reset_hprintf_counter(void){
	hprintf_counter = 0;
}

void pt_setup_ip_filters(uint8_t filter_id, uint64_t start, uint64_t end, void* filter_bitmap, void* tfilter_bitmap){
	if (filter_id < INTEL_PT_MAX_RANGES){
		filter_enabled[filter_id] = true;
		filter[filter_id][0] = start;
		filter[filter_id][1] = end;
		if (filter_bitmap){
			det_filter[filter_id] = new_filter(start, end, filter_bitmap);
			//printf("det_filter enabled\n");
			if(!det_tfilter){
				det_tfilter = new_filter(0, DEFAULT_EDGE_FILTER_SIZE, tfilter_bitmap);
				//printf("det_tfilter enabled\n");
			}
		}
	}
}

static inline void init_det_filter(void){
	int i;
	for(i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (det_filter_enabled[i]){
			filter_init_new_exec(det_filter[i]);
			filter_init_new_exec(det_tfilter);
		}	
	}
}

static inline void fin_det_filter(void){
	//printf("%s \n", __func__);
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (det_filter_enabled[i]){
			filter_finalize_exec(det_filter[i]);
			filter_finalize_exec(det_tfilter);
		}
	}
}

void hypercall_submit_address(uint64_t address){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && det_filter_enabled[i]){
			//printf("%s %lx \n", __func__, address);
			filter_add_address(det_filter[i], address);
		}
	}
}

void hypercall_submit_transition(uint32_t value){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_tfilter && det_filter_enabled[i]){
			//printf("%s %lx \n", __func__, value);
			filter_add_address(det_tfilter, value);
		}
	}
}

bool hypercall_check_tuple(uint64_t current_addr, uint64_t prev_addr){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i]){
			if(filter_is_address_nondeterministic(det_filter[i], current_addr) ||  filter_is_address_nondeterministic(det_filter[i], prev_addr)){
				return true;
			}
		}
	}
	return false;
}

bool hypercall_check_transition(uint64_t value){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_tfilter){
			if(filter_is_address_nondeterministic(det_tfilter, value)){
				return true;
			}
		}
	}
	return false;
}


void hypercall_check_in_range(uint64_t* addr){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (*addr < filter[i][0]){
			*addr = filter[i][0];
			return;
		}

		if (*addr > filter[i][1]){
			*addr = filter[i][1];
			return;
		}
	}
}

void hypercall_enable_filter(void){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && !det_filter_enabled[i]){
			//printf("%s (%d)\n", __func__, i);
			det_filter_enabled[i] = true;
			filter_init_determinism_run(det_filter[i]);
			filter_init_determinism_run(det_tfilter);
		}
	}
}

void hypercall_disable_filter(void){
	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(det_filter[i] && det_filter_enabled[i]){
			//printf("%s (%d)\n", __func__, i);
			filter_finalize_determinism_run(det_filter[i]);
			if(!filter_count_new_addresses(det_filter[i])){
				filter_finalize_determinism_run(det_tfilter);
			}
			det_filter_enabled[i] = false;
		}
	}
}

void hypercall_commit_filter(void){
	fin_det_filter();
}

bool setup_snapshot_once = false;


void pt_setup_program(void* ptr){
	program_buffer = ptr;
}

void pt_setup_payload(void* ptr){
	payload_buffer = ptr;
}

bool handle_hypercall_kafl_next_payload(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (init_state){
			synchronization_lock(cpu);
		} else {
			if(!setup_snapshot_once){  //TODO???
				pt_reset_bitmap();
				/* decrease RIP value by vmcall instruction size */
				X86CPU *x86_cpu = X86_CPU(cpu);
	    		CPUX86State *env = &x86_cpu->env;
	    		kvm_cpu_synchronize_state(cpu);
	    		env->eip -= 3; /* vmcall size */
	    		kvm_arch_put_registers(cpu, KVM_PUT_FULL_STATE);

				setup_snapshot_once = true;
				for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
					//printf("=> %d\n", i);
					if(filter_enabled[i]){
	#ifdef CONFIG_REDQUEEN
						pt_enable_ip_filtering(cpu, i, filter[i][0], filter[i][1], true, false);
	#else					
						pt_enable_ip_filtering(cpu, i, filter[i][0], filter[i][1], false);
	#endif			
					}
				}
			}
			else{
				synchronization_lock(cpu);
				write_virtual_memory((uint64_t)payload_buffer_guest, payload_buffer, PAYLOAD_SIZE, cpu);
				return true;
			}
		}
	}
	return false;
}

void handle_hypercall_kafl_acquire(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (!init_state){
			init_det_filter();
			if (pt_enable(cpu, false) == 0){
				cpu->pt_enabled = true;
			}
		}
	}
}

void handle_hypercall_get_payload(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if(payload_buffer){
			QEMU_PT_PRINTF(CORE_PREFIX, "Payload Address:\t%lx", (uint64_t)run->hypercall.args[0]);
			payload_buffer_guest = (void*)run->hypercall.args[0];
			write_virtual_memory((uint64_t)payload_buffer_guest, payload_buffer, PAYLOAD_SIZE, cpu);
		}
	}
}

void handle_hypercall_get_program(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if(program_buffer){
			QEMU_PT_PRINTF(CORE_PREFIX, "Program Address:\t%lx", (uint64_t)run->hypercall.args[0]);
			write_virtual_memory((uint64_t)run->hypercall.args[0], program_buffer, PROGRAM_SIZE, cpu);
		}
	}
}

void handle_hypercall_kafl_release(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		if (init_state){
			init_state = false;	

			hypercall_snd_char(KAFL_PROTO_RELEASE);
		} else {

			synchronization_disable_pt(cpu);
		}
	}
}


void handle_hypercall_kafl_cr3(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		//QEMU_PT_PRINTF(CORE_PREFIX, "CR3 address:\t\t%lx", (uint64_t)run->hypercall.args[0]);
		pt_set_cr3(cpu, run->hypercall.args[0], false);
	}
}

void handle_hypercall_kafl_submit_panic(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		QEMU_PT_PRINTF(CORE_PREFIX, "Panic address:\t%lx", (uint64_t)run->hypercall.args[0]);
		if(notifiers_enabled){
			write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)PANIC_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
		}
	}
}

void handle_hypercall_kafl_submit_kasan(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		QEMU_PT_PRINTF(CORE_PREFIX, "kASAN address:\t%lx", (uint64_t)run->hypercall.args[0]);
		if(notifiers_enabled){
			write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)KASAN_PAYLOAD, PAYLOAD_BUFFER_SIZE, cpu);
		}
	}
}

void handle_hypercall_kafl_panic(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
#ifdef PANIC_DEBUG
		if(cpu, run->hypercall.args[0]){
			QEMU_PT_PRINTF(CORE_PREFIX, "Panic in user mode!");
		} else{
			QEMU_PT_PRINTF(CORE_PREFIX, "Panic in kernel mode!");
		}
#endif
    QEMU_PT_PRINTF(CORE_PREFIX, "Panic detected during initialization of stage 1 or stage 2 loader");
    hypercall_snd_char(KAFL_PROTO_CRASH);
	}
}

void handle_hypercall_kafl_timeout(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
    QEMU_PT_PRINTF(CORE_PREFIX, "Timeout detected during initialization of stage 1 or stage 2 loader");
    hypercall_snd_char(KAFL_PROTO_TIMEOUT);
	}
}

void handle_hypercall_kafl_kasan(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
#ifdef PANIC_DEBUG
		if(cpu, run->hypercall.args[0]){
			QEMU_PT_PRINTF(CORE_PREFIX, "ASan notification in user mode!");
		} else{
			QEMU_PT_PRINTF(CORE_PREFIX, "ASan notification in kernel mode!");
		}
#endif
    QEMU_PT_PRINTF(CORE_PREFIX, "KASAN detected during initialization of stage 1 or stage 2 loader");
    hypercall_snd_char(KAFL_PROTO_KASAN);
	}
}

void handle_hypercall_kafl_lock(struct kvm_run *run, CPUState *cpu){
	if(create_snapshot_enabled){
		QEMU_PT_PRINTF(CORE_PREFIX, "Creating snapshot <kafl> ...");
		qemu_mutex_lock_iothread();
	    kvm_cpu_synchronize_state(qemu_get_cpu(0));
		save_vmstate(NULL, "kafl");
		qemu_mutex_unlock_iothread();
		QEMU_PT_PRINTF(CORE_PREFIX, "Done...");
		qemu_system_shutdown_request();
	}
}

void handle_hypercall_kafl_info(struct kvm_run *run, CPUState *cpu){
	read_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)info_buffer, INFO_SIZE, cpu);
	FILE* info_file_fd = fopen(INFO_FILE, "w");
	fprintf(info_file_fd, "%s\n", info_buffer);
	fclose(info_file_fd);
	if(hypercall_enabled){
		hypercall_snd_char(KAFL_PROTO_INFO);
	}
	qemu_system_shutdown_request();
}

void enable_hprintf(void){
	QEMU_PT_PRINTF(CORE_PREFIX, "Enable hprintf support");
	hprintf_enabled = true;
}

void enable_notifies(void){
	notifiers_enabled = true;
}

void enable_reload_mode(void){
  assert(false);
}

void hprintf(char* msg){
	char file_name[256];
	if(!(hprintf_counter >= HPRINTF_LIMIT) && hprintf_enabled){
		if(hypercall_enabled){
			snprintf(file_name, 256, "%s.%d", HPRINTF_FILE, hprintf_counter);
			//printf("%s: %s\n", __func__, msg);
			FILE* printf_file_fd = fopen(file_name, "w");
			fprintf(printf_file_fd, "%s", msg);
			fclose(printf_file_fd);
			hypercall_snd_char(KAFL_PROTO_PRINTF);
		}
		hprintf_counter++;

	}		
}

void handle_hypercall_kafl_printf(struct kvm_run *run, CPUState *cpu){
	//printf("%s\n", __func__);
	if(!(hprintf_counter >= HPRINTF_LIMIT) && hprintf_enabled){
		read_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)hprintf_buffer, HPRINTF_SIZE, cpu);
		hprintf(hprintf_buffer);
	}
}


void handle_hypercall_kafl_printk(struct kvm_run *run, CPUState *cpu){
	if(!notifiers_enabled){
		if (hypercall_enabled && hprintf_enabled){
			if(kafl_linux_printk(cpu)){
				handle_hypercall_kafl_panic(run, cpu);
			}
		}
	}
}

void handle_hypercall_kafl_printk_addr(struct kvm_run *run, CPUState *cpu){
	if(!notifiers_enabled){
		printf("%s\n", __func__);
		printf("%lx\n", (uint64_t)run->hypercall.args[0]);
		write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t*)PRINTK_PAYLOAD, PRINTK_PAYLOAD_SIZE, cpu);
		printf("Done\n");
	}		
}

void handle_hypercall_kafl_user_range_advise(struct kvm_run *run, CPUState *cpu){
	kAFL_ranges* buf = malloc(sizeof(kAFL_ranges));

	for(int i = 0; i < INTEL_PT_MAX_RANGES; i++){
		buf->ip[i] = filter[i][0];
		buf->size[i] = (filter[i][1]-filter[i][0]);
		buf->enabled[i] = (uint8_t)filter_enabled[i];
	}

	write_virtual_memory((uint64_t)run->hypercall.args[0], (uint8_t *)buf, sizeof(kAFL_ranges), cpu);
}

void handle_hypercall_kafl_user_submit_mode(struct kvm_run *run, CPUState *cpu){
	//printf("%s\n", __func__);
	switch((uint64_t)run->hypercall.args[0]){
		case KAFL_MODE_64:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_64 ...");
			cpu->disassembler_word_width = 64;
			break;
		case KAFL_MODE_32:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_32 ...");
			cpu->disassembler_word_width = 32;
			break;
		case KAFL_MODE_16:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in KAFL_MODE_16 ...");
			cpu->disassembler_word_width = 16;
			break;
		default:
			QEMU_PT_PRINTF(CORE_PREFIX, "target runs in unkown mode...");
			cpu->disassembler_word_width = -1;
			break;
	}
}

#ifdef CONFIG_REDQUEEN
bool handle_hypercall_kafl_hook(struct kvm_run *run, CPUState *cpu){
	X86CPU *cpux86 = X86_CPU(cpu);
    CPUX86State *env = &cpux86->env;

	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (cpu->redqueen_state[i] && (env->eip >= cpu->pt_ip_filter_a[i]) && (env->eip <= cpu->pt_ip_filter_b[i])){
			handle_hook(cpu->redqueen_state[i]);
			return true;
		}else if (cpu->singlestep_enabled && ((redqueen_t*)cpu->redqueen_state[i])->singlestep_enabled){
			handle_hook(cpu->redqueen_state[i]);
			return true;
    }
	}
	return false;
}

void handle_hypercall_kafl_user_abort(struct kvm_run *run, CPUState *cpu){
	if(hypercall_enabled){
		hypercall_snd_char(KAFL_PROTO_PT_ABORT);
	}
	qemu_system_shutdown_request();
}

void pt_enable_rqi(CPUState *cpu){
	((uint8_t*) payload_buffer)[PAYLOAD_SIZE-1] = 1;
	cpu->redqueen_enable_pending = true;
}

void pt_disable_rqi(CPUState *cpu){
	cpu->redqueen_disable_pending = true;
  cpu->redqueen_instrumentation_mode = REDQUEEN_NO_INSTRUMENTATION;
  	((uint8_t*) payload_buffer)[PAYLOAD_SIZE-1] = 0;

}

void pt_set_enable_patches_pending(CPUState *cpu){
	cpu->patches_enable_pending = true;
}

void pt_set_redqueen_instrumentation_mode(CPUState *cpu, int redqueen_mode){
  cpu->redqueen_instrumentation_mode = redqueen_mode;
}

void pt_set_redqueen_update_blacklist(CPUState *cpu, bool newval){
  assert(!newval || !cpu->redqueen_update_blacklist);
  cpu->redqueen_update_blacklist = newval;
}

void pt_set_disable_patches_pending(CPUState *cpu){
	cpu->patches_disable_pending = true;
}

void pt_enable_rqi_trace(CPUState *cpu){
	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (cpu->redqueen_state[i]) {
			redqueen_set_trace_mode((redqueen_t*)cpu->redqueen_state[i]);
		}
	}
}

void pt_disable_rqi_trace(CPUState *cpu){
	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if (cpu->redqueen_state[i] ){
			((redqueen_t*)cpu->redqueen_state[i])->trace_mode = false;
			return;
		}
	}
}

#endif
