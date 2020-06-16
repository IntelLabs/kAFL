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
#include "qapi/error.h"
#include "qemu/cutils.h"
#include "hw/hw.h"
#include "hw/i386/pc.h"
#include "hw/pci/pci.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "sysemu/kvm.h"
#include "migration/migration.h"
#include "qemu/error-report.h"
#include "qemu/event_notifier.h"
#include "qom/object_interfaces.h"
#include "sysemu/char.h"
#include "sysemu/hostmem.h"
#include "sysemu/qtest.h"
#include "qapi/visitor.h"
#include "exec/ram_addr.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include "pt.h"
#include "pt/hypercall.h"
#include "pt/filter.h"
#include "pt/interface.h"
#include "pt/debug.h"
#include "pt/synchronization.h"
#include "pt/asm_decoder.h"

#include <time.h>

#ifdef CONFIG_REDQUEEN
#include "redqueen.h"
#endif

#define CONVERT_UINT64(x) (uint64_t)(strtoull(x, NULL, 16))

#define TYPE_KAFLMEM "kafl"
#define KAFLMEM(obj) \
		OBJECT_CHECK(kafl_mem_state, (obj), TYPE_KAFLMEM)

uint32_t kafl_bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;

static void pci_kafl_guest_realize(DeviceState *dev, Error **errp);

typedef struct kafl_mem_state {
	DeviceState parent_obj;

	Chardev *kafl_chr_drv_state;
	CharBackend chr;
	
	char* redqueen_workdir;
	char* data_bar_fd_0;
	char* data_bar_fd_1;
	char* data_bar_fd_2;
	char* bitmap_file;

	char* filter_bitmap[4];
	char* ip_filter[4][2];

	bool irq_filter;
	uint64_t bitmap_size;

	bool debug_mode; 	/* support for hprintf */
	bool notifier;
	bool reload_mode;
	bool disable_snapshot;
	bool lazy_vAPIC_reset;

#ifdef CONFIG_REDQUEEN
	bool redqueen;
#endif
	
} kafl_mem_state;

static void kafl_guest_event(void *opaque, int event){
}

static void send_char(char val, void* tmp_s){
	kafl_mem_state *s = tmp_s;
	qemu_chr_fe_write(&s->chr, (const uint8_t *) &val, 1);
}

static int kafl_guest_can_receive(void * opaque){
	return sizeof(int64_t);
}

static void kafl_guest_receive(void *opaque, const uint8_t * buf, int size){
	kafl_mem_state *s = opaque;
	int i;				
	for(i = 0; i < size; i++){
		switch(buf[i]){
			case KAFL_PROTO_RELEASE:
				synchronization_unlock();
				break;

			case KAFL_PROTO_RELOAD:
				assert(false);
				synchronization_reload_vm();
				break;

			/* active sampling mode */
			case KAFL_PROTO_ENABLE_SAMPLING:	
				hypercall_enable_filter();
				break;

			/* deactivate sampling mode */
			case KAFL_PROTO_DISABLE_SAMPLING:
				hypercall_disable_filter();
				break;

			/* commit sampling result */
			case KAFL_PROTO_COMMIT_FILTER:
				hypercall_commit_filter();
				break;

			/* finalize iteration (dump and decode PT data) in case of timeouts */
			case KAFL_PROTO_FINALIZE:
				synchronization_disable_pt(qemu_get_cpu(0));
				send_char('F', s);
				break;
#ifdef CONFIG_REDQUEEN
				
			/* enable redqueen intercept mode */
			case KAFL_PROTO_ENABLE_RQI_MODE:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto enable rqi");
				assert(qemu_get_cpu(0)->redqueen_instrumentation_mode != REDQUEEN_NO_INSTRUMENTATION);
				pt_enable_rqi(qemu_get_cpu(0));
				send_char(KAFL_PROTO_ENABLE_RQI_MODE, s);
				break;

			/* disable redqueen intercept mode */
			case KAFL_PROTO_DISABLE_RQI_MODE:
				 //QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto disable rqi");
				pt_set_redqueen_instrumentation_mode(qemu_get_cpu(0),REDQUEEN_NO_INSTRUMENTATION);
				pt_set_redqueen_update_blacklist(qemu_get_cpu(0), false);
				pt_disable_rqi(qemu_get_cpu(0));
				send_char(KAFL_PROTO_DISABLE_RQI_MODE, s);
				break;

			case KAFL_PROTO_REDQUEEN_SET_LIGHT_INSTRUMENTATION:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto set light");
				pt_set_redqueen_instrumentation_mode(qemu_get_cpu(0),REDQUEEN_LIGHT_INSTRUMENTATION);
				send_char(KAFL_PROTO_REDQUEEN_SET_LIGHT_INSTRUMENTATION, s);
				break;

			case KAFL_PROTO_REDQUEEN_SET_SE_INSTRUMENTATION:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto set se");
				pt_set_redqueen_instrumentation_mode(qemu_get_cpu(0),REDQUEEN_SE_INSTRUMENTATION);
				send_char(KAFL_PROTO_REDQUEEN_SET_SE_INSTRUMENTATION, s);
				break;

			case KAFL_PROTO_REDQUEEN_SET_WHITELIST_INSTRUMENTATION:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto set whitelist");
				pt_set_redqueen_instrumentation_mode(qemu_get_cpu(0),REDQUEEN_WHITELIST_INSTRUMENTATION);
				send_char(KAFL_PROTO_REDQUEEN_SET_WHITELIST_INSTRUMENTATION, s);
				break;

			case KAFL_PROTO_REDQUEEN_SET_BLACKLIST:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto set blacklist");
				pt_set_redqueen_update_blacklist(qemu_get_cpu(0), true);
				send_char(KAFL_PROTO_REDQUEEN_SET_BLACKLIST, s);
				break;

			/* enable symbolic execution mode */
			case KAFL_PROTO_ENABLE_TRACE_MODE:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto enable trace");
				pt_enable_rqi_trace(qemu_get_cpu(0));
				send_char(KAFL_PROTO_ENABLE_TRACE_MODE, s);
				break;

			/* disable symbolic execution mode */
			case KAFL_PROTO_DISABLE_TRACE_MODE:
 				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto disable trace");
				pt_disable_rqi_trace(qemu_get_cpu(0));
				send_char(KAFL_PROTO_DISABLE_TRACE_MODE, s);
				break;
			/* apply patches to target */
			case KAFL_PROTO_ENABLE_PATCHES:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto patches enable");
				pt_set_enable_patches_pending(qemu_get_cpu(0));
				send_char(KAFL_PROTO_ENABLE_PATCHES, s);
				break;

			/* remove all patches from the target */
			case KAFL_PROTO_DISABLE_PATCHES:
				//QEMU_PT_PRINTF(REDQUEEN_PREFIX, "proto patches disable");
				pt_set_disable_patches_pending(qemu_get_cpu(0));
				send_char(KAFL_PROTO_DISABLE_PATCHES, s);
				break;
#endif
		}
	}
}

static int kafl_guest_create_memory_bar(kafl_mem_state *s, int region_num, uint64_t bar_size, const char* file, Error **errp){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bar_size) == 0);
	stat(file, &st);
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "new shm file: (max size: %lx) %lx", bar_size, st.st_size);
	
	assert(bar_size == st.st_size);
	ptr = mmap(0, bar_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED) {
		error_setg_errno(errp, errno, "Failed to mmap memory");
		return -1;
	}

	switch(region_num){
		case 1:	pt_setup_program((void*)ptr);
				break;
		case 2:	pt_setup_payload((void*)ptr);
				break;
	}

	pt_setup_snd_handler(&send_char, s);

	return 0;
}

static void kafl_guest_setup_bitmap(kafl_mem_state *s, uint32_t bitmap_size){
	void * ptr;
	int fd;
	struct stat st;
	
	fd = open(s->bitmap_file, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	assert(ftruncate(fd, bitmap_size) == 0);
	stat(s->bitmap_file, &st);
	assert(bitmap_size == st.st_size);
	ptr = mmap(0, bitmap_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	pt_setup_bitmap((void*)ptr);
}

static void* kafl_guest_setup_filter_bitmap(kafl_mem_state *s, char* filter, uint64_t size){
	void * ptr;
	int fd;
	struct stat st;
	
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "setup filter file: %s", filter);
	fd = open(filter, O_CREAT|O_RDWR, S_IRWXU|S_IRWXG|S_IRWXO);
	stat(filter, &st);
	if (st.st_size != size){
		assert(ftruncate(fd, size) == 0);
	}
	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	QEMU_PT_PRINTF(INTERFACE_PREFIX, "filter file size: %lx (addr: %p)", size, ptr);
	return ptr;
	//pt_setup_bitmap((void*)ptr);
}

static void pci_kafl_guest_realize(DeviceState *dev, Error **errp){
	uint64_t tmp0, tmp1;
	kafl_mem_state *s = KAFLMEM(dev);
	void* tmp = NULL;

	void* tfilter = kafl_guest_setup_filter_bitmap(s, (char*) "/dev/shm/kafl_tfilter", DEFAULT_EDGE_FILTER_SIZE);

	if(s->bitmap_size <= 0){
		s->bitmap_size = DEFAULT_KAFL_BITMAP_SIZE;
	}
	kafl_bitmap_size = (uint32_t)s->bitmap_size;
	
	if (s->data_bar_fd_0 != NULL)
		kafl_guest_create_memory_bar(s, 1, PROGRAM_SIZE, s->data_bar_fd_0, errp);
	if (s->data_bar_fd_1 != NULL)
		kafl_guest_create_memory_bar(s, 2, PAYLOAD_SIZE, s->data_bar_fd_1, errp);
	if (s->redqueen_workdir){
		setup_redqueen_workdir(s->redqueen_workdir);
	}
	
	if(&s->chr)
		qemu_chr_fe_set_handlers(&s->chr, kafl_guest_can_receive, kafl_guest_receive, kafl_guest_event, s, NULL, true);
	if(s->bitmap_file)
		kafl_guest_setup_bitmap(s, kafl_bitmap_size);

	for(uint8_t i = 0; i < INTEL_PT_MAX_RANGES; i++){
		if(s->ip_filter[i][0] && s->ip_filter[i][1]){
			tmp0 = CONVERT_UINT64(s->ip_filter[i][0]);
			tmp1 = CONVERT_UINT64(s->ip_filter[i][1]);
			if (tmp0 < tmp1){
				tmp = NULL;
				if(s->filter_bitmap[i]){
					tmp = kafl_guest_setup_filter_bitmap(s, s->filter_bitmap[i], (uint64_t)(tmp1-tmp0));
				}
				pt_setup_ip_filters(i, tmp0, tmp1, tmp, tfilter);
			}
		}
	}

	if(s->irq_filter){
	}

	if(s->debug_mode){
		enable_hprintf();
	}

	if(s->notifier){
		enable_notifies();
	}

	if(s->reload_mode){
		enable_reload_mode();
	}

	if(s->disable_snapshot){
		pt_setup_disable_create_snapshot();
	}

	if(s->lazy_vAPIC_reset){
    assert(false);
	}


	pt_setup_enable_hypercalls();
  asm_decoder_compile();
}

static Property kafl_guest_properties[] = {
	DEFINE_PROP_CHR("chardev", kafl_mem_state, chr),
	DEFINE_PROP_STRING("redqueen_workdir", kafl_mem_state, redqueen_workdir),
	DEFINE_PROP_STRING("shm0", kafl_mem_state, data_bar_fd_0),
	DEFINE_PROP_STRING("shm1", kafl_mem_state, data_bar_fd_1),
	DEFINE_PROP_STRING("bitmap", kafl_mem_state, bitmap_file),
	DEFINE_PROP_STRING("filter0", kafl_mem_state, filter_bitmap[0]),
	DEFINE_PROP_STRING("filter1", kafl_mem_state, filter_bitmap[1]),
	DEFINE_PROP_STRING("filter2", kafl_mem_state, filter_bitmap[2]),
	DEFINE_PROP_STRING("filter3", kafl_mem_state, filter_bitmap[3]),
	/* 
	 * Since DEFINE_PROP_UINT64 is somehow broken (signed/unsigned madness),
	 * let's use DEFINE_PROP_STRING and post-process all values via strtol...
	 */
	DEFINE_PROP_STRING("ip0_a", kafl_mem_state, ip_filter[0][0]),
	DEFINE_PROP_STRING("ip0_b", kafl_mem_state, ip_filter[0][1]),
	DEFINE_PROP_STRING("ip1_a", kafl_mem_state, ip_filter[1][0]),
	DEFINE_PROP_STRING("ip1_b", kafl_mem_state, ip_filter[1][1]),
	DEFINE_PROP_STRING("ip2_a", kafl_mem_state, ip_filter[2][0]),
	DEFINE_PROP_STRING("ip2_b", kafl_mem_state, ip_filter[2][1]),
	DEFINE_PROP_STRING("ip3_a", kafl_mem_state, ip_filter[3][0]),
	DEFINE_PROP_STRING("ip3_b", kafl_mem_state, ip_filter[3][1]),
	DEFINE_PROP_BOOL("irq_filter", kafl_mem_state, irq_filter, false),
	DEFINE_PROP_UINT64("bitmap_size", kafl_mem_state, bitmap_size, DEFAULT_KAFL_BITMAP_SIZE),
	DEFINE_PROP_BOOL("debug_mode", kafl_mem_state, debug_mode, false),
	DEFINE_PROP_BOOL("crash_notifier", kafl_mem_state, notifier, true),
	DEFINE_PROP_BOOL("reload_mode", kafl_mem_state, reload_mode, true),
	DEFINE_PROP_BOOL("disable_snapshot", kafl_mem_state, disable_snapshot, false),
	DEFINE_PROP_BOOL("lazy_vAPIC_reset", kafl_mem_state, lazy_vAPIC_reset, false),

	DEFINE_PROP_END_OF_LIST(),
};

static void kafl_guest_class_init(ObjectClass *klass, void *data){
	DeviceClass *dc = DEVICE_CLASS(klass);
	//PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);
	dc->realize = pci_kafl_guest_realize;
	//k->class_id = PCI_CLASS_MEMORY_RAM;
	dc->props = kafl_guest_properties;
	set_bit(DEVICE_CATEGORY_MISC, dc->categories);
	dc->desc = "KAFL Inter-VM shared memory";
}

static void kafl_guest_init(Object *obj){
}

static const TypeInfo kafl_guest_info = {
	.name          = TYPE_KAFLMEM,
	.parent        = TYPE_DEVICE,
	.instance_size = sizeof(kafl_mem_state),
	.instance_init = kafl_guest_init,
	.class_init    = kafl_guest_class_init,
};

static void kafl_guest_register_types(void){
	type_register_static(&kafl_guest_info);
}

type_init(kafl_guest_register_types)
