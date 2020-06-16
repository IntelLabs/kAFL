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

#include "memory_access.h"
#include "hypercall.h"
#include "debug.h"

#define x86_64_PAGE_SIZE    	0x1000
#define x86_64_PAGE_MASK   		~(x86_64_PAGE_SIZE - 1)

bool read_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu){
	uint8_t tmp_buf[x86_64_PAGE_SIZE];
	MemTxAttrs attrs;
	hwaddr phys_addr;
	int asidx;
	
  uint64_t amount_copied = 0;
	
	//cpu_synchronize_state(cpu);
	kvm_cpu_synchronize_state(cpu);

	/* copy per page */
	while(amount_copied < size){
		uint64_t len_to_copy = (size - amount_copied);
    if(len_to_copy > x86_64_PAGE_SIZE)
      len_to_copy = x86_64_PAGE_SIZE;

		asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
		attrs = MEMTXATTRS_UNSPECIFIED;
		phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

    if (phys_addr == -1){
      uint64_t next_page = (address & x86_64_PAGE_MASK) + x86_64_PAGE_SIZE;
      uint64_t len_skipped =next_page-address;  
      if(len_skipped > size-amount_copied){
        len_skipped = size-amount_copied;
      }

      QEMU_PT_PRINTF(MEM_PREFIX, "Warning, read from unmapped memory:\t%lx, skipping to %lx", address, next_page);
		  memset( data+amount_copied, ' ',  len_skipped);
      address += len_skipped;
      amount_copied += len_skipped;
      continue;
    }
		
		phys_addr += (address & ~x86_64_PAGE_MASK);
    uint64_t remaining_on_page = x86_64_PAGE_SIZE - (address & ~x86_64_PAGE_MASK);
    if(len_to_copy > remaining_on_page){
      len_to_copy = remaining_on_page;
    }
		MemTxResult txt = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, tmp_buf, len_to_copy, 0);
    if(txt){
      QEMU_PT_PRINTF(MEM_PREFIX, "Warning, read failed:\t%lx", address);
    }
		
		memcpy(data+amount_copied, tmp_buf, len_to_copy);
		
		address += len_to_copy;
		amount_copied += len_to_copy;
	}
	
	return true;
}

bool is_addr_mapped(uint64_t address, CPUState *cpu){
	MemTxAttrs attrs;
	hwaddr phys_addr;
	kvm_cpu_synchronize_state(cpu);
	attrs = MEMTXATTRS_UNSPECIFIED;
	phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);
	return phys_addr != -1;
}

bool write_virtual_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu)
{
	int asidx;
	MemTxAttrs attrs;
    hwaddr phys_addr;
    MemTxResult res;

    uint64_t counter, l, i;

    counter = size;
	while(counter != 0){
		l = x86_64_PAGE_SIZE;
        if (l > counter)
            l = counter;

	kvm_cpu_synchronize_state(cpu);
        //cpu_synchronize_state(cpu);
        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        attrs = MEMTXATTRS_UNSPECIFIED;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

        if (phys_addr == -1){
        	QEMU_PT_PRINTF(MEM_PREFIX, "phys_addr == -1:\t%lx", address);
            return false;
        }
        
        phys_addr += (address & ~x86_64_PAGE_MASK);   
        res = address_space_rw(cpu_get_address_space(cpu, asidx), phys_addr, MEMTXATTRS_UNSPECIFIED, data, l, true);
        if (res != MEMTX_OK){
        	QEMU_PT_PRINTF(MEM_PREFIX, "!MEMTX_OK:\t%lx", address);
            return false;
        }   

        i++;
        data += l;
        address += l;
        counter -= l;
	}

	return true;
}

void hexdump_virtual_memory(uint64_t address, uint32_t size, CPUState *cpu){
	assert(size < 0x100000); /* 1MB max */
	uint64_t i = 0;
	uint8_t tmp[17];
	uint8_t* data = malloc(size);
	bool success = read_virtual_memory(address, data, size, cpu);

	if(success){
		for (i = 0; i < size; i++){
	        if(!(i % 16)){
	        	if (i != 0){
                	printf ("  %s\n", tmp);
                }
	            printf ("  %04lx ", i);
	        }
	        printf (" %02x", data[i]);

	        if ((data[i] < 0x20) || (data[i] > 0x7e))
	            tmp[i % 16] = '.';
	        else
	            tmp[i % 16] = data[i];
	        tmp[(i % 16) + 1] = '\0';
	    }

	    while ((i % 16) != 0) {
	        printf ("   ");
	        i++;
	    }
	    printf ("  %s\n", tmp);
	}

	free(data);
}

bool write_virtual_shadow_memory(uint64_t address, uint8_t* data, uint32_t size, CPUState *cpu)
{
    /* Todo: later &address_space_memory + phys_addr -> mmap SHARED */
    int asidx;
    MemTxAttrs attrs;
    hwaddr phys_addr;
    MemTxResult res;

    uint64_t counter, l, i;

    void* shadow_memory = NULL;

    counter = size;
    while(counter != 0){
        l = x86_64_PAGE_SIZE;
        if (l > counter)
            l = counter;

        kvm_cpu_synchronize_state(cpu);
        //cpu_synchronize_state(cpu);
        asidx = cpu_asidx_from_attrs(cpu, MEMTXATTRS_UNSPECIFIED);
        attrs = MEMTXATTRS_UNSPECIFIED;
        phys_addr = cpu_get_phys_page_attrs_debug(cpu, (address & x86_64_PAGE_MASK), &attrs);

        if (phys_addr == -1){
            QEMU_PT_PRINTF(MEM_PREFIX, "phys_addr == -1:\t%lx", address);
            return false;
        }
        
        res = address_space_rw(cpu_get_address_space(cpu, asidx), (phys_addr + (address & ~x86_64_PAGE_MASK)), MEMTXATTRS_UNSPECIFIED, data, l, true);
        if (res != MEMTX_OK){
            QEMU_PT_PRINTF(MEM_PREFIX, "!MEMTX_OK:\t%lx", address);
            return false;
        }   

        assert(false);
        shadow_memory = 0;//*get_physmem_shadow_ptr(phys_addr);
        if (shadow_memory){
              memcpy(shadow_memory + (address & ~x86_64_PAGE_MASK), data, l);
        }
        else{
            QEMU_PT_PRINTF(MEM_PREFIX, "get_physmem_shadow_ptr(%lx) == NULL", phys_addr);
            assert(false);
            return false;
        }

        phys_addr += (address & ~x86_64_PAGE_MASK);   


        i++;
        data += l;
        address += l;
        counter -= l;
    }

    return true;
}
