import mmap
import os
import struct
    
my_magic = 0x54502d554d4551
my_version = 0x1
my_hash = 0x51
    
HEADER_OFFSET = 0
CAP_OFFSET = 128
CONFIG_OFFSET = 384
STATUS_OFFSET = 896
MISC_OFFSET = 1408

class qemu_aux_buffer:

  def __init__(self, file):
    self.aux_buffer_fd = os.open(file, os.O_RDWR | os.O_SYNC)
    self.aux_buffer = mmap.mmap(self.aux_buffer_fd, 0x1000, mmap.MAP_SHARED, mmap.PROT_WRITE | mmap.PROT_READ) # fix this later


  def validate_header(self):
    magic = (struct.unpack('L', self.aux_buffer[0:8])[0])
    version = (struct.unpack('H', self.aux_buffer[8:10])[0])
    hash = (struct.unpack('H', self.aux_buffer[10:12])[0])

    if magic != my_magic:
      print("MAGIC MISMATCH: %x != %x\n" % (magic, my_magic))
      return False

    if version != my_version:
      print("VERSION MISMATCH: %x != %x\n" % (version, my_version))
      return False 

    if hash != my_hash:
      print("HASH MISMATCH: %x != %x\n" % (hash, my_hash))
      return False

    return True

  def print_hprintf_buffer(self):
    len = (struct.unpack('H', self.aux_buffer[MISC_OFFSET+0:MISC_OFFSET+2])[0]) 

    print('\033[0;33m' + str(self.aux_buffer[MISC_OFFSET+2:MISC_OFFSET+2+len]) + '\033[0m')


  def get_status(self):
    state     = (struct.unpack('B', self.aux_buffer[STATUS_OFFSET+0:STATUS_OFFSET+1])[0]) 
    hprintf   = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+10:STATUS_OFFSET+11])[0]) 
    exec_done = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+11:STATUS_OFFSET+12])[0]) 

    #print("STATE: " + str(state) + "\tHPRINTF: " + str(hprintf) + "\tEXEC_DONE: " + str(exec_done))

    if hprintf:
      self.print_hprintf_buffer()

    return state, exec_done

  def get_state(self):
    return self.get_status()[0]

  def get_result(self):
    result = {}

    result["crash_found"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+12:STATUS_OFFSET+13])[0]) 
    result["asan_found"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+13:STATUS_OFFSET+14])[0]) 
    result["timeout_found"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+14:STATUS_OFFSET+15])[0]) 
    result["reloaded"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+15:STATUS_OFFSET+16])[0]) 
    result["pt_overflow"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+16:STATUS_OFFSET+17])[0]) 
    result["page_not_found"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+18:STATUS_OFFSET+19])[0]) 
    result["page_fault_addr"] = (struct.unpack('Q', self.aux_buffer[STATUS_OFFSET+23:STATUS_OFFSET+31])[0]) 
    result["success"] = (struct.unpack('?', self.aux_buffer[STATUS_OFFSET+19:STATUS_OFFSET+20])[0]) 
    # result["payload_write_fault"] 
    return result

  def set_config_buffer_changed(self):
    self.aux_buffer[CONFIG_OFFSET+0] = 1

  def dump_page(self, addr):
    self.aux_buffer[CONFIG_OFFSET+10] = 1
    data = struct.pack("Q", addr)
    self.aux_buffer.seek(CONFIG_OFFSET+11)
    self.aux_buffer.write(data)
    self.aux_buffer.seek(0)
    self.set_config_buffer_changed()

  def enable_redqueen(self):
    self.aux_buffer[CONFIG_OFFSET+6] = 1
    self.set_config_buffer_changed()
    

  def disable_redqueen(self):
    self.aux_buffer[CONFIG_OFFSET+6] = 0
    self.set_config_buffer_changed()

  def set_timeout(self, sec, usec):
    data = struct.pack("<BI", sec, usec)
    self.aux_buffer.seek(CONFIG_OFFSET+1)
    self.aux_buffer.write(data)
    self.aux_buffer.seek(0)
    #self.aux_buffer[CONFIG_OFFSET+1: CONFIG_OFFSET+6] = data
    self.set_config_buffer_changed()

  def set_reload_mode(self, enable):
    self.aux_buffer[CONFIG_OFFSET+8] = int(enable)
    self.set_config_buffer_changed()
