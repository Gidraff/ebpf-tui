import os
from bcc import BPF
from time import sleep
import ctypes as ct


class EventData(ct.Structure):
    _fields_ = [
        ("uid", ct.c_uint32),
        ("comm", ct.c_char * 16),
        ("fname", ct.c_char * 255),
        ("flags", ct.c_int)
    ]
    
    def translate_flags(self, flags):
        str_flags = []
        if flags & 0x1:
            str_flags.append("O_RDONLY")
        if flags & 0x2:
            str_flags.append("O_WRONLY")
        if flags & 0x4:
            str_flags.append("O_RDWR")
        return "|".join(str_flags)

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(EventData)).contents
    print(f"UID: {event.uid}, Comm: {event.comm.decode()}, Filename: {event.fname.decode()}, Flags: {event.translate_flags(event.flags)}")

def main():
    with open("ebpf_program.c", "r") as f:
        bpf_program = f.read()
    
    b = BPF(text=bpf_program)
    fnname_openat = b.get_syscall_prefix().decode() + 'openat'
    
    b.attach_kprobe(event=fnname_openat, fn_name="syscall__openat")
    
    b["events"].open_perf_buffer(print_event)
    while True:
        try:
            b.perf_buffer_poll()
            sleep(1)
        except KeyboardInterrupt:
            os._exit(0)          
if __name__ == "__main__":
    main()