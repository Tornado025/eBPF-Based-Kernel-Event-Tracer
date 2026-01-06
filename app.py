import streamlit as st
import pandas as pd
from bcc import BPF
import time
import threading
import os
import ctypes as ct
from collections import deque

src_code = "eBPF Scripts"
lim=1000  # Maximum number of entries to keep in the deque

st.title("eBPF Kernel Dashboard")
st.set_page_config(layout="wide",page_title="eBPF Kernel Dashboard")

class SyscallEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("uid", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("syscall_id", ct.c_long)]

class MmapEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("length", ct.c_ulonglong),
                ("flags", ct.c_uint),
                ("event_type", ct.c_ubyte)]

class MemEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("behavior", ct.c_uint),
                ("event_type", ct.c_ubyte)]

class OpenEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("filename", ct.c_char * 256),
                ("event_type", ct.c_ubyte)]

class RwEvent(ct.Structure):
    _fields_ = [("timestamp", ct.c_ulonglong),
                ("pid", ct.c_uint),
                ("comm", ct.c_char * 16),
                ("fd", ct.c_uint),
                ("event_type", ct.c_ubyte)]
    


def load_bpf_program(filename):
    path=os.path.join(src_code, filename)
    if not os.path.exists(path):
        st.error(f"eBPF source file '{filename}' not found in '{src_code}' directory.")
        return None
    with open(path, 'r') as f:
        bpf_source = f.read()
        return BPF(text=bpf_source)
    
def startbpf():
    fileaccess=load_bpf_program("file_access.c")
    memtrace=load_bpf_program("memory_trace.c")
    syscalltrace=load_bpf_program("syscall_trace.c")

    if fileaccess:
        
