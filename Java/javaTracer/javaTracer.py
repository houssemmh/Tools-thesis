#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# uthreads  Trace thread creation/destruction events in high-level languages.
#           For Linux, uses BCC, eBPF.
#
# USAGE: uthreads [-l {java}] [-v] pid
#
# Copyright 2016 Sasha Goldshtein
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Oct-2016   Sasha Goldshtein   Created this.

from __future__ import print_function
import sys
sys.path.insert(0, 'traceLib')
from trace import *
import argparse
from bcc import BPF, USDT, utils
import ctypes as ct
import time
import os

examples = """examples:
    ./javathreads 12245         # trace the process 12245
"""
parser = argparse.ArgumentParser(
    description="Trace Java events",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("pid", type=int, help="process id to attach to")
parser.add_argument("-v", "--verbose", action="store_true",
    help="verbose mode: print the BPF program (for debugging purposes)")
args = parser.parse_args()

usdt = USDT(pid=args.pid)

program = """
struct java_event_t {
    u64 runtime_id;
    u32 native_id;
    char event_name[80];
    char thread_name[80];
    char gc_name[80];
    u32 tid;
    u32 pid;
};

BPF_PERF_OUTPUT(threads);

"""

thread_template = """
int %s(struct pt_regs *ctx) {
    char event_name[] = "%s";
    struct java_event_t te = {};
    u64 thread_nameptr = 0, runtime_id = 0;
    u32 native_id = 0;
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    bpf_usdt_readarg(1, ctx, &thread_nameptr);
    bpf_usdt_readarg(3, ctx, &runtime_id);
    bpf_usdt_readarg(4, ctx, &native_id);
    bpf_probe_read(&te.thread_name, sizeof(te.thread_name), (void *)thread_nameptr);
    te.runtime_id = runtime_id;
    te.native_id = native_id;
    te.tid = tid;
    te.pid = pid;
    __builtin_memcpy(&te.event_name, event_name, sizeof(te.event_name));
    threads.perf_submit(ctx, &te, sizeof(te));
    return 0;
}
"""

gc_template = """
int %s(struct pt_regs *ctx) {
    char event_name[] = "%s";
    struct java_event_t te = {};
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id >> 32; // PID is higher part
    u32 tid = id;       // Cast and get the lower part
    te.tid = tid;
    te.pid = pid;
    __builtin_memcpy(&te.event_name, event_name, sizeof(te.event_name));
    threads.perf_submit(ctx, &te, sizeof(te));
    return 0;
}
"""

program += thread_template % ("thread__start", "thread__start")
program += thread_template % ("thread__stop", "thread__stop")
program += gc_template % ("gc__begin", "gc__begin")
program += gc_template % ("gc__end", "gc__end")
usdt.enable_probe_or_bail("gc__begin", "gc__begin")
usdt.enable_probe_or_bail("gc__end", "gc__end")
usdt.enable_probe_or_bail("thread__start", "thread__start")
usdt.enable_probe_or_bail("thread__stop", "thread__stop")

if args.verbose:
    print(usdt.get_text())
    print(program)

bpf = BPF(text=program, usdt_contexts=[usdt])
print("Tracing thread events in process %d ... Ctrl-C to quit." %
      (args.pid))

class JavaEvent(ct.Structure):
    _fields_ = [
        ("runtime_id", ct.c_ulonglong),
        ("native_id", ct.c_int32),
        ("event_name", ct.c_char * 80),
        ("thread_name", ct.c_char * 80),
        ("gc_name", ct.c_char * 80),
        ("tid", ct.c_int32),
        ("pid", ct.c_int32),
        ]

start_ts = time.time()

def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(JavaEvent)).contents
    tid = int("%s" % event.tid)
    pid = int("%s" % event.pid)
    print(event.event_name+ " " + str(tid) + " " + str(pid))
    if event.event_name == "thread__start":
        tracepoint("thread__start", event.thread_name, event.runtime_id, event.native_id, 0, 0, tid, pid)
    if event.event_name == "thread__stop":
        tracepoint("thread__stop", event.thread_name, event.runtime_id, event.native_id, 0, 0, tid, pid)
    if event.event_name == "gc__begin":
        tracepoint("gc__begin", 1, 1, 1, tid, pid)
    if event.event_name == "gc__end":
        tracepoint("gc__end", 1, 1, 1, tid, pid)

bpf["threads"].open_perf_buffer(print_event)
while 1:
    bpf.kprobe_poll()
