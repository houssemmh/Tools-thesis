#include <stdio.h>
#include "trace_definition.h"


int trace_thread__start(int tid, int pid, long java_tid, long os_tid, char* name)
{
   tracepoint(jvm, thread_start, name, java_tid, os_tid, 0, 0, tid, pid);
   return 0;
}

int trace_thread__stop(int tid, int pid, long java_tid, long os_tid, char* name)
{
   tracepoint(jvm, thread_stop, name, java_tid, os_tid, 0, 0, tid, pid);
   return 0;
}

int trace_report_gc_start(long id, long name, long cause, int tid, int pid)
{
   tracepoint(jvm, report_gc_start, id, name, cause, tid, pid);
   return 0;
}

int trace_report_gc_end(long id, long name, long cause, int tid, int pid)
{
   tracepoint(jvm, report_gc_end, id, name, cause, tid, pid);
   return 0;
}

int trace_mem__pool__gc__begin(long tid, long pid, char* gc_name, char* pool_name)
{
   tracepoint(jvm, mem__pool__gc__begin, tid, pid, gc_name, pool_name);
   return 0;
}

int trace_mem__pool__gc__end(long tid, long pid, char* gc_name, char* pool_name)
{
   tracepoint(jvm, mem__pool__gc__end, tid, pid, gc_name, pool_name);
   return 0;
}
