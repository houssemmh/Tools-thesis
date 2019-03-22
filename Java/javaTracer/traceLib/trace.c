#include <stdio.h>
#include "trace_definition.h"


int trace_thread__start(char* name, long java_tid, long os_tid, long daemon, long compiler, int tid, int pid)
{
   tracepoint(jvm, thread_start, name, java_tid, os_tid, daemon, compiler, tid, pid);
   return 0;
}

int trace_thread__stop(char* name, long java_tid, long os_tid, long daemon, long compiler, int tid, int pid)
{
   tracepoint(jvm, thread_stop, name, java_tid, os_tid, daemon, compiler, tid, pid);
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
