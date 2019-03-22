
#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER jvm 

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./trace_definition.h"

#if !defined(TRACE_DEFINITION_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define TRACE_DEFINITION_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    jvm,
        thread_start,
    TP_ARGS(
        char*, name,
        long, java_threadid,
        long, os_threadid,
        long, deamon,
        long, compiler,
        int, tid,
        int, pid
    ),
    TP_FIELDS(
        ctf_string(name, name)
        ctf_integer(long, java_threadid, java_threadid)
        ctf_integer(long, os_threadid, os_threadid)
        ctf_integer(long, deamon, deamon)
        ctf_integer(long, compiler, compiler)
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
    )
)

TRACEPOINT_EVENT(
    jvm,
        thread_stop,
    TP_ARGS(
        char*, name,
        long, java_threadid,
        long, os_threadid,
        long, deamon,
        long, compiler,
        int, tid,
        int, pid
    ),
    TP_FIELDS(
        ctf_string(name, name)
                ctf_integer(long, java_threadid, java_threadid)
                ctf_integer(long, os_threadid, os_threadid)
                ctf_integer(long, deamon, deamon)
                ctf_integer(long, compiler, compiler)
                ctf_integer(int, tid, tid)
                ctf_integer(int, pid, pid)
    )
)

TRACEPOINT_EVENT(
    jvm,
        report_gc_start,
    TP_ARGS(
        long, id,
        long, name,
        long, cause,
        int, tid,
        int, pid
    ),
    TP_FIELDS(
        ctf_integer(long, id, id)
        ctf_integer(long, name, name)
        ctf_integer(long, cause, cause)
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
    )
)


TRACEPOINT_EVENT(
    jvm,
        report_gc_end,
    TP_ARGS(
        long, id,
        long, name,
        long, cause,
        int, tid,
        int, pid
    ),
    TP_FIELDS(
        ctf_integer(long, id, id)
        ctf_integer(long, name, name)
        ctf_integer(long, cause, cause)
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
    )
)



#endif /* TRACE_DEFINITION_H */

#include <lttng/tracepoint-event.h>
