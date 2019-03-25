
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
        mem__pool__gc__begin,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, gc_name,
        char*, pool_name

    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(gc_name, gc_name)
        ctf_string(pool_name, pool_name)
    )
)

TRACEPOINT_EVENT(
    jvm,
        mem__pool__gc__end,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, gc_name,
        char*, pool_name

    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(gc_name, gc_name)
        ctf_string(pool_name, pool_name)
    )
)

TRACEPOINT_EVENT(
    jvm,
        method__compile__begin,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, compilerName,
        char*, className,
        char*, methodName,
        char*, signature

    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(compilerName, compilerName)
        ctf_string(className, className)
        ctf_string(methodName, methodName)
        ctf_string(signature, signature)
    )
)

TRACEPOINT_EVENT(
    jvm,
        method__compile__end,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, compilerName,
        char*, className,
        char*, methodName,
        char*, signature

    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(compilerName, compilerName)
        ctf_string(className, className)
        ctf_string(methodName, methodName)
        ctf_string(signature, signature)
    )
)


//monitor events

TRACEPOINT_EVENT(
    jvm,
        monitor__wait,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, monitorName
    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(monitorName, monitorName)
    )
)

TRACEPOINT_EVENT(
    jvm,
        monitor__waited,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, monitorName
    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(monitorName, monitorName)
    )
)

TRACEPOINT_EVENT(
    jvm,
        monitor__contended__enter,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, monitorName
    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(monitorName, monitorName)
    )
)

TRACEPOINT_EVENT(
    jvm,
        monitor__contended__entered,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, monitorName
    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(monitorName, monitorName)
    )
)

TRACEPOINT_EVENT(
    jvm,
        statedump_java_thread,
    TP_ARGS(
        int, tid,
        int, pid,
        char*, threadName
    ),
    TP_FIELDS(
        ctf_integer(int, tid, tid)
        ctf_integer(int, pid, pid)
        ctf_string(threadName, threadName)
    )
)


#endif /* TRACE_DEFINITION_H */

#include <lttng/tracepoint-event.h>
