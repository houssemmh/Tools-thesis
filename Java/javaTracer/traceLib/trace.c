#include <stdio.h>
#include <string.h>
#include "trace_definition.h"



char* correctstring(char* str){

	char       *target;
	target = malloc(1 + strlen(str)); /* allocate space for the copy of the string */
    strcpy(target, str);
    return target;
}

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

int trace_method__compile__begin(long tid, long pid, char* compilerName, char* className, char* methodName, char* signature)
{
   tracepoint(jvm, method__compile__begin, tid, pid, compilerName, className, methodName, signature);
   return 0;
}

int trace_method__compile__end(long tid, long pid, char* compilerName, char* className, char* methodName, char* signature)
{
   tracepoint(jvm, method__compile__end, tid, pid, compilerName, className, methodName, signature);
   return 0;
}

int trace_monitor__wait(long tid, long pid, char* monitorName)
{
   tracepoint(jvm, monitor__wait, tid, pid, monitorName);
   return 0;
}

int trace_monitor__waited(long tid, long pid, char* monitorName)
{
   tracepoint(jvm, monitor__waited, tid, pid, monitorName);
   return 0;
}

int trace_monitor__contended__enter(long tid, long pid, char* monitorName)
{
   tracepoint(jvm, monitor__contended__enter, tid, pid, monitorName);
   return 0;
}

int trace_monitor__contended__entered(long tid, long pid, char* monitorName)
{
   tracepoint(jvm, monitor__contended__entered, tid, pid, monitorName);
   return 0;
}

int trace_statedump_java_thread(long tid, long pid,char* threadName)
{
   tracepoint(jvm, statedump_java_thread, tid, pid, threadName);
   return 0;
}