#!/usr/bin/python

from ctypes import cdll


def tracepoint(tracepoint_name, *trace_arguments):
	lib = cdll.LoadLibrary('./traceLib/libtrace.so')
	if (tracepoint_name == "thread__start"):
		lib.trace_thread__start(*trace_arguments)
	if (tracepoint_name == "thread__stop"):
		lib.trace_thread__stop(*trace_arguments)
	if (tracepoint_name == "mem__pool__gc__begin"):
		lib.trace_mem__pool__gc__begin(*trace_arguments)
	if (tracepoint_name == "mem__pool__gc__end"):
		lib.trace_mem__pool__gc__end(*trace_arguments)
	if (tracepoint_name == "method__compile__begin"):
		lib.trace_method__compile__begin(*trace_arguments)
	if (tracepoint_name == "method__compile__end"):
		lib.trace_method__compile__end(*trace_arguments);
	if (tracepoint_name == "monitor__wait"):
		lib.trace_monitor__wait(*trace_arguments)
	if (tracepoint_name == "monitor__waited"):
		lib.trace_monitor__waited(*trace_arguments)
	if (tracepoint_name == "monitor__contended__enter"):
		lib.trace_monitor__contended__enter(*trace_arguments)
	if (tracepoint_name == "monitor__contended__entered"):
		lib.trace_monitor__contended__entered(*trace_arguments);

	if (tracepoint_name == "statedump_java_thread"):
		lib.trace_statedump_java_thread(*trace_arguments);


#TODO : thread__sleep__begin thread__sleep__end thread__park__begin thread__park__end vmops__begin vmops__end

