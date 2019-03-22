#!/usr/bin/python

from ctypes import cdll


def tracepoint(tracepoint_name, *trace_arguments):
	lib = cdll.LoadLibrary('./traceLib/libtrace.so')
	if (tracepoint_name == "thread__start"):
		lib.trace_thread__start(*trace_arguments);
	if (tracepoint_name == "thread__stop"):
		lib.trace_thread__stop(*trace_arguments);
	if (tracepoint_name == "gc__begin"):
		lib.trace_report_gc_start(*trace_arguments);
	if (tracepoint_name == "gc__end"):
		lib.trace_report_gc_end(*trace_arguments);
