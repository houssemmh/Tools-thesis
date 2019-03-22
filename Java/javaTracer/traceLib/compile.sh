gcc -I. -fpic -c trace_definition.c 
gcc -I. -fpic -c trace.c 
gcc -shared -o libtrace.so trace.o trace_definition.o -llttng-ust -ldl
