#!/bin/bash

lttng create
lttng enable-channel -u --subbuf-size 16384 --num-subbuf 128 ustchannel
lttng enable-event -u lttng_ust_lib:unload,lttng_ust_lib:debug_link,lttng_ust_lib:build_id,lttng_ust_lib:load,lttng_ust_statedump:end,lttng_ust_statedump:debug_link,lttng_ust_statedump:build_id,lttng_ust_statedump:bin_info,lttng_ust_statedump:start -c ustchannel
lttng enable-event -u jvm:* -c ustchannel
lttng add-context -u -t vpid -t vtid -c ustchannel
lttng enable-channel -k --subbuf-size 32768 --num-subbuf 8192 mykernelchannel
lttng enable-event -k block_rq_insert,lttng_statedump_end,lttng_statedump_file_descriptor,lttng_statedump_process_state,lttng_statedump_start,sched_migrate_task,sched_process_exec,sched_process_exit,sched_process_fork,sched_switch,sched_wakeup,sched_wakeup_new -c mykernelchannel
lttng enable-event -k sched_stat_wait,sched_stat_sleep,sched_stat_iowait,sched_stat_blocked,sched_stat_runtime -c mykernelchannel
lttng add-context -k -t tid -t pid -c mykernelchannel
lttng start
sudo ./javaTracer.py $1
