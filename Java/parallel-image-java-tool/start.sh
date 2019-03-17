export JAVA_HOME=/home/houssemmh/work/jdk8u-new/build/linux-x86_64-normal-server-fastdebug/jdk
export PATH=$JAVA_HOME/bin:$PATH

LD_PRELOAD="/home/houssemmh/work/jdk8u-new/hotspot/src/share/vm/lttng/libtpp.so /usr/local/lib/liblttng-ust-dl.so" java -Xms1024m -XX:SuppressErrorAt=/resourceArea.hpp:63 -XX:+PreserveFramePointer  ConcurrentOil Selection_038.jpg 4 4 
