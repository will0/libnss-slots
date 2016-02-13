all: libnss_slots.so.2
libnss_slots.so.2: libnss_slots.c
	gcc -fPIC -Wall -shared -o libnss_slots.so.2 -Wl,-soname,libnss_slots.so.2 libnss_slots.c
