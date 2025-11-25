APPS =

DRIVERS = driver/dummy.o \
		  driver/loopback.o \

OBJS = util.o \
	   net.o \
	   ip.o \
	   icmp.o \
	   ether.o \
	   arp.o \
	   udp.o \
	   tcp.o

TESTS = test/step0.exe \
		test/device_management.exe \
		test/loopback.exe \
		test/protocol_management.exe \
		test/logical_interface.exe \
		test/ip_output.exe \
		test/ip_upper_protocol.exe \
		test/icmp_output.exe \
		test/tap.exe \
		test/arp.exe \
		test/ip_routing.exe \
		test/udp_inout.exe \
		test/udp_pcb.exe \
		test/udp_api_echoback.exe \
		test/udp_api_bind_auto.exe \
		test/udp_intr.exe \
		test/tcp_input.exe \
		test/tcp_passive_open.exe \
		test/tcp_data_trans.exe \
		test/tcp_active_open.exe

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -iquote .

ifeq ($(shell uname),Linux)
  # Linux specific settings
  BASE = platform/linux
  CFLAGS := $(CFLAGS) -pthread -iquote $(BASE)
  DRIVERS := $(DRIVERS) $(BASE)/driver/ether_tap.o
  OBJS := $(OBJS) $(BASE)/intr.o $(BASE)/sched.o
endif

ifeq ($(shell uname),Darwin)
  # macOS specific settings
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TESTS)

$(APPS): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TESTS): %.exe : %.o $(OBJS) $(DRIVERS) test/test.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:.exe=.o) $(OBJS) $(DRIVERS) $(TESTS) $(TESTS:.exe=.o)
