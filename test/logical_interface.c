#include <signal.h>
#include <stdio.h>
#include <unistd.h>

#include "driver/loopback.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
}

int main(int argc, char* argv[]) {
    struct net_device* dev;
    struct ip_iface* iface;
    signal(SIGINT, on_signal);
    if (net_init() < 0) {
        errorf("net_init() failed");
        return -1;
    }
    dev = loopback_init();
    if (!dev) {
        errorf("loopback_init() failed");
        return -1;
    }
    iface = ip_iface_alloc(LOOPBACK_IP_ADDR, LOOPBACK_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failed");
        return -1;
    }
    if (ip_iface_register(dev, iface) < 0) {
        errorf("ip_iface_register() failed");
        return -1;
    }
    if (net_run() < 0) {
        errorf("net_run() failed");
        return -1;
    }
    while (!terminate) {
        /* 1秒ごとにパケットを書き込む */
        if (net_device_output(dev, NET_PROTOCOL_TYPE_IP, test_data,
                              sizeof(test_data), NULL) < 0) {
            errorf("net_device_output() failed");
            return -1;
        }
        sleep(1);
    }
    net_shutdown();
    return 0;
}
