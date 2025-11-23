#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "driver/ether_tap.h"
#include "driver/loopback.h"
#include "icmp.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "udp.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
    close(0);  // close stdin
}

static int setup(void) {
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
    dev = ether_tap_init(ETHER_TAP_NAME, ETHER_TAP_HW_ADDR);
    if (!dev) {
        errorf("ether_tap_init() failed");
        return -1;
    }
    iface = ip_iface_alloc(ETHER_TAP_IP_ADDR, ETHER_TAP_NETMASK);
    if (!iface) {
        errorf("ip_iface_alloc() failed");
        return -1;
    }
    if (ip_iface_register(dev, iface) < 0) {
        errorf("ip_iface_register() failed");
        return -1;
    }
    if (ip_route_set_default_gateway(iface, DEFAULT_GATEWAY) < 0) {
        errorf("ip_route_set_default_gateway() failed");
        return -1;
    }
    if (net_run() < 0) {
        errorf("net_run() failed");
        return -1;
    }
    return 0;
}

static void cleanup(void) { net_shutdown(); }

int main(int argc, char* argv[]) {
    int soc;
    struct ip_endpoint foreign;
    uint8_t buf[1024];

    if (setup() == -1) {
        errorf("setup() failed");
        return -1;
    }
    soc = udp_open();
    if (soc < 0) {
        errorf("udp_open() failed");
        return -1;
    }
    ip_endpoint_pton("192.0.2.1:10007", &foreign);
    while (!terminate) {
        /* stdinから一行読む */
        if (!fgets((char*)buf, sizeof(buf), stdin)) {
            break;
        }
        if (udp_sendto(soc, buf, strlen((char*)buf), &foreign) < 0) {
            errorf("udp_sendto() failed");
            break;
        }
    }
    udp_close(soc);
    cleanup();
    return 0;
}
