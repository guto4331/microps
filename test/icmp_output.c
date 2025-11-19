#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

#include "driver/loopback.h"
#include "icmp.h"
#include "ip.h"
#include "net.h"
#include "test.h"
#include "util.h"

static volatile sig_atomic_t terminate;

static void on_signal(int s) {
    (void)s;
    terminate = 1;
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
    if (net_run() < 0) {
        errorf("net_run() failed");
        return -1;
    }
    return 0;
}

static void cleanup(void) { net_shutdown(); }

int main(int argc, char* argv[]) {
    ip_addr_t src, dst;
    uint16_t id, seq = 0;
    size_t offset = IP_HDR_SIZE_MIN + ICMP_HDR_SIZE;  // ヘッダ分

    if (setup() == -1) {
        errorf("setup() failed");
        return -1;
    }
    ip_addr_pton(LOOPBACK_IP_ADDR, &src);
    dst = src;
    id = getpid() % UINT16_MAX;
    while (!terminate) {
        /* 1秒ごとにパケットを書き込む */
        if (icmp_output(ICMP_TYPE_ECHO, 0,
                        hton32(id << 16 | ++seq), /* value: 16'id + 16'seq */
                        test_data + offset, sizeof(test_data), src, dst) < 0) {
            errorf("icmp_output() failed");
            return -1;
        }
        sleep(1);
    }
    cleanup();
    return 0;
}
