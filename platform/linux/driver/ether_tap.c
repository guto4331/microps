#define _GNU_SOURCE /* for F_SETSIG */
#include "driver/ether_tap.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ether.h"
#include "net.h"
#include "platform.h"
#include "util.h"

#define CLONE_DEVICE "/dev/net/tun"

#define ETHER_TAP_IRQ (INTR_IRQ_BASE + 2)

struct ether_tap {
    char name[IFNAMSIZ];
    int fd;
    unsigned int irq;
};

#define PRIV(x) ((struct ether_tap*)x->priv)

/* ハードウェアアドレスを取得する */
static int ether_tap_addr(struct net_device* dev) {
    int soc;
    struct ifreq ifr = {};

    /*
        通信するわけではないが、SIOCGIFHWADDR要求は空いているsocketに対してのみ有効なので
    */
    soc = socket(AF_INET, SOCK_DGRAM, 0);
    if (soc < 0) {
        errorf("socket() failed: %s\n", strerror(errno));
        return -1;
    }

    strncpy(ifr.ifr_name, PRIV(dev)->name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(soc, SIOCGIFHWADDR, &ifr) < 0) {
        errorf("ioctl(SIOCGIFHWADDR) failed: %s\n", strerror(errno));
        close(soc);
        return -1;
    }
    memcpy(dev->addr, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
    close(soc);
    return 0;
}

static int ether_tap_open(struct net_device* dev) {
    struct ether_tap* tap;
    struct ifreq ifr = {};

    tap = PRIV(dev);
    tap->fd = open(CLONE_DEVICE, O_RDWR);
    if (tap->fd < 0) {
        errorf("failed to open %s: %s\n", dev->name, strerror(errno));
        return -1;
    }
    strncpy(ifr.ifr_name, tap->name, sizeof(ifr.ifr_name) - 1);
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;  // TAPデバイス、パケット情報ヘッダなし
    /* TAPデバイスを登録 */
    if (ioctl(tap->fd, TUNSETIFF, &ifr) < 0) {
        errorf("ioctl(TUNSETIFF) failed: %s\n", strerror(errno));
        close(tap->fd);
        return -1;
    }

    /* シグナル駆動のI/Oを設定 */
    if (fcntl(tap->fd, F_SETOWN, getpid()) < 0) {
        errorf("fcntl(F_SETOWN) failed: %s\n", strerror(errno));
        close(tap->fd);
        return -1;
    }
    if (fcntl(tap->fd, F_SETFL, O_ASYNC) < 0) {
        errorf("fcntl(F_SETFL) failed: %s\n", strerror(errno));
        close(tap->fd);
        return -1;
    }
    if (fcntl(tap->fd, F_SETSIG, tap->irq) < 0) {
        errorf("fcntl(F_SETSIG) failed: %s\n", strerror(errno));
        close(tap->fd);
        return -1;
    }

    if (memcmp(dev->addr, ETHER_ADDR_ANY, ETHER_ADDR_LEN) == 0 &&
        ether_tap_addr(dev) < 0) {
        errorf("ether_tap_addr() failed for %s\n", dev->name);
        close(tap->fd);
        return -1;
    }
    return 0;
}

static int ether_tap_close(struct net_device* dev) {
    close(PRIV(dev)->fd);
    return 0;
}

static ssize_t ether_tap_write(struct net_device* dev, const uint8_t* frame,
                               size_t flen) {
    return write(PRIV(dev)->fd, frame, flen);
}

int ether_tap_transmit(struct net_device* dev, uint16_t type,
                       const uint8_t* buf, size_t len, const void* dst) {
    return ether_transmit_helper(dev, type, buf, len, dst, ether_tap_write);
}

static ssize_t ether_tap_read(struct net_device* dev, uint8_t* buf,
                              size_t size) {
    ssize_t len;

    len = read(PRIV(dev)->fd, buf, size);

    if (len <= 0) {
        if (len == -1 && errno != EINTR) {
            errorf("read() failed: %s\n", strerror(errno));
        }
        return -1;
    }
    return len;
}

static int ether_tap_isr(unsigned int irq, void* id) {
    struct net_device* dev;
    struct pollfd pfd;
    int ret;

    dev = (struct net_device*)id;
    pfd.fd = PRIV(dev)->fd;
    pfd.events = POLLIN;

    while (1) {
        // 読み込み可能なデータがあるか？
        ret = poll(&pfd, 1, 0);
        if (ret < 0) {
            // ただの割り込みなので回復可能
            if (errno == EINTR) {
                continue;
            }
            errorf("poll() failed: %s\n", strerror(errno));
            return -1;
        }
        if (ret == 0) {
            break;
        }
        ether_input_helper(dev, ether_tap_read);
    }
    return 0;
}

static struct net_device_ops ether_tap_ops = {
    .open = ether_tap_open,
    .close = ether_tap_close,
    .transmit = ether_tap_transmit,
};

struct net_device* ether_tap_init(const char* name, const char* addr) {
    struct net_device* dev;
    struct ether_tap* tap;

    dev = net_device_alloc();
    if (!dev) {
        errorf("net_device_alloc() failed\n");
        return NULL;
    }

    ether_setup_helper(dev);
    if (addr && ether_addr_pton(addr, dev->addr) < 0) {
        errorf("invalid address: %s\n", addr);
        return NULL;
    }

    /* ドライバの関数群 */
    dev->ops = &ether_tap_ops;
    tap = memory_alloc(sizeof(*tap));
    if (!tap) {
        errorf("memory_alloc() failed\n");
        return NULL;
    }
    strncpy(tap->name, name, sizeof(tap->name) - 1);
    tap->fd = -1;
    tap->irq = ETHER_TAP_IRQ;
    dev->priv = tap;

    if (net_device_register(dev) < 0) {
        errorf("net_device_register() failed for %s\n", name);
        return NULL;
    }
    intr_request_irq(tap->irq, ether_tap_isr, INTR_IRQ_SHARED, dev->name, dev);
    infof("Ethernet TAP device initialized: %s\n", name);
    return dev;
}
