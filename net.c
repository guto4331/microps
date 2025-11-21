#include "net.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "arp.h"
#include "icmp.h"
#include "ip.h"
#include "platform.h"
#include "util.h"

struct net_protocol {
    struct net_protocol* next;
    uint16_t type;           // NET_PROTOCOL_TYPE_XXX
    struct queue_head queue; /* input queue */
    void (*handler)(
        const uint8_t* data, size_t len,
        struct net_device* dev);  // プロトコル毎の入力関数へのポインタ
};

/* プロトコル毎の受信キューのエントリ */
struct net_protocol_queue_entry {
    struct net_device* dev;
    size_t len;
    uint8_t data[];
};

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
static struct net_device* devices;
static struct net_protocol* protocols;  // 対応するプロトコルをリストでもつ

struct net_device* net_device_alloc(void) {
    struct net_device* dev = memory_alloc(sizeof(*dev));
    if (!dev) {
        errorf("memory_alloc() failed");
        return NULL;
    }
    return dev;
}

/* NOTE: must not be call after net_run() */
int net_device_register(struct net_device* dev) {
    /* デバイス名を生成 */
    static unsigned int index = 0;
    dev->index = index++;
    snprintf(dev->name, sizeof(dev->name), "net%d", dev->index);

    /* 先頭に追加 */
    dev->next = devices;
    devices = dev;

    infof("registered: dev=%s, type=0x%04x", dev->name, dev->type);
    return 0;
}

static int net_device_open(struct net_device* dev) {
    if (NET_DEVICE_IS_UP(dev)) {
        errorf("already open: dev=%s", dev->name);
        return -1;
    }
    /* ドライバのopenを呼び出す（あれば） */
    if (dev->ops->open) {
        if (dev->ops->open(dev) < 0) {
            errorf("failed to open: dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags |= NET_DEVICE_FLAG_UP;
    infof("opened: dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

static int net_device_close(struct net_device* dev) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not open: dev=%s", dev->name);
        return -1;
    }
    /* ドライバのcloseを呼び出す（あれば） */
    if (dev->ops->close) {
        if (dev->ops->close(dev) < 0) {
            errorf("failed to close: dev=%s", dev->name);
            return -1;
        }
    }
    dev->flags &= ~NET_DEVICE_FLAG_UP;
    infof("closed: dev=%s, state=%s", dev->name, NET_DEVICE_STATE(dev));
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_device_add_iface(struct net_device* dev, struct net_iface* iface) {
    struct net_iface* entry;

    for (entry = dev->ifaces; entry != NULL; entry = entry->next) {
        if (entry->family == iface->family) {
            errorf(
                "only one interface per family is supported: dev=%s, family=%d",
                dev->name, iface->family);
            return -1;
        }
    }

    iface->dev = dev;
    /* devのifaceリストの先頭に追加 */
    iface->next = dev->ifaces;
    dev->ifaces = iface;
    return 0;
}

struct net_iface* net_device_get_iface(struct net_device* dev, int family) {
    struct net_iface* entry;

    for (entry = dev->ifaces; entry != NULL; entry = entry->next) {
        if (entry->family == family) {
            return entry;
        }
    }
    return NULL;
}

int net_device_output(struct net_device* dev, uint16_t type,
                      const uint8_t* data, size_t len, const void* dst) {
    if (!NET_DEVICE_IS_UP(dev)) {
        errorf("not open: dev=%s", dev->name);
        return -1;
    }
    if (len > dev->mtu) {
        errorf("data too long: dev=%s, len=%zu, mtu=%u", dev->name, len,
               dev->mtu);
        return -1;
    }
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    if (dev->ops->transmit(dev, type, data, len, dst) < 0) {
        errorf("device transmit failed: dev=%s, len=%zu", dev->name, len);
        return -1;
    }
    return 0;
}

/* NOTE: must not be call after net_run() */
int net_protocol_register(uint16_t type,
                          void (*handler)(const uint8_t* data, size_t len,
                                          struct net_device* dev)) {
    struct net_protocol* proto;

    for (proto = protocols; proto != NULL; proto = proto->next) {
        if (type == proto->type) {
            errorf("protocol already registered: type=0x%04x", type);
            return -1;
        }
    }
    proto = memory_alloc(sizeof(*proto));
    if (!proto) {
        errorf("memory_alloc() failed");
        return -1;
    }
    proto->type = type;
    proto->handler = handler;

    proto->next = protocols;
    protocols = proto;
    infof("protocol registered: type=0x%04x", type);
    return 0;
}

int net_input_handler(uint16_t type, const uint8_t* data, size_t len,
                      struct net_device* dev) {
    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;

    for (proto = protocols; proto != NULL; proto = proto->next) {
        if (proto->type == type) {
            entry = memory_alloc(sizeof(*entry) + len);
            if (!entry) {
                errorf("memory_alloc() failed");
                return -1;
            }
            entry->dev = dev;
            entry->len = len;
            memcpy(entry->data, data, len);

            if (!queue_push(&proto->queue, entry)) {
                errorf("queue_push() failed");
                return -1;
            }

            debugf(
                "pushed to protocol queue (num=%u): dev=%s, type=0x%04x, "
                "len=%zu",
                proto->queue.num, dev->name, type, len);
            debugdump(data, len);
            intr_raise_irq(
                INTR_IRQ_SOFTIRQ);  // ソフトウェア割り込みからハンドラを呼び出す
            return 0;
        }
    }
    /* 対応していないプロトコルを受信 */
    return 0;
}

int net_softirq_handler(void) {
    struct net_protocol* proto;
    struct net_protocol_queue_entry* entry;

    for (proto = protocols; proto != NULL; proto = proto->next) {
        while (1) {
            entry = queue_pop(&proto->queue);
            if (!entry) {
                break;
            }

            debugf(
                "popped from protocol queue (num=%u): dev=%s, type=0x%04x, "
                "len=%zu",
                proto->queue.num, entry->dev->name, proto->type, entry->len);
            debugdump(entry->data, entry->len);

            proto->handler(entry->data, entry->len, entry->dev);

            memory_free(entry);
        }
    }
    return 0;
}

int net_run(void) {
    struct net_device* dev;

    if (intr_run() < 0) {
        errorf("intr_run() failed");
        return -1;
    }

    debugf("opening all devices...");
    for (dev = devices; dev != NULL; dev = dev->next) {
        net_device_open(dev);
    }
    debugf("all devices opened");
    return 0;
}

void net_shutdown(void) {
    struct net_device* dev;

    debugf("closing all devices...");
    for (dev = devices; dev != NULL; dev = dev->next) {
        net_device_close(dev);
    }
    intr_shutdown();
    debugf("shutdown complete");
}

int net_init(void) {
    if (intr_init() < 0) {
        errorf("intr_init() failed");
        return -1;
    }
    if (arp_init() < 0) {
        errorf("arp_init() failed");
        return -1;
    }
    if (ip_init() < 0) {
        errorf("ip_init() failed");
        return -1;
    }
    if (icmp_init() < 0) {
        errorf("icmp_init() failed");
        return -1;
    }
    infof("initialized");
    return 0;
}
