#include "net.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "platform.h"
#include "util.h"

/* NOTE: if you want to add/delete the entries after net_run(), you need to
 * protect these lists with a mutex. */
static struct net_device* devices;

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

int net_input_handler(uint16_t type, const uint8_t* data, size_t len,
                      struct net_device* dev) {
    // TODO
    debugf("dev=%s, type=0x%04x, len=%zu", dev->name, type, len);
    debugdump(data, len);
    return 0;
}

int net_run(void) {
    struct net_device* dev;

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
    debugf("shutdown complete");
}

int net_init(void) {
    // TODO
    infof("initialized");
    return 0;
}
