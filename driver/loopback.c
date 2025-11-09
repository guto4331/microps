#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "net.h"
#include "platform.h"
#include "util.h"

#define LOOPBACK_MTU UINT16_MAX /* maximum size of IP datagram */
#define LOOPBACK_QUEUE_LIMIT 16
#define LOOPBACK_IRQ (INTR_IRQ_BASE + 1)

#define PRIV(x) ((struct loopback*)x->priv)

/* プライベートなデータ */
struct loopback {
    int irq;
    mutex_t mutex;
    struct queue_head queue;
};

/* データはキューに入れて送受信する */
struct loopback_queue_entry {
    uint16_t type;
    size_t len;
    uint8_t data[]; /* flexible array member:
                       サイズ不明の配列。メモリ確保の際に大きさを考慮する */
};

static int loopback_transmit(struct net_device* dev, uint16_t type,
                             const uint8_t* data, size_t len, const void* dst) {
    struct loopback_queue_entry* entry;
    unsigned int num;

    mutex_lock(&PRIV(dev)->mutex);
    if (PRIV(dev)->queue.num >= LOOPBACK_QUEUE_LIMIT) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("loopback queue full: dev=%s", dev->name);
        return -1;
    }

    entry = memory_alloc(sizeof(*entry) + len);  // データ長lenもあわせて確保
    if (!entry) {
        mutex_unlock(&PRIV(dev)->mutex);
        errorf("failed to allocate memory");
        return -1;
    }
    entry->type = type;
    entry->len = len;
    memcpy(entry->data, data, len);  // dataは連続領域に確保されている
    queue_push(&PRIV(dev)->queue, entry);
    num = PRIV(dev)->queue.num;
    mutex_unlock(&PRIV(dev)->mutex);

    debugf("pushed to queue (num: %u): dev=%s, type=0x%04x, len=%zu", num,
           dev->name, type, len);
    debugdump(data, len);
    intr_raise_irq(PRIV(dev)->irq);
    return 0;
}

static int loopback_isr(unsigned int irq, void* id) {
    struct net_device* dev;
    struct loopback_queue_entry* entry;

    dev = (struct net_device*)id;
    mutex_lock(&PRIV(dev)->mutex);
    while (1) {
        entry = queue_pop(&PRIV(dev)->queue);
        if (!entry) {
            break;
        }
        debugf("popped from queue (num: %u): dev=%s, type=0x%04x, len=%zu",
               PRIV(dev)->queue.num, dev->name, entry->type, entry->len);
        debugdump(entry->data, entry->len);

        net_input_handler(entry->type, entry->data, entry->len, dev);
        memory_free(entry);
    }
    mutex_unlock(&PRIV(dev)->mutex);
    return 0;
}

static struct net_device_ops loopback_ops = {
    .transmit = loopback_transmit,
};

struct net_device* loopback_init(void) {
    struct net_device* dev;
    struct loopback* lo;

    dev = net_device_alloc();
    if (!dev) {
        errorf("failed to allocate device");
        return NULL;
    }
    dev->type = NET_DEVICE_TYPE_LOOPBACK;
    dev->mtu = LOOPBACK_MTU;
    dev->hlen = 0;
    dev->alen = 0;
    dev->ops = &loopback_ops;
    dev->flags = NET_DEVICE_FLAG_LOOPBACK;

    /* プライベートデータの準備 */
    lo = memory_alloc(sizeof(*lo));
    if (!lo) {
        errorf("failed to allocate memory");
        return NULL;
    }
    lo->irq = LOOPBACK_IRQ;
    mutex_init(&lo->mutex);
    queue_init(&lo->queue);
    dev->priv = lo;

    if (net_device_register(dev) < 0) {
        errorf("failed to register device");
        return NULL;
    }
    intr_request_irq(LOOPBACK_IRQ, loopback_isr, INTR_IRQ_SHARED, dev->name,
                     dev);
    debugf("device initialized: dev=%s", dev->name);
    return dev;
}
