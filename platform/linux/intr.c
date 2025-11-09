#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "platform.h"
#include "util.h"

/* IRQ: 割り込み要求 */
struct irq_entry {
    struct irq_entry* next;
    unsigned int irq;  // IRQ番号
    int (*handler)(unsigned int irq, void* dev);
    int flags;
    char name[16];
    void* dev;  // 発生元のデバイス
};

/* NOTE: if you want to add/delete the entries after intr_run(), you need to
 * protect these lists with a mutex. */
static struct irq_entry* irqs;

static sigset_t sigmask;

static pthread_t tid;
static pthread_barrier_t barrier;

int intr_request_irq(unsigned int irq,
                     int (*handler)(unsigned int irq, void* dev), int flags,
                     const char* name, void* dev) {
    struct irq_entry* entry;

    debugf("irq=%u, flags=%d, name=%s", irq, flags, name);
    for (entry = irqs; entry; entry = entry->next) {
        if (entry->irq == irq) {
            if (entry->flags ^ INTR_IRQ_SHARED || flags ^ INTR_IRQ_SHARED) {
                errorf(
                    "IRQ already registered and not allowed to be shared: "
                    "irq=%u, name=%s",
                    irq, name);
                return -1;
            }
        }
    }

    entry = memory_alloc(sizeof(*entry));
    if (!entry) {
        errorf("failed to allocate memory");
        return -1;
    }
    entry->irq = irq;
    entry->handler = handler;
    entry->flags = flags;
    strncpy(entry->name, name, sizeof(entry->name) - 1);

    /* 先頭に追加 */
    entry->dev = dev;
    entry->next = irqs;
    irqs = entry;

    sigaddset(&sigmask, irq);
    debugf("registerd IRQ: irq=%u, name=%s", irq, name);
    return 0;
}

int intr_raise_irq(unsigned int irq) { return pthread_kill(tid, (int)irq); }

static void* intr_thread(void* arg) {
    int terminate = 0, sig, err;
    struct irq_entry* entry;

    debugf("start...");
    pthread_barrier_wait(&barrier);

    while (!terminate) {
        err = sigwait(&sigmask, &sig);
        if (err) {
            errorf("sigwait(): %s", strerror(err));
            continue;
        }

        switch (sig) {
            case SIGHUP:  // 割り込みスレッドを終了させる
                terminate = 1;
                break;
            default:
                for (entry = irqs; entry; entry = entry->next) {
                    if (entry->irq == (unsigned int)sig) {
                        debugf("handling IRQ: irq=%u, name=%s", entry->irq,
                               entry->name);
                        entry->handler(entry->irq, entry->dev);
                    }
                }
                break;
        }
    }
    debugf("terminated");
    return NULL;
}

int intr_run(void) {
    int err;
    err = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
    if (err) {
        errorf("pthread_sigmask failed: %d", err);
        return -1;
    }
    err = pthread_create(&tid, NULL, intr_thread, NULL);
    if (err) {
        errorf("pthread_create failed: %d", err);
        return -1;
    }
    pthread_barrier_wait(&barrier);
    return 0;
}

void intr_shutdown(void) {
    if (pthread_equal(tid, pthread_self()) != 0) {
        return;
    }
    pthread_kill(tid, SIGHUP);
    pthread_join(tid, NULL);
}

int intr_init(void) {
    tid = pthread_self();
    pthread_barrier_init(&barrier, NULL, 2);
    sigemptyset(&sigmask);
    sigaddset(&sigmask, SIGHUP);
    return 0;
}
