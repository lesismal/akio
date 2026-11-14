/*
 * only-dpdk C shim: a narrow, plain-C ABI over the parts of DPDK only needs.
 *
 * Most of DPDK's fast path (rte_eth_rx_burst, rte_pktmbuf_alloc, ...) is `static inline` in the
 * headers, so it cannot be bound from Rust directly; this file wraps it. Every function takes
 * and returns only integers and opaque pointers, so the Rust side (src/pmd/ffi.rs) needs no
 * generated bindings and is independent of DPDK's struct layouts.
 *
 * Built by build.rs with the flags `pkg-config --cflags libdpdk` reports.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

/* One mbuf pool per port (allocated by only_dpdk_port_start). */
static struct rte_mempool *pools[RTE_MAX_ETHPORTS];

int only_dpdk_eal_init(int argc, char **argv) {
    return rte_eal_init(argc, argv);
}

int only_dpdk_eal_cleanup(void) {
    return rte_eal_cleanup();
}

/* Registers the calling (non-EAL) thread with the EAL so it gets an lcore id and mempool caches.
 * Returns 0 or -1 (no free lcore id; the thread still works, without caches). */
int only_dpdk_thread_register(void) {
    return rte_thread_register();
}

int only_dpdk_errno(void) {
    return rte_errno;
}

uint16_t only_dpdk_port_count(void) {
    return rte_eth_dev_count_avail();
}

int only_dpdk_port_by_name(const char *name, uint16_t *port) {
    return rte_eth_dev_get_port_by_name(name, port);
}

/*
 * Configures `port` with `queues` rx and tx queues of `desc` descriptors each, an mbuf pool of
 * `mbufs` buffers, then starts it in promiscuous mode. Writes the port's MAC address to `mac`.
 * Returns 0 or a negative errno.
 */
int only_dpdk_port_start(uint16_t port, uint16_t queues, uint16_t desc, uint32_t mbufs,
                          uint16_t mtu, uint8_t mac[6]) {
    if (port >= RTE_MAX_ETHPORTS || !rte_eth_dev_is_valid_port(port)) {
        return -ENODEV;
    }
    struct rte_eth_dev_info info;
    int rc = rte_eth_dev_info_get(port, &info);
    if (rc != 0) {
        return rc;
    }
    if (queues > info.max_rx_queues || queues > info.max_tx_queues) {
        return -EINVAL;
    }
    int socket = rte_eth_dev_socket_id(port);
    if (socket < 0) {
        socket = (int)rte_socket_id();
    }
    if (pools[port] == NULL) {
        char name[RTE_MEMPOOL_NAMESIZE];
        snprintf(name, sizeof name, "only_mbuf_%u", port);
        pools[port] = rte_pktmbuf_pool_create(name, mbufs, 256, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                              socket);
        if (pools[port] == NULL) {
            return -rte_errno;
        }
    }
    struct rte_eth_conf conf;
    memset(&conf, 0, sizeof conf);
    if (queues > 1) {
        /* Spread flows over the queues by their IP/UDP/TCP 4-tuple. */
        conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
        conf.rx_adv_conf.rss_conf.rss_hf =
            (RTE_ETH_RSS_IP | RTE_ETH_RSS_UDP | RTE_ETH_RSS_TCP) & info.flow_type_rss_offloads;
    }
    rc = rte_eth_dev_configure(port, queues, queues, &conf);
    if (rc != 0) {
        return rc;
    }
    if (mtu != 0) {
        /* Not every PMD supports changing the MTU (net_ring does not); ignore that. */
        (void)rte_eth_dev_set_mtu(port, mtu);
    }
    uint16_t nb_rx = desc, nb_tx = desc;
    rc = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rx, &nb_tx);
    if (rc != 0) {
        return rc;
    }
    for (uint16_t q = 0; q < queues; q++) {
        rc = rte_eth_rx_queue_setup(port, q, nb_rx, (unsigned)socket, NULL, pools[port]);
        if (rc != 0) {
            return rc;
        }
        rc = rte_eth_tx_queue_setup(port, q, nb_tx, (unsigned)socket, NULL);
        if (rc != 0) {
            return rc;
        }
    }
    rc = rte_eth_dev_start(port);
    if (rc != 0) {
        return rc;
    }
    (void)rte_eth_promiscuous_enable(port);
    struct rte_ether_addr addr;
    rc = rte_eth_macaddr_get(port, &addr);
    if (rc != 0) {
        return rc;
    }
    memcpy(mac, addr.addr_bytes, 6);
    return 0;
}

int only_dpdk_port_stop(uint16_t port) {
    int rc = rte_eth_dev_stop(port);
    if (rc != 0) {
        return rc;
    }
    return rte_eth_dev_close(port);
}

uint16_t only_dpdk_rx_burst(uint16_t port, uint16_t queue, struct rte_mbuf **pkts, uint16_t n) {
    return rte_eth_rx_burst(port, queue, pkts, n);
}

uint16_t only_dpdk_tx_burst(uint16_t port, uint16_t queue, struct rte_mbuf **pkts, uint16_t n) {
    return rte_eth_tx_burst(port, queue, pkts, n);
}

/* The frame in `m` if it is a single segment (NULL otherwise); its length goes to `len`. */
uint8_t *only_dpdk_mbuf_data(struct rte_mbuf *m, uint32_t *len) {
    if (m->nb_segs != 1) {
        return NULL;
    }
    *len = m->data_len;
    return rte_pktmbuf_mtod(m, uint8_t *);
}

void only_dpdk_mbuf_free(struct rte_mbuf *m) {
    rte_pktmbuf_free(m);
}

/* A new mbuf from `port`'s pool holding `len` writable bytes at `*data`, or NULL. */
struct rte_mbuf *only_dpdk_tx_alloc(uint16_t port, uint16_t len, uint8_t **data) {
    if (port >= RTE_MAX_ETHPORTS || pools[port] == NULL) {
        return NULL;
    }
    struct rte_mbuf *m = rte_pktmbuf_alloc(pools[port]);
    if (m == NULL) {
        return NULL;
    }
    char *p = rte_pktmbuf_append(m, len);
    if (p == NULL) {
        rte_pktmbuf_free(m);
        return NULL;
    }
    *data = (uint8_t *)p;
    return m;
}
