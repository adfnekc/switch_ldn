#include "radio.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <linux/wireless.h>
#include <unistd.h>

#include "common.h"

typedef struct Radio {
    RadioConfig cfg;

    int ap_fd;   /* AF_PACKET, ethertype capture on the AP interface */
    int mon_fd;  /* AF_PACKET, injected frames on the monitor interface */

    /* Socket backend: one bound AF_UNIX datagram socket standing in for both
     * interfaces above. The peer is whoever sent the first datagram, and it
     * stays the console until the bridge is closed. */
    bool socket_backend;
    bool have_peer;
    bool peer_warned;
    struct sockaddr_un peer;
    socklen_t peer_len;

    radio_rx_cb rx_cb;
    void *user;

    uint64_t last_adv_ms;
    uint64_t adv_interval_ms;
} Radio;

/* ------------------------------------------------------------------ */
/* Interface helpers                                                  */
/* ------------------------------------------------------------------ */

static int socket_ifindex(const char *iface);

int radio_selfcheck(const char *iface);

const RadioConfig *radio_config(const Radio *radio)
{
    return &radio->cfg;
}

int radio_get_hwaddr(const char *iface, uint8_t mac[6])
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int iface_index(const char *iface)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    int idx = -1;
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
        idx = ifr.ifr_ifindex;
    }
    close(fd);
    return idx;
}

/* Look up the kernel ifindex without leaking an fd. */
static int socket_ifindex(const char *ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int idx = -1;
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == 0) {
        idx = ifr.ifr_ifindex;
    }
    close(fd);
    return idx;
}

__attribute__((unused)) static int iface_up(const char *iface, bool up)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        close(fd);
        return -1;
    }
    ifr.ifr_flags = up ? (ifr.ifr_flags | IFF_UP) : (ifr.ifr_flags & ~IFF_UP);
    int rc = ioctl(fd, SIOCSIFFLAGS, &ifr);
    close(fd);
    return rc == 0 ? 0 : -1;
}

/*
 * Read the interface type so we can tell whether the driver actually gave us
 * monitor mode (the RTL8812AU stack is notoriously imprecise here).
 */
int radio_selfcheck(const char *iface)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
    struct iwreq *iwr = (struct iwreq *)&ifr;

    int mode = -1;
    if (ioctl(fd, SIOCGIWMODE, iwr) == 0) {
        mode = iwr->u.mode;
    }
    close(fd);

    const char *name = "unknown";
    switch (mode) {
    case 1: name = "adhoc"; break;
    case 2: name = "managed/station"; break;
    case 3: name = "master/AP"; break;
    case 4: name = "repeater"; break;
    case 5: name = "secondary"; break;
    case 6: name = "monitor"; break;
    default: break;
    }

    LOG_I("selfcheck %-16s mode=%s (%d)", iface, name, mode);

    /* Channel */
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
        iwr = (struct iwreq *)&ifr;
        if (ioctl(fd, SIOCGIWFREQ, iwr) == 0) {
            double freq = iwr->u.freq.m / 100000.0;
            if (iwr->u.freq.e == 6) {
                freq = iwr->u.freq.m / 10000.0 / 1000000.0;
            }
            LOG_I("selfcheck %-16s freq=%.3f GHz", iface, freq);
        }
        close(fd);
    }

    /*
     * VIF support is what decides the whole architecture, and an interface that
     * does not exist is a hard failure: reporting "mode=unknown" and exiting 0
     * let setup-ap.sh carry on as though the probe had passed, which is exactly
     * the kind of silent success this project keeps removing.
     */
    int idx = iface_index(iface);
    LOG_I("selfcheck %-16s ifindex=%d", iface, idx);
    if (idx < 0) {
        LOG_E("selfcheck %s: no such interface", iface);
        return -1;
    }
    if (mode < 0) {
        LOG_E("selfcheck %s: the kernel has no wireless extensions for it; "
              "if this is a USB adapter, is its driver bound?",
              iface);
        return -1;
    }
    return mode;
}

/* ------------------------------------------------------------------ */
/* Sockets                                                            */
/* ------------------------------------------------------------------ */

static int packet_open(const char *iface, int protocol, int *out_idx)
{
    int fd = socket(AF_PACKET, SOCK_RAW, htons(protocol));
    if (fd < 0) {
        LOG_E("socket(AF_PACKET, %s): %s", iface, strerror(errno));
        return -1;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(protocol);
    sll.sll_ifindex = socket_ifindex(iface);
    if (sll.sll_ifindex < 0) {
        LOG_E("cannot find ifindex for %s", iface);
        close(fd);
        return -1;
    }
    *out_idx = sll.sll_ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        LOG_E("bind(%s): %s", iface, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Bind the socket radio backend. A stale path from a previous run would make
 * bind() fail with EADDRINUSE, so it is removed first; ENOENT (the normal
 * case) is not an error.
 */
static int radio_socket_open(const char *path)
{
    if (unlink(path) < 0 && errno != ENOENT) {
        LOG_W("cannot unlink stale %s: %s", path, strerror(errno));
    }

    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0) {
        LOG_E("socket(AF_UNIX, SOCK_DGRAM, %s): %s", path, strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t plen = strlen(path);
    if (plen >= sizeof(addr.sun_path)) {
        plen = sizeof(addr.sun_path) - 1;
    }
    memcpy(addr.sun_path, path, plen); /* addr is already zero-filled */
    socklen_t alen = (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                 strnlen(addr.sun_path,
                                         sizeof(addr.sun_path)) + 1);

    if (bind(fd, (struct sockaddr *)&addr, alen) < 0) {
        LOG_E("bind(%s): %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    /* Local-only debug channel: no other user should be able to listen in. */
    if (chmod(path, 0600) < 0) {
        LOG_W("chmod(%s, 0600): %s", path, strerror(errno));
    }
    return fd;
}

/* Nothing has arrived from a console yet, so there is nobody to send to. */
static void radio_warn_no_peer(Radio *radio)
{
    if (radio->peer_warned) {
        return;
    }
    radio->peer_warned = true;
    LOG_W("no console attached to the radio socket (%s)",
          radio->cfg.radio_socket);
}

/* ------------------------------------------------------------------ */
/* Frame classification                                               */
/* ------------------------------------------------------------------ */

static uint16_t get_fc(const uint8_t *p, size_t len)
{
    if (len < 2) {
        return 0;
    }
    return rd_be16(p);
}

static bool is_ldn_action(const uint8_t *p, size_t len)
{
    if (len < IEEE80211_HDRLEN + 8) {
        return false;
    }
    const uint8_t *b = p + IEEE80211_HDRLEN;
    return b[0] == LDN_CATEGORY_VENDOR_SPECIFIC && b[1] == LDN_OUI_0 &&
           b[2] == LDN_OUI_1 && b[3] == LDN_OUI_2 && b[4] == LDN_PROTOCOL_ID;
}

static bool is_ldn_control(const uint8_t *p, size_t len)
{
    if (len < sizeof(struct ethhdr) + 6) {
        return false;
    }
    const uint8_t *b = p + sizeof(struct ethhdr);
    return b[0] == LDN_OUI_0 && b[1] == LDN_OUI_1 && b[2] == LDN_OUI_2 &&
           (rd_be16(b + 3) == LDN_PACKET_AUTHENTICATION ||
            rd_be16(b + 3) == LDN_PACKET_DISCONNECT);
}

/* The AP interface bridges 802.11 to Ethernet, so LDN control frames arrive
 * with a normal Ethernet header (ethertype 0x88B7) and a padded 802.11-ish
 * body. Normalise them back into a plain 802.11 frame so the rest of the
 * stack can treat both paths identically. */
/*
 * Rebuild an inbound packet into the uniform 802.11 shape.
 *
 * `frame` is either
 *   - a raw 802.11 frame from the monitor interface (leading 802.11 header), or
 *   - an Ethernet frame bridged off hostapd's AP port (14-byte header,
 *     ethertype 0x88B7 for LDN control or 0x0800 for Pia IP traffic).
 *
 * The Ethernet case is the common one on the AP port, and the LDN body starts
 * at offset 14 there - not at offset 24. The old code compared a synthesised
 * MAC against the AP's real MAC and parsed the LDN body at the 802.11 offset,
 * so the authentication handshake could never be reached.
 */
static void emit(Radio *r, const uint8_t *frame, size_t len)
{
    if (!r->rx_cb || len < 2) {
        return;
    }
    if (len > 9000) {
        return;
    }

    RadioFrame f;
    memset(&f, 0, sizeof(f));
    f.timestamp_ms = now_ms();

    const uint8_t *src_mac, *dst_mac, *payload;
    size_t payload_len;

    if (len >= sizeof(struct ethhdr) && rd_be16(frame + 12) != ETH_P_LDN) {
        /* Probably an Ethernet frame; check the ethertype. */
        uint16_t etype = rd_be16(frame + 12);
        if (etype == 0x0800 || etype == 0x88DD || etype == 0x0806) {
            dst_mac = frame;
            src_mac = frame + 6;
            payload = frame + sizeof(struct ethhdr);
            payload_len = len - sizeof(struct ethhdr);
            goto build;
        }
    }

    if (len >= IEEE80211_HDRLEN) {
        /* A raw 802.11 frame: addr1 = destination, addr2 = source. */
        dst_mac = frame + 4;
        src_mac = frame + 10;
        payload = frame + IEEE80211_HDRLEN;
        payload_len = len - IEEE80211_HDRLEN;
        goto build;
    }

    return;

build:
    if (payload_len > sizeof(f.frame) - IEEE80211_HDRLEN) {
        payload_len = sizeof(f.frame) - IEEE80211_HDRLEN;
    }
    memcpy(f.src_mac, src_mac, 6);
    memcpy(f.dst_mac, dst_mac, 6);
    memset(f.frame, 0, IEEE80211_HDRLEN);
    memcpy(f.frame + 4, dst_mac, 6); /* addr1 */
    memcpy(f.frame + 10, src_mac, 6); /* addr2 */
    memcpy(f.frame + IEEE80211_HDRLEN, payload, payload_len);
    f.frame_len = IEEE80211_HDRLEN + payload_len;

    /*
     * No classification here. Both shapes are now "MAC header + payload", and
     * what the payload *is* (an LDN vendor body or an IP packet) is decided
     * once, in radio_rx(), from the payload bytes - not from an offset that
     * happens to mean different things depending on how the frame arrived.
     */
    r->rx_cb(&f, r->user);
}

/*
 * Remember which peer is the console. Learned from the source address of the
 * first datagram; ignored afterwards so a second caller cannot steal the
 * stream mid-session.
 */
static void learn_peer(Radio *r, const struct sockaddr *sa, socklen_t len)
{
    if (!r->socket_backend || r->have_peer || !sa || len == 0 ||
        sa->sa_family != AF_UNIX) {
        return;
    }
    if (len > sizeof(r->peer)) {
        len = sizeof(r->peer);
    }
    memset(&r->peer, 0, sizeof(r->peer));
    memcpy(&r->peer, sa, (size_t)len);
    r->peer_len = len;
    r->have_peer = true;
    LOG_I("radio: console attached to radio socket (peer path %s)",
          r->peer.sun_path[0] ? r->peer.sun_path : "<unnamed>");
}

/*
 * Read one pending datagram. On the socket backend recvfrom() is used so we
 * also learn the peer; the AF_PACKET path keeps the plain recv() it always
 * had, so its behaviour is byte-identical.
 */
static ssize_t pump_read(Radio *r, int fd, uint8_t *buf, size_t cap)
{
    if (!r->socket_backend) {
        return recv(fd, buf, cap, MSG_DONTWAIT);
    }
    struct sockaddr_storage from;
    memset(&from, 0, sizeof(from));
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(fd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&from,
                         &fromlen);
    if (n > 0) {
        learn_peer(r, (const struct sockaddr *)&from, fromlen);
    }
    return n;
}

static void pump_ap(Radio *r)
{
    for (int i = 0; i < 16; i++) {
        uint8_t buf[2304];
        ssize_t n = pump_read(r, r->ap_fd, buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        if (is_ldn_control(buf, (size_t)n)) {
            /* control frames come through the bridge as Ethernet frames */
            emit(r, buf, (size_t)n);
            continue;
        }
        /* otherwise it's an 802.11 frame from the AP VAP (auth request etc.) */
        uint16_t fc = get_fc(buf, (size_t)n);
        uint8_t type = (uint8_t)((fc >> 2) & 0x3);
        uint8_t subtype = (uint8_t)((fc >> 4) & 0xF);
        if (type == 0x00 && subtype == 0x0D) { /* action */
            emit(r, buf, (size_t)n);
        } else if (type == 0x02) { /* data frame (shouldn't happen on AP) */
            emit(r, buf, (size_t)n);
        }
    }
}

static void pump_monitor(Radio *r)
{
    for (int i = 0; i < 16; i++) {
        uint8_t buf[2304];
        ssize_t n = pump_read(r, r->mon_fd, buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        if (is_ldn_action(buf, (size_t)n)) {
            emit(r, buf, (size_t)n);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

Radio *radio_open(const RadioConfig *cfg, radio_rx_cb rx_cb, void *user)
{
    Radio *r = calloc(1, sizeof(*r));
    if (!r) {
        return NULL;
    }
    r->cfg = *cfg;
    r->rx_cb = rx_cb;
    r->user = user;
    r->adv_interval_ms = 100; /* LDN advertises every 100 ms */
    r->last_adv_ms = now_ms();

    /*
     * Socket backend. One bound Unix datagram socket replaces both raw
     * sockets, so the bridge can be driven - and CI-tested - without root or a
     * wireless NIC. The peer is discovered on the first inbound datagram.
     */
    if (cfg->radio_socket[0]) {
        int fd = radio_socket_open(cfg->radio_socket);
        if (fd < 0) {
            radio_close(r);
            return NULL;
        }
        r->ap_fd = fd;
        r->mon_fd = fd;
        r->socket_backend = true;
        if (cfg->mon_iface[0]) {
            LOG_W("--mon-iface %s ignored on the radio socket: one fd serves both",
                  cfg->mon_iface);
        }
        LOG_I("radio: socket backend on %s (no wireless NIC needed)",
              cfg->radio_socket);
        return r;
    }

    if (strlen(cfg->mon_iface)) {
        int idx;
        r->mon_fd = packet_open(cfg->mon_iface, ETH_P_ALL, &idx);
        if (r->mon_fd >= 0) {
            LOG_I("monitor interface %s ready (ifindex %d)", cfg->mon_iface, idx);
        }
    }

    int idx;
    r->ap_fd = packet_open(r->cfg.ap_iface, ETH_P_ALL, &idx);
    if (r->ap_fd < 0) {
        radio_close(r);
        return NULL;
    }
    LOG_I("AP interface %s ready (ifindex %d)", r->cfg.ap_iface, idx);

    return r;
}

void radio_close(Radio *radio)
{
    if (!radio) {
        return;
    }
    if (radio->ap_fd >= 0) {
        close(radio->ap_fd);
    }
    /* On the socket backend ap_fd and mon_fd are the same descriptor. */
    if (radio->mon_fd >= 0 && radio->mon_fd != radio->ap_fd) {
        close(radio->mon_fd);
    }
    free(radio);
}

int radio_send(Radio *radio, const uint8_t *frame, size_t len)
{
    if (!radio) {
        LOG_W("radio_send: no radio attached");
        return -1;
    }
    if (radio->ap_fd < 0 || len < 2) {
        return -1;
    }
    if (radio->socket_backend && !radio->have_peer) {
        radio_warn_no_peer(radio);
        return -1;
    }
    ssize_t n;
    if (radio->socket_backend) {
        /* sendto() re-resolves the peer's path, so the console must keep its
         * socket bound for as long as the bridge is talking to it. */
        n = sendto(radio->ap_fd, frame, len, MSG_DONTWAIT,
                   (struct sockaddr *)&radio->peer, radio->peer_len);
    } else {
        n = send(radio->ap_fd, frame, len, MSG_DONTWAIT);
    }
    if (n < 0) {
        LOG_E("radio_send: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int radio_send_action_frame(Radio *radio, const uint8_t *body, size_t len)
{
    if (!radio) {
        LOG_W("radio_send_action_frame: no radio attached");
        return -1;
    }

    /* Same 802.11 frame, just delivered to the socket peer instead of the
     * monitor interface. */
    if (radio->socket_backend) {
        if (!radio->have_peer) {
            radio_warn_no_peer(radio);
            return -1;
        }
        ssize_t n = sendto(radio->mon_fd, body, len, MSG_DONTWAIT,
                           (struct sockaddr *)&radio->peer, radio->peer_len);
        if (n < 0) {
            LOG_E("radio_send_action_frame: %s", strerror(errno));
            return -1;
        }
        return 0;
    }

    if (radio->mon_fd < 0) {
        LOG_E("no monitor interface configured for action frame injection");
        return -1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = socket_ifindex(radio->cfg.mon_iface);
    if (sll.sll_ifindex < 0) {
        return -1;
    }
    sll.sll_halen = 6;
    memset(sll.sll_addr, 0xFF, 6);

    ssize_t n = sendto(radio->mon_fd, body, len, MSG_DONTWAIT,
                       (struct sockaddr *)&sll, sizeof(sll));
    if (n < 0) {
        LOG_E("radio_send_action_frame: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void radio_poll(Radio *radio, int timeout_ms)
{
    if (!radio) {
        LOG_W("radio_poll: no radio attached");
        return;
    }
    /*
     * One fd covers both roles on the socket backend, so pumping the monitor
     * fd as well would drain the queue before pump_ap() ever sees a frame.
     */
    bool have_monitor = radio->mon_fd >= 0 && !radio->socket_backend;

    struct pollfd fds[2];
    fds[0].fd = radio->ap_fd;
    fds[0].events = POLLIN;
    size_t n = 1;
    if (have_monitor) {
        fds[n].fd = radio->mon_fd;
        fds[n].events = POLLIN;
        n++;
    }

    int rc = poll(fds, (nfds_t)n, timeout_ms);
    if (rc <= 0) {
        return;
    }
    if (have_monitor && (fds[1].revents & POLLIN)) {
        pump_monitor(radio);
    }
    if (fds[0].revents & POLLIN) {
        pump_ap(radio);
    }
}

