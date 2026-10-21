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
#include "nl80211.h"

typedef struct Radio {
    RadioConfig cfg;

    int ap_fd;   /* AF_PACKET, ethertype capture on the AP interface */
    int mon_fd;  /* AF_PACKET, injected frames on the monitor interface */

    /* Socket backend: one bound AF_UNIX datagram socket standing in for both
     * interfaces above. The peer is whoever sent the first datagram, and it
     * stays the console until the bridge is closed. */
    bool socket_backend;

    /*
     * nl80211 handle for action-frame injection on the AP interface. Present
     * when no monitor interface was configured: the RTL8812AU driver wedges the
     * kernel if asked for a monitor VIF, but it does implement .mgmt_tx.
     */
    struct Nl80211 *nl;
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

static bool is_ldn_action(const uint8_t *p, size_t len)
{
    if (len < IEEE80211_HDRLEN + 8) {
        return false;
    }
    const uint8_t *b = p + IEEE80211_HDRLEN;
    return b[0] == LDN_CATEGORY_VENDOR_SPECIFIC && b[1] == LDN_OUI_0 &&
           b[2] == LDN_OUI_1 && b[3] == LDN_OUI_2 && b[4] == LDN_PROTOCOL_ID;
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
/*
 * `is_ethernet` is supplied by the caller, which already classified the frame.
 *
 * Deriving it here from the bytes was wrong twice over: an Ethernet LDN
 * control frame has ethertype 0x88B7, which the old condition explicitly
 * excluded, so it fell through to the 802.11 branch and every inbound
 * authentication request was parsed at the wrong offsets. The caller always
 * knows - pump_ap classifies with is_ldn_control(), the monitor and nl80211
 * paths are always 802.11 - so let it say so.
 */
static void emit(Radio *r, const uint8_t *frame, size_t len, bool is_ethernet)
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

    if (is_ethernet) {
        if (len < sizeof(struct ethhdr)) {
            return;
        }
        dst_mac = frame;
        src_mac = frame + 6;
        payload = frame + sizeof(struct ethhdr);
        payload_len = len - sizeof(struct ethhdr);
        goto build;
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

/* Rate-limited so a misbehaving peer cannot flood the log. */
static void warn_dropped_ap_frame(const uint8_t *p, size_t len)
{
    static uint64_t last_ms;
    static unsigned count;

    count++;
    uint64_t now = now_ms();
    if (last_ms && now - last_ms < 5000) {
        return;
    }
    last_ms = now;
    uint16_t fc = len >= 2 ? rd_le16(p) : 0;
    LOG_W("dropped %zu-byte frame on the AP interface: not LDN control (0x88B7), "
          "not IPv4/IPv6/ARP, and not a usable 802.11 frame (fc=0x%04x); "
          "%u dropped so far",
          len, fc, count);
}

static void pump_ap(Radio *r)
{
    for (int i = 0; i < 16; i++) {
        uint8_t buf[2304];
        ssize_t n = pump_read(r, r->ap_fd, buf, sizeof(buf));
        if (n <= 0) {
            return;
        }
        switch (ldn_classify_ap_frame(buf, (size_t)n)) {
        case LDN_FRAME_CONTROL:
            /* LDN control frames come through the bridge as Ethernet 0x88B7. */
        case LDN_FRAME_ETHERNET:
            /* Pia traffic, bridged out of hostapd as Ethernet. */
            emit(r, buf, (size_t)n, true);
            break;
        case LDN_FRAME_80211_ACTION:
        case LDN_FRAME_80211_DATA:
            emit(r, buf, (size_t)n, false);
            break;
        case LDN_FRAME_DROP:
            /* Not silently: an AP netdev only produces Ethernet, so anything
             * here is a framing we did not expect, and dropping it quietly is
             * how the 0x88B7 bug survived. */
            warn_dropped_ap_frame(buf, (size_t)n);
            break;
        }
    }
}

/* An action frame received over nl80211 goes through the same normaliser as
 * every other inbound frame, so host.c and the relay cannot tell the
 * difference between an injected and a sniffed frame. */
static void nl_frame_cb(const uint8_t *frame, size_t len, void *user)
{
    emit((Radio *)user, frame, len, false);
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
            emit(r, buf, (size_t)n, false);
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
    } else {
        /*
         * No monitor interface: inject the advertisements through nl80211 on
         * the AP interface instead. This is the path the RTL8812AU needs,
         * because asking that driver for a monitor VIF wedges the kernel.
         * Failure is not fatal - data traffic still flows - but without it no
         * console will ever see the network, so say so loudly.
         */
        r->nl = nl80211_open(cfg->ap_iface);
        if (!r->nl) {
            LOG_E("no monitor interface and nl80211 is unavailable: the LDN "
                  "advertisement cannot be transmitted, so no console will "
                  "find this network");
        } else {
            uint8_t oui[3] = {LDN_OUI_0, LDN_OUI_1, LDN_OUI_2};
            nl80211_register_action(r->nl, oui, LDN_PROTOCOL_ID);
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
    if (radio->nl) {
        nl80211_close(radio->nl);
        radio->nl = NULL;
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

int radio_send_ldn_control(Radio *radio, const uint8_t dst_mac[6], const void *body,
                           size_t len)
{
    if (!radio || !dst_mac || !body || len == 0) {
        return -1;
    }
    if (len > 1500) {
        LOG_E("radio_send_ldn_control: %zu-byte body is too large", len);
        return -1;
    }
    uint8_t frame[14 + 1500];
    int n = ldn_build_ldn_ethernet(frame, sizeof(frame), dst_mac, radio->cfg.mac,
                                   body, len);
    if (n < 0) {
        LOG_E("radio_send_ldn_control: cannot build the frame");
        return -1;
    }
    return radio_send(radio, frame, (size_t)n);
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

    if (radio->nl) {
        /*
         * The channel has to be described in full (see nl80211.h); 20 MHz with
         * no HT is what LDN uses and what hostapd was started with.
         */
        uint32_t mhz = radio->cfg.band == 5
                           ? (uint32_t)(5000 + 5 * radio->cfg.channel)
                           : (uint32_t)(2407 + 5 * radio->cfg.channel);
        int rc = nl80211_mgmt_tx(radio->nl, body, len, mhz,
                                 0 /* NL80211_CHAN_WIDTH_20_NOHT */, mhz);
        if (rc != 0) {
            return -1;
        }
        return 0;
    }

    if (radio->mon_fd < 0) {
        LOG_E("no monitor interface and no nl80211 handle: cannot inject "
              "action frames");
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

    struct pollfd fds[3];
    fds[0].fd = radio->ap_fd;
    fds[0].events = POLLIN;
    size_t n = 1;
    if (have_monitor) {
        fds[n].fd = radio->mon_fd;
        fds[n].events = POLLIN;
        n++;
    }
    int nl_at = -1;
    if (radio->nl) {
        fds[n].fd = nl80211_fd(radio->nl);
        fds[n].events = POLLIN;
        nl_at = (int)n;
        n++;
    }

    int rc = poll(fds, (nfds_t)n, timeout_ms);
    if (rc <= 0) {
        return;
    }
    if (have_monitor && (fds[1].revents & POLLIN)) {
        pump_monitor(radio);
    }
    if (nl_at >= 0 && (fds[nl_at].revents & POLLIN)) {
        nl80211_drain(radio->nl, nl_frame_cb, radio);
    }
    if (fds[0].revents & POLLIN) {
        pump_ap(radio);
    }
}

