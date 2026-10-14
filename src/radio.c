#include "radio.h"

#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <unistd.h>

#include "common.h"

typedef struct Radio {
    RadioConfig cfg;

    int ap_fd;   /* AF_PACKET, ethertype capture on the AP interface */
    int mon_fd;  /* AF_PACKET, injected frames on the monitor interface */

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

    /* VIF support is what decides the whole architecture. */
    int idx = iface_index(iface);
    LOG_I("selfcheck %-16s ifindex=%d", iface, idx);
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
            f.payload_ethertype = etype;
            goto build;
        }
    }

    if (len >= IEEE80211_HDRLEN) {
        /* A raw 802.11 frame: addr1 = destination, addr2 = source. */
        dst_mac = frame + 4;
        src_mac = frame + 10;
        payload = frame + IEEE80211_HDRLEN;
        payload_len = len - IEEE80211_HDRLEN;
        f.payload_ethertype = 0;
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

    if (payload_len >= 6) {
        f.packet_type = rd_be16(payload + 3);
    }
    r->rx_cb(&f, r->user);
}

static void pump_ap(Radio *r)
{
    for (int i = 0; i < 16; i++) {
        uint8_t buf[2304];
        ssize_t n = recv(r->ap_fd, buf, sizeof(buf), MSG_DONTWAIT);
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
        ssize_t n = recv(r->mon_fd, buf, sizeof(buf), MSG_DONTWAIT);
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
    if (radio->mon_fd >= 0) {
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
    ssize_t n = send(radio->ap_fd, frame, len, MSG_DONTWAIT);
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
    struct pollfd fds[2];
    fds[0].fd = radio->ap_fd;
    fds[0].events = POLLIN;
    size_t n = 1;
    if (radio->mon_fd >= 0) {
        fds[n].fd = radio->mon_fd;
        fds[n].events = POLLIN;
        n++;
    }

    int rc = poll(fds, (nfds_t)n, timeout_ms);
    if (rc <= 0) {
        return;
    }
    if (radio->mon_fd >= 0 && (fds[1].revents & POLLIN)) {
        pump_monitor(radio);
    }
    if (fds[0].revents & POLLIN) {
        pump_ap(radio);
    }
}

