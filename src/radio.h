#ifndef SWITCH_LDN_RADIO_H
#define SWITCH_LDN_RADIO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ldn.h"

#include <net/if.h>

/*
 * 802.11 radio layer.
 *
 * Design (see DESIGN.md section 3):
 *
 *   The bridge is the LDN *host*. hostapd runs a minimal hidden-AP on one
 *   virtual interface (SSID zeroed in beacons, open authentication, no WPA),
 *   which gives us auth/assoc/IP management for free. A second interface in
 *   monitor mode injects the LDN vendor-specific action frames every 100 ms,
 *   because neither hostapd nor the kernel drivers implement that.
 *
 *   LDN control frames (ethertype 0x88B7) and Pia game traffic ride the AP's
 *   bridge interface and are read/written through AF_PACKET raw sockets.
 *
 *   Scope note: the monitor-interface receive path (pump_monitor) is for
 *   diagnostics only - it lets you see *someone else's* LDN networks in the
 *   air. Actually joining one (p1) is not supported; see DESIGN.md "Scope".
 *
 * Why the bridge takes the host role: on a real console the LDN *station* has
 * to answer an authentication challenge proving it independently owns the game
 * (device id, HMAC, undocumented P/Q fields). As host we are the one issuing
 * that challenge, so we can just answer "success" - no ownership proof needed.
 *
 * Known hardware caveat: the out-of-tree RTL8812AU driver (aircrack-ng fork)
 * has flaky virtual-interface support. `radio_selfcheck` reports what the
 * actually loaded driver supports before you rely on the split AP/monitor
 * layout; the fallback (pure monitor + own MAC FSM) is documented in DESIGN.md.
 */

#define RADIO_MAX_VAPS 2

typedef struct {
    /* Interface that hostapd manages (usually a VAP of the NIC or the NIC
     * itself). LDN data and control frames are read/written here. */
    char ap_iface[IFNAMSIZ];
    /* Interface in monitor mode used to inject action frames. */
    char mon_iface[IFNAMSIZ];

    uint8_t channel;
    uint8_t band;
    uint8_t mac[6];
    uint8_t bssid[6];
    bool bssid_same_as_mac;
} RadioConfig;

/*
 * A parsed inbound frame, normalised to a uniform 802.11 shape:
 *
 *   frame[0 .. 23]   a synthetic MAC header (addr1 = dst, addr2 = src)
 *   frame[24 ..]     the L2 payload: LDN control frames (ethertype 0x88B7),
 *                    Pia IPv4/UDP frames, or a vendor-specific action frame
 *
 * Normalising here means every consumer below (host.c, ldn.c, the Pia relay
 * in main.c) can parse at fixed offsets, instead of having to know whether the
 * packet arrived on the monitor interface or was bridged out of hostapd as an
 * Ethernet frame. Getting that distinction wrong is what made the LDN
 * authentication handshake unreachable.
 */
typedef struct {
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t packet_type;
    uint8_t frame[2304];
    size_t frame_len;
    uint16_t payload_ethertype; /* 0x88B7 for LDN control, 0x0800 for IP */
    uint64_t timestamp_ms;
} RadioFrame;

/* The payload starts right after the synthetic 24-byte MAC header. */
#define RADIO_PAYLOAD(f) ((f)->frame + IEEE80211_HDRLEN)
#define RADIO_PAYLOAD_LEN(f) ((f)->frame_len - IEEE80211_HDRLEN)

typedef void (*radio_rx_cb)(const RadioFrame *frame, void *user);

typedef struct Radio Radio;

/* Bring up the sockets, apply the config, and start the AP. */
Radio *radio_open(const RadioConfig *cfg, radio_rx_cb rx_cb, void *user);
void radio_close(Radio *radio);

/* Send a raw 802.11 frame on the AP interface. */
int radio_send(Radio *radio, const uint8_t *frame, size_t len);

/* Inject a vendor-specific action frame on the monitor interface. */
int radio_send_action_frame(Radio *radio, const uint8_t *body, size_t len);

/* Pump the receive queue. */
void radio_poll(Radio *radio, int timeout_ms);

/* Report what the NIC actually supports. */
int radio_selfcheck(const char *iface);

/* Access the AP interface's netlink/hw addresses. */
int radio_get_hwaddr(const char *iface, uint8_t mac[6]);

/* Read back the active configuration (MAC/channel/ifaces). */
const RadioConfig *radio_config(const Radio *radio);

#endif /* SWITCH_LDN_RADIO_H */
