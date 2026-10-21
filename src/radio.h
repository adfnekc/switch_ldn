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
 *   The bridge is the LDN *host*. hostapd runs a minimal AP on ONE interface
 *   (SSID hidden in beacons, open authentication, no WPA), which gives us
 *   auth/assoc/IP management for free.
 *
 *   LDN control frames (ethertype 0x88B7) and Pia game traffic ride that
 *   interface and are read/written through an AF_PACKET raw socket: the kernel
 *   and hostapd bridge them to 802.11 data frames.
 *
 *   The LDN vendor-specific action frames cannot go through that path, so they
 *   are injected with nl80211 .mgmt_tx on the same interface every 100 ms (see
 *   nl80211.h). The original design used a second, monitor-mode interface for
 *   this; on the RTL8812AU creating that VIF wedges the kernel, and .mgmt_tx
 *   makes it unnecessary. A monitor interface is still accepted (--mon-iface)
 *   for drivers where it works.
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
 * has flaky virtual-interface support - a monitor VIF hangs it outright.
 * `radio_selfcheck` therefore only reports capabilities and never creates one.
 */

#define RADIO_MAX_VAPS 2

/* Length of sun_path in a sockaddr_un, the longest --radio-socket path we take. */
#define RADIO_SOCKET_PATH_MAX 108

typedef struct {
    /* Interface that hostapd manages (usually a VAP of the NIC or the NIC
     * itself). LDN data and control frames are read/written here. */
    char ap_iface[IFNAMSIZ];
    /*
     * Optional interface in monitor mode, used to inject action frames the old
     * way. Leave it empty on the RTL8812AU: creating a monitor VIF wedges that
     * driver, so radio_open() falls back to nl80211 .mgmt_tx on ap_iface
     * instead. See src/nl80211.h.
     */
    char mon_iface[IFNAMSIZ];

    /* Optional socket radio backend. When set, radio_open() binds a Unix
     * datagram socket at this path and uses that one fd in place of both
     * AF_PACKET sockets: a client on the other end of the socket plays the
     * console - it injects frames with sendto() and reads everything the
     * bridge transmits with recvfrom(). The bytes are exactly what the real
     * NICs would have produced, so nothing above the radio layer cares which
     * backend is live. No root and no wireless NIC, so CI can use it. */
    char radio_socket[RADIO_SOCKET_PATH_MAX];

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
    uint8_t frame[2304];
    size_t frame_len;
    uint64_t timestamp_ms;
} RadioFrame;

/*
 * The payload starts right after the synthetic 24-byte MAC header. Use these
 * rather than open-coding the offset: emit() prepends that header to *both*
 * input shapes, so "payload" means the same thing whatever the frame arrived
 * as, and a hand-written offset is how the LDN dispatch ended up reading an
 * EtherType out of the middle of addr2.
 */
#define RADIO_PAYLOAD(f) ((f)->frame + IEEE80211_HDRLEN)
#define RADIO_PAYLOAD_LEN(f) ((f)->frame_len - IEEE80211_HDRLEN)

typedef void (*radio_rx_cb)(const RadioFrame *frame, void *user);

typedef struct Radio Radio;

/* Bring up the sockets, apply the config, and start the AP. */
Radio *radio_open(const RadioConfig *cfg, radio_rx_cb rx_cb, void *user);
void radio_close(Radio *radio);

/* Send a raw 802.11 frame on the AP interface. */
int radio_send(Radio *radio, const uint8_t *frame, size_t len);

/*
 * Send an LDN control frame to a station.
 *
 * `body` is the 0x88B7 body (see ldn_build_auth_body). It is wrapped in an
 * Ethernet frame with ethertype 0x88B7 and written to the AP interface, which
 * is the only framing that interface understands - hostapd and the kernel turn
 * it into an 802.11 data frame addressed to `dst_mac`. Passing a raw 802.11
 * frame to radio_send() instead produces an Ethernet frame with a bogus
 * ethertype, and the station never receives anything.
 */
int radio_send_ldn_control(Radio *radio, const uint8_t dst_mac[6],
                           const void *body, size_t len);

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
