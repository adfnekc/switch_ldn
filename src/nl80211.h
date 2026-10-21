#ifndef SWITCH_LDN_NL80211_H
#define SWITCH_LDN_NL80211_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Management-frame injection and reception over nl80211.
 *
 * Why this exists: the LDN advertisement is an 802.11 vendor-specific action
 * frame. The obvious way to send it is a raw write to an AF_PACKET socket on a
 * monitor interface - which needs a second virtual interface. On the RTL8812AU
 * driver creating that VIF wedges the kernel outright (aircrack-ng/rtl8812au
 * #93, #376), measured three times. The driver does implement cfg80211's
 * .mgmt_tx, so the same frame can be sent on the AP interface hostapd already
 * owns, and the second interface disappears from the design.
 *
 * One interface, then: hostapd runs the AP and bridges ordinary data traffic,
 * advertisements go out through here, and LDN control frames are received by
 * subscribing to their OUI instead of sniffing a monitor device.
 *
 * The interface must be in AP mode. In managed mode and unassociated the kernel
 * answers -ENOTCONN.
 */
typedef struct Nl80211 Nl80211;

/* Returns NULL and logs why if nl80211 or the interface is unavailable. */
Nl80211 *nl80211_open(const char *ifname);
void nl80211_close(Nl80211 *nl);

/*
 * Send a complete 802.11 *management* frame (header included).
 *
 * `mhz`, `chan_width` and `center1` must describe the channel in full. A bare
 * frequency is not a parseable chandef and cfg80211 rejects it; omitting the
 * frequency instead leaves the vendor driver with a NULL channel and it
 * returns -EINVAL itself. Both mistakes look identical from the caller.
 *
 * Returns 0 when the kernel accepted the frame, a negative errno otherwise.
 */
int nl80211_mgmt_tx(Nl80211 *nl, const void *frame, size_t len, uint32_t mhz,
                    uint32_t chan_width, uint32_t center1);

/*
 * Subscribe to vendor-specific action frames carrying `oui` (+ one selector
 * byte). Received frames are full 802.11 management frames.
 */
int nl80211_register_action(Nl80211 *nl, const uint8_t oui[3], uint8_t oui_type);

/* The netlink fd, so callers can poll it alongside everything else. */
int nl80211_fd(const Nl80211 *nl);

/* Drain whatever is pending; `cb` sees each received action frame. */
int nl80211_drain(Nl80211 *nl,
                  void (*cb)(const uint8_t *frame, size_t len, void *user),
                  void *user);

#endif /* SWITCH_LDN_NL80211_H */
