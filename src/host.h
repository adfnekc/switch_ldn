#ifndef SWITCH_LDN_HOST_H
#define SWITCH_LDN_HOST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ldn.h"
#include "radio.h"

/*
 * LDN **host** state machine (the 802.11 role).
 *
 * THIS IS THE ONLY ROLE IMPLEMENTED. The bridge never acts as an LDN station
 * (it cannot answer the authentication challenge - see DESIGN.md "Scope"),
 * so there is no scan-and-join path here; stations join *us*.
 *
 * The bridge owns:
 *   - the advertisement timer (100 ms action frames)
 *   - the station table (joined consoles) and the 169.254.X.Y IP space
 *   - the LDN authentication handshake, always answering "success"
 *   - the Pia mesh view, which it forwards to Ryubing/Eden via RyuLdn
 */

#define HOST_MAX_STATIONS 8


typedef struct {
    bool in_use;
    bool associated;    /* 802.11 assoc done, IP assigned */
    bool ldn_joined;   /* answered the LDN auth request */
    uint8_t mac[6];
    uint8_t platform;
    uint32_t ipv4; /* network byte order: 169.254.X.Y */
    char username[32];
    uint16_t app_communication_version;
    uint64_t last_seen_ms;
    uint64_t joined_ms;
} HostStation;

typedef struct {
    LdnSessionInfo session_info;
    LdnAdvertiseData adv_data;
    uint8_t adv_key[16];
    uint8_t data_key[16];
    bool keys_ready;
    bool has_passphrase;

    uint8_t nonce[LDN_NONCE_SIZE];
    uint8_t security_level;

    HostStation stations[HOST_MAX_STATIONS];
    int station_count;

    /* 169.254.X.1 - we always host the LDN network. */
    uint8_t host_ip_octet_x;

    const ProdKeys *prodkeys;
    uint64_t title_id;
    uint16_t channel;
    uint8_t band;
} LdnHost;

/* Attach to a running Radio. */
typedef struct Host Host;

/* Create / destroy the LDN host. */
Host *host_create(const ProdKeys *prodkeys, uint64_t title_id, uint16_t channel,
                  uint8_t band, uint8_t node_count_max,
                  const uint8_t *passphrase, size_t passphrase_len,
                  const char *host_username, uint16_t app_comm_version);
void host_destroy(Host *host);

/*
 * Adopt the settings a guest's game declared when it called
 * nn::ldn::CreateNetwork (delivered over RyuLdn as a CreateAccessPoint
 * packet). This is the main path: the bridge learns the title id, channel,
 * player limit, local communication version *and the crypto passphrase*
 * straight from the game, so no per-game table is involved.
 *
 * This is the host-side network creation. There is deliberately no counterpart
 * for the Connect/ConnectPrivate (join) path - see "Scope" in DESIGN.md.
 */
int host_adopt_guest_settings(Host *host, uint64_t title_id, uint16_t channel,
                              uint8_t node_count_max, const uint8_t *passphrase,
                              size_t passphrase_len, const char *username,
                              uint16_t app_comm_version);

/* Update the advertisement payload (players list, app data, etc.). */
void host_set_app_data(Host *host, const uint8_t *data, uint16_t size);
void host_sync_station_list(Host *host);

/*
 * Refresh a station's last-seen timestamp. Called whenever LDN traffic
 * arrives from an already-joined station (see the watchdog in host_tick()).
 * Does nothing for an out-of-range or unused slot.
 */
void host_touch_station(Host *host, int index);

/*
 * Set the station watchdog timeout in milliseconds (default 30 s). Passing 0
 * is a no-op so a caller cannot accidentally disable the watchdog.
 */
void host_set_station_timeout_ms(Host *host, uint64_t ms);

/* Per-frame dispatch. Returns true if the frame was consumed. */
bool host_handle_frame(Host *host, Radio *radio, const RadioFrame *frame);

/* Emit a fresh advertisement if the 100 ms deadline passed. */
void host_tick(Host *host, Radio *radio);


/*
 * Override node 0 (the guest) in the advertisement: username, MAC and Pia
 * version. Used by the transports, which learn these from the emulator.
 */
void host_set_guest_identity(Host *host, const char *username, const uint8_t mac[6],
                             uint16_t app_comm_version);

/*
 * Join/leave notifications.
 *
 * The bridge has to tell the emulator when a real console appears or
 * disappears, and it cannot infer that reliably by polling the station table
 * (a station can be re-used). So the host FSM records events and the transport
 * drains them.
 */
typedef enum {
    HOST_EVENT_STATION_JOINED = 1,
    HOST_EVENT_STATION_LEFT,
} HostEventKind;

typedef struct {
    HostEventKind kind;
    int index; /* station slot */
    /*
     * Snapshot of the station, taken before the slot is cleared.
     *
     * A leave event has to be actionable *after* the slot is gone: the studio
     * producers memset the station before pushing, so anything that tries to
     * read the table when draining the ring finds an empty slot and does
     * nothing - which is how leaves used to be swallowed. Carry the identity so
     * the event is self-contained.
     */
    uint8_t mac[6];
    uint32_t ipv4; /* network byte order, as in HostStation */
    uint16_t app_communication_version;
    char username[32]; /* sizeof(((HostStation *)0)->username) */
} HostEvent;

/* Returns 1 and fills `ev` when an event is pending, 0 when drained. */
int host_poll_event(Host *host, HostEvent *ev);

/* Introspection for the bridge. */
int host_station_index_by_mac(const Host *host, const uint8_t mac[6]);
const HostStation *host_station(const Host *host, int index);
int host_station_count(const Host *host);
const LdnAdvertiseData *host_advertise(const Host *host);
const LdnSessionInfo *host_session_info(const Host *host);

/* The wire-format advertisement nonce (4 bytes, big-endian). */
const uint8_t *host_nonce(const Host *host);

#endif /* SWITCH_LDN_HOST_H */
