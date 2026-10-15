#include "ryuldn.h"

#define LDN_NODE_MAX 8

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "common.h"

/* ------------------------------------------------------------------ */
/* Session                                                            */
/* ------------------------------------------------------------------ */

#define SESSION_RECV_MAX (64 * 1024)

typedef struct RyuSession {
    int fd;
    bool alive;
    bool initialized;
    uint8_t session_id[16];
    uint8_t mac[6]; /* server-assigned; the guest waits for this */
    char user_name[33];
    uint8_t node_id;
    uint8_t has_node_id;
    uint8_t accept_policy;
    char room_passphrase[128];

    uint8_t recv[SESSION_RECV_MAX];
    size_t recv_len;

    /* What the guest's game told us via CreateNetwork (see ryuldn.h). */
    RyuLdnGuestGameSettings guest;
    bool has_guest;

    /* deferred creates (a guest that has not completed the handshake yet) */
    struct RyuSession *next;
} RyuSessionImpl;

struct RyuLdnSession {
    RyuSessionImpl impl;
};

struct RyuLdnServer {
    int fd;
    char bind_addr[64];
    uint16_t port;
    RyuLdnHandlers handlers;
    void *user;
    RyuSessionImpl *sessions; /* singly linked, heap allocated */
    uint32_t mac_counter;     /* hands out 02:4A:57:53:xx:xx MACs */
};

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

void ryuldn_header_init(RyuLdnHeader *h, uint8_t type, int32_t data_size)
{
    memset(h, 0, sizeof(*h));
    h->magic[0] = (uint8_t)(RYULDN_MAGIC & 0xFF);
    h->magic[1] = (uint8_t)((RYULDN_MAGIC >> 8) & 0xFF);
    h->magic[2] = (uint8_t)((RYULDN_MAGIC >> 16) & 0xFF);
    h->magic[3] = (uint8_t)((RYULDN_MAGIC >> 24) & 0xFF);
    h->type = type;
    h->version = RYULDN_VERSION;
    h->data_size = (uint32_t)data_size;
}

bool ryuldn_header_ok(const RyuLdnHeader *h)
{
    return rd_le32(h->magic) == RYULDN_MAGIC && h->version == RYULDN_VERSION;
}

/*
 * Mint a MAC for a guest. Ryubing/LdnServer hands out random ones and keyed by
 * session id; for the bridge a deterministic locally-administered pool is
 * simpler and easier to recognise in a packet capture.
 *
 *   02:4A:57:53:00:01 .. 02:4A:57:53:00:FF
 */
static void mint_mac(uint8_t mac[6], uint32_t index)
{
    mac[0] = 0x02; /* locally administered, no OUI clash with a real Switch */
    mac[1] = 0x4A;
    mac[2] = 0x57;
    mac[3] = 0x53;
    mac[4] = (uint8_t)((index >> 8) & 0xFF);
    mac[5] = (uint8_t)(index & 0xFF);
}

static void mint_session_id(uint8_t id[16], int fd)
{
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        if (fread(id, 1, 16, f) != 16) {
            /* fall through */
        }
        fclose(f);
        return;
    }
    /* fall back to something reproducible from the descriptor */
    memset(id, 0, 16);
    wr_le32(id, (uint32_t)fd);
    wr_le32(id + 4, 0x4C444E53u); /* "SNDL" */
}

static void set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

void ryuldn_network_info_init(RyuLdnNetworkInfo *info)
{
    memset(info, 0, sizeof(*info));
    info->node_count_max = LDN_NODE_MAX;
    info->security_mode = 1; /* Product */
    info->station_accept_policy = 0;
    info->advertise_data_size = 0;
    info->authentication_id = 0;
}

/* ------------------------------------------------------------------ */
/* Frame write                                                        */
/* ------------------------------------------------------------------ */

/*
 * A guest that stops reading (a paused Ryubing, a suspended Eden) must not be
 * able to wedge the bridge: the main loop is single threaded, so a spinning
 * send() here would stop radio_poll(), room_server_poll() and host_tick(), and
 * the console would watch the network disappear.
 *
 * So instead of spinning we wait for writability with poll() in bounded
 * slices, warn once the guest has been stuck for a moment, and give up on the
 * session entirely if it makes no progress for SESSION_WRITE_STALL_MS. The
 * session is then marked dead, which the reap path in
 * ryuldn_server_poll() turns into close() + free().
 */
#define SESSION_WRITE_POLL_MS 50   /* poll() slice while the guest is not reading */
#define SESSION_WRITE_GRACE_MS 250 /* complain once a write has been stuck this long */
#define SESSION_WRITE_WARN_MS 1000 /* ...and then at most this often */
#define SESSION_WRITE_STALL_MS 5000 /* no progress at all: drop the session */

static int session_write_all(RyuSessionImpl *s, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    uint64_t stuck_since = 0; /* ms timestamp, 0 = not currently blocked */
    uint64_t last_warn = 0;

    while (off < len) {
        ssize_t n = send(s->fd, buf + off, len - off, MSG_NOSIGNAL);
        if (n >= 0) {
            off += (size_t)n;
            stuck_since = 0; /* progress: the stall is over */
            continue;
        }
        if (errno == EINTR) {
            continue; /* interrupted by a signal: just retry */
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_E("session %d: send failed: %s", s->fd, strerror(errno));
            s->alive = false;
            return -1;
        }

        /*
         * The socket buffer is full because the guest is not reading. Never
         * spin: wait for it to drain, and keep an eye on the clock so a peer
         * that never reads cannot hang the rest of the bridge.
         */
        uint64_t now = now_ms();
        if (!stuck_since) {
            stuck_since = now;
            last_warn = now;
            LOG_W("session %d: guest is not reading, write blocked (%zu bytes left)",
                  s->fd, len - off);
        } else {
            if (now - last_warn >= SESSION_WRITE_WARN_MS) {
                LOG_W("session %d: still blocked after %llu ms", s->fd,
                      (unsigned long long)(now - stuck_since));
                last_warn = now;
            }
            if (now - stuck_since >= SESSION_WRITE_STALL_MS) {
                LOG_E("session %d: no send progress for %llu ms, dropping it", s->fd,
                      (unsigned long long)(now - stuck_since));
                s->alive = false;
                return -1;
            }
        }

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = s->fd;
        pfd.events = POLLOUT;
        int rc = poll(&pfd, 1, SESSION_WRITE_POLL_MS);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            LOG_E("session %d: poll failed: %s", s->fd, strerror(errno));
            s->alive = false;
            return -1;
        }
    }
    return 0;
}

static RyuLdnSession *as_session(RyuSessionImpl *impl)
{
    return (RyuLdnSession *)impl;
}

static void send_packet(RyuSessionImpl *s, uint8_t type, const void *payload,
                        int32_t payload_len)
{
    uint8_t header[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)header, type, payload_len);
    if (session_write_all(s, header, sizeof(header)) != 0) {
        return;
    }
    if (payload_len > 0) {
        session_write_all(s, payload, (size_t)payload_len);
    }
}

void ryuldn_send_proxy_config(RyuLdnSession *session, RyuLdnProxyConfig cfg)
{
    send_packet(&session->impl, RYULDN_PROXY_CONFIG, &cfg, (int32_t)sizeof(cfg));
}

void ryuldn_send_sync_network(RyuLdnSession *session, const RyuLdnNetworkInfo *info)
{
    send_packet(&session->impl, RYULDN_SYNC_NETWORK, info,
                (int32_t)sizeof(RyuLdnNetworkInfo));
}

void ryuldn_send_initialize(RyuLdnSession *session, const uint8_t session_id[16],
                            const uint8_t mac[6])
{
    uint8_t payload[22];
    memset(payload, 0, sizeof(payload));
    memcpy(payload, session_id, 16);
    memcpy(payload + 16, mac, 6);
    send_packet(&session->impl, RYULDN_INITIALIZE, payload, (int32_t)sizeof(payload));
}

void ryuldn_send_connected(RyuLdnSession *session, const RyuLdnNetworkInfo *info)
{
    send_packet(&session->impl, RYULDN_CONNECTED, info,
                (int32_t)sizeof(RyuLdnNetworkInfo));
}

void ryuldn_send_scan_reply_end(RyuLdnSession *session)
{
    send_packet(&session->impl, RYULDN_SCAN_REPLY_END, NULL, 0);
}

void ryuldn_send_reject_reply(RyuLdnSession *session)
{
    send_packet(&session->impl, RYULDN_REJECT_REPLY, NULL, 0);
}

void ryuldn_send_proxy_connect_reply(RyuLdnSession *session, RyuLdnProxyInfo info)
{
    send_packet(&session->impl, RYULDN_PROXY_CONNECT_REPLY, &info,
                (int32_t)sizeof(info));
}

void ryuldn_send_proxy_data(RyuLdnSession *session, RyuLdnProxyInfo info,
                            const uint8_t *data, size_t len)
{
    uint8_t buf[sizeof(RyuLdnProxyDataHeader) + 0x40000];
    RyuLdnProxyDataHeader *h = (RyuLdnProxyDataHeader *)buf;
    h->info = info;
    h->data_length = (uint32_t)len;
    if (len > sizeof(buf) - sizeof(*h)) {
        LOG_E("proxy data too large (%zu)", len);
        return;
    }
    memcpy(buf + sizeof(*h), data, len);
    send_packet(&session->impl, RYULDN_PROXY_DATA, buf,
                (int32_t)(sizeof(*h) + len));
}

void ryuldn_send_network_error(RyuLdnSession *session, uint32_t error_code)
{
    send_packet(&session->impl, RYULDN_NETWORK_ERROR, &error_code, 4);
}

void ryuldn_send_ping(RyuLdnSession *session, uint8_t requester, uint8_t id)
{
    RyuLdnPingMessage ping = {requester, id};
    send_packet(&session->impl, RYULDN_PING, &ping, (int32_t)sizeof(ping));
}

/* ------------------------------------------------------------------ */
/* Guest settings accessors                                           */
/* ------------------------------------------------------------------ */

const RyuLdnGuestGameSettings *ryuldn_session_guest_settings(const RyuLdnSession *session)
{
    return session->impl.has_guest ? &session->impl.guest : NULL;
}

/* ------------------------------------------------------------------ */
/* Accessors                                                          */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Dispatch                                                           */
/* ------------------------------------------------------------------ */

static void handle_packet(RyuLdnServer *server, RyuSessionImpl *s, uint8_t type,
                          const uint8_t *payload, uint32_t len)
{
    RyuLdnSession *session = as_session(s);

    switch (type) {
    case RYULDN_PASSPHRASE: {
        if (len < 128) {
            return;
        }
        size_t n = strnlen((const char *)payload, 128);
        if (n >= sizeof(s->room_passphrase)) {
            n = sizeof(s->room_passphrase) - 1;
        }
        memcpy(s->room_passphrase, payload, n);
        s->room_passphrase[n] = '\0';
        LOG_D("session %d: room passphrase='%s'", s->fd, s->room_passphrase);
        break;
    }

    case RYULDN_INITIALIZE: {
        if (len < 22) {
            LOG_W("session %d: short Initialize", s->fd);
            return;
        }
        /*
         * The guest sends an all-zero id/MAC on first contact, or its previous
         * ones to resume. Either way it needs a MAC assigned before it can
         * build an LDN network, so this reply is mandatory.
         */
        uint8_t want_id[16], want_mac[6];
        memcpy(want_id, payload, 16);
        memcpy(want_mac, payload + 16, 6);

        bool has_id = false, has_mac = false;
        for (int i = 0; i < 16; i++) {
            has_id |= payload[i] != 0;
        }
        for (int i = 0; i < 6; i++) {
            has_mac |= payload[16 + i] != 0;
        }

        if (has_id) {
            memcpy(s->session_id, want_id, 16);
        } else {
            mint_session_id(s->session_id, s->fd);
        }
        if (has_mac) {
            memcpy(s->mac, want_mac, 6);
        } else {
            mint_mac(s->mac, ++server->mac_counter);
        }

        s->initialized = true;
        ryuldn_send_initialize(session, s->session_id, s->mac);

        LOG_I("session %d: initialize -> mac=%02x:%02x:%02x:%02x:%02x:%02x",
              s->fd, s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5]);

        if (server->handlers.on_initialized) {
            server->handlers.on_initialized(session, s->session_id, s->mac, server->user);
        }
        break;
    }

    case RYULDN_CREATE_ACCESS_POINT:
    case RYULDN_CREATE_ACCESS_POINT_PRIVATE: {
        if (!s->initialized) {
            ryuldn_send_network_error(session, 0); /* None */
            return;
        }

        /*
         * The request carries the game's own LDN configuration, verbatim from
         * its nn::ldn::CreateNetwork call:
         *
         *   0x00 SecurityConfig    (crypto passphrase!)
         *   0x44 UserConfig        (username)
         *   0x74 NetworkConfig     (title id, channel, node count, version)
         *   0x94 RyuNetworkConfig
         *   0xBC advertise data    (game-specific, variable length)
         *
         * Grabbing it here means the bridge can build the real 802.11 network
         * with the game's own passphrase, title id and local communication
         * version - which is exactly why no per-game table is needed.
         */
        RyuLdnGuestGameSettings guest;
        memset(&guest, 0, sizeof(guest));

        if (len >= (uint32_t)sizeof(guest.security)) {
            memcpy(&guest.security, payload, sizeof(guest.security));

            if (guest.security.passphrase_size > sizeof(guest.security.passphrase)) {
                LOG_W("session %d: bogus PassphraseSize %u", s->fd,
                      guest.security.passphrase_size);
                guest.security.passphrase_size = 0;
            }
        }
        if (len >= 0x74 + (uint32_t)sizeof(guest.network)) {
            memcpy(&guest.network, payload + 0x74, sizeof(guest.network));
        }
        if (len >= 0x44 + (uint32_t)sizeof(guest.user)) {
            memcpy(&guest.user, payload + 0x44, sizeof(guest.user));
            size_t n = strnlen(guest.user.user_name, sizeof(guest.user.user_name));
            memcpy(s->user_name, guest.user.user_name, n);
            s->user_name[n] = '\0';
        }
        if (len > 0xBC) {
            guest.advertise_data_size = (uint16_t)(len - 0xBC);
            if (guest.advertise_data_size > sizeof(guest.advertise_data)) {
                guest.advertise_data_size = sizeof(guest.advertise_data);
            }
            memcpy(guest.advertise_data, payload + 0xBC, guest.advertise_data_size);
        }

        s->guest = guest;
        s->has_guest = true;

        LOG_I("session %d: %s '%s' title=%016llx scene=%u mode=%u chan=%u "
              "max_nodes=%u ver=%u passphrase=%u bytes",
              s->fd,
              type == RYULDN_CREATE_ACCESS_POINT ? "createAccessPoint"
                                                 : "createAccessPointPrivate",
              s->user_name,
              (unsigned long long)s->guest.network.intent_id.local_communication_id,
              s->guest.network.intent_id.scene_id, guest.security.security_mode,
              guest.network.channel, guest.network.node_count_max,
              guest.network.local_communication_version, guest.security.passphrase_size);

        if (server->handlers.on_access_point) {
            server->handlers.on_access_point(session, payload, len,
                                            type == RYULDN_CREATE_ACCESS_POINT_PRIVATE,
                                            server->user);
        }
        break;
    }

    case RYULDN_SCAN: {
        /*
         * Scanning would only matter for joining someone else's network (p1).
         * In p0 the guest is the host and the real consoles join it, so there
         * is never anything for the guest to discover. Reply with an empty
         * list so the game does not hang.
         */
        LOG_D("session %d: Scan (p0: the guest hosts, so nothing to report)",
              s->fd);
        if (server->handlers.on_scan) {
            server->handlers.on_scan(session, payload, len, server->user);
        }
        break;
    }

    case RYULDN_CONNECT:
    case RYULDN_CONNECT_PRIVATE: {
        /*
         * ====================================================================
         * NOT SUPPORTED (p1).
         *
         * This is the guest's game asking to JOIN a network, which would make
         * the bridge an LDN *station*. A station has to answer the LDN v3+
         * authentication challenge, proving the game was independently
         * purchased on this machine (device id, HMAC, undocumented P/Q
         * material) - material this bridge has no way to produce.
         *
         * The bridge only implements the *host* role (p0): the emulator creates
         * the network with CreateAccessPoint and real consoles join it. See
         * DESIGN.md "Scope".
         * ====================================================================
         */
        if (len >= 0x44 + 0x30) {
            RyuLdnUserConfig uc;
            memcpy(&uc, payload + 0x44, sizeof(uc));
            size_t n = strnlen(uc.user_name, sizeof(uc.user_name));
            memcpy(s->user_name, uc.user_name, n);
            s->user_name[n] = '\0';
        }
        LOG_E("session %d: '%s' asked to JOIN a network (Connect); the bridge only "
              "supports HOSTING. Have the emulator's game create the network "
              "(CreateAccessPoint) instead - see DESIGN.md.",
              s->fd, s->user_name);
        ryuldn_send_network_error(session, 202 /* ConnectionRejected */);
        break;
    }

    case RYULDN_SET_ACCEPT_POLICY:
        if (len >= 1) {
            s->accept_policy = payload[0];
            if (server->handlers.on_set_accept_policy) {
                server->handlers.on_set_accept_policy(session, payload[0],
                                                     server->user);
            }
        }
        break;

    case RYULDN_SET_ADVERTISE_DATA:
        if (server->handlers.on_set_advertise_data) {
            server->handlers.on_set_advertise_data(session, payload, len,
                                                  server->user);
        }
        break;

    case RYULDN_REJECT:
        ryuldn_send_reject_reply(session);
        break;

    case RYULDN_PROXY_CONNECT:
        if (len >= (uint32_t)sizeof(RyuLdnProxyInfo)) {
            RyuLdnProxyInfo info;
            memcpy(&info, payload, sizeof(info));
            if (server->handlers.on_proxy_connect) {
                server->handlers.on_proxy_connect(session, info, server->user);
            }
        }
        break;

    case RYULDN_PROXY_DATA:
        if (len > (uint32_t)sizeof(RyuLdnProxyDataHeader)) {
            RyuLdnProxyDataHeader h;
            memcpy(&h, payload, sizeof(h));
            if (server->handlers.on_proxy_data) {
                server->handlers.on_proxy_data(session, h.info, payload + sizeof(h),
                                               h.data_length, server->user);
            }
        }
        break;

    case RYULDN_PROXY_DISCONNECT:
        if (len >= (uint32_t)sizeof(RyuLdnProxyInfo)) {
            RyuLdnProxyInfo info;
            memcpy(&info, payload, sizeof(info));
            if (server->handlers.on_proxy_disconnect) {
                server->handlers.on_proxy_disconnect(session, info, server->user);
            }
        }
        break;

    case RYULDN_DISCONNECT:
        s->alive = false;
        if (server->handlers.on_disconnected) {
            server->handlers.on_disconnected(session, server->user);
        }
        break;

    case RYULDN_PING:
        /* PingMessage is {requester, id}; the server answers with requester=0
         * and the same id (Ryubing/LdnServer LdnSession.cs). */
        if (len >= 2) {
            ryuldn_send_ping(session, 0, payload[1]);
        }
        break;

    case RYULDN_EXTERNAL_PROXY:
        /* Not supported by the bridge: we want all game traffic through us. */
        LOG_W("session %d: guest asked for an external proxy; ignoring", s->fd);
        break;

    default:
        LOG_W("session %d: unhandled packet type %u", s->fd, type);
        break;
    }
}

static void session_readable(RyuLdnServer *server, RyuSessionImpl *s)
{
    uint8_t buf[16384];
    ssize_t n;
    while ((n = recv(s->fd, buf, sizeof(buf), 0)) > 0) {
        if (s->recv_len + (size_t)n > SESSION_RECV_MAX) {
            LOG_E("session %d: receive overflow", s->fd);
            s->alive = false;
            return;
        }
        memcpy(s->recv + s->recv_len, buf, (size_t)n);
        s->recv_len += (size_t)n;

        size_t off = 0;
        while (s->recv_len - off >= RYULDN_HEADER_SIZE) {
            RyuLdnHeader h;
            memcpy(&h, s->recv + off, RYULDN_HEADER_SIZE);
            if (!ryuldn_header_ok(&h)) {
                LOG_E("session %d: bad magic, dropping", s->fd);
                s->alive = false;
                return;
            }
            uint32_t dlen = rd_le32((const uint8_t *)&h.data_size);
            if (s->recv_len - off < RYULDN_HEADER_SIZE + dlen) {
                break;
            }
            handle_packet(server, s, h.type, s->recv + off + RYULDN_HEADER_SIZE, dlen);
            off += RYULDN_HEADER_SIZE + dlen;
        }

        if (off) {
            memmove(s->recv, s->recv + off, s->recv_len - off);
            s->recv_len -= off;
        }
    }

    if (n == 0) {
        LOG_I("session %d: closed", s->fd);
        s->alive = false;
        if (server->handlers.on_disconnected) {
            server->handlers.on_disconnected(as_session(s), server->user);
        }
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        LOG_E("session %d: recv failed: %s", s->fd, strerror(errno));
        s->alive = false;
        if (server->handlers.on_disconnected) {
            server->handlers.on_disconnected(as_session(s), server->user);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Server                                                             */
/* ------------------------------------------------------------------ */

RyuLdnServer *ryuldn_server_create(const char *bind_addr, uint16_t port,
                                    const RyuLdnHandlers *handlers, void *user)
{
    RyuLdnServer *server = calloc(1, sizeof(*server));
    if (!server) {
        return NULL;
    }

    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server->fd < 0) {
        LOG_E("socket: %s", strerror(errno));
        free(server);
        return NULL;
    }
    int one = 1;
    setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (!bind_addr || inet_pton(AF_INET, bind_addr ? bind_addr : "0.0.0.0",
                                &addr.sin_addr) != 1) {
        LOG_E("invalid bind address '%s'", bind_addr ? bind_addr : "0.0.0.0");
        close(server->fd);
        free(server);
        return NULL;
    }

    if (bind(server->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_E("bind(%s:%u): %s", bind_addr, port, strerror(errno));
        close(server->fd);
        free(server);
        return NULL;
    }
    if (listen(server->fd, 8) < 0) {
        LOG_E("listen: %s", strerror(errno));
        close(server->fd);
        free(server);
        return NULL;
    }
    set_nonblock(server->fd);

    strncpy(server->bind_addr, bind_addr ? bind_addr : "0.0.0.0",
            sizeof(server->bind_addr) - 1);
    server->port = port;
    server->handlers = *handlers;
    server->user = user;

    LOG_I("RyuLdn server listening on %s:%u", server->bind_addr, port);
    return server;
}

void ryuldn_server_destroy(RyuLdnServer *server)
{
    if (!server) {
        return;
    }
    RyuSessionImpl *s = server->sessions;
    while (s) {
        RyuSessionImpl *next = s->next;
        close(s->fd);
        free(s);
        s = next;
    }
    close(server->fd);
    free(server);
}

void ryuldn_server_poll(RyuLdnServer *server, int timeout_ms)
{
    struct pollfd fds[32];
    RyuSessionImpl *sess[32];
    size_t n = 0;

    fds[n].fd = server->fd;
    fds[n].events = POLLIN;
    sess[n] = NULL;
    n++;

    for (RyuSessionImpl *s = server->sessions; s && n < 32; s = s->next) {
        fds[n].fd = s->fd;
        fds[n].events = POLLIN;
        sess[n] = s;
        n++;
    }

    int rc = poll(fds, (nfds_t)n, timeout_ms);
    if (rc < 0) {
        if (errno == EINTR) {
            return;
        }
        LOG_E("poll: %s", strerror(errno));
        return;
    }
    if (rc == 0) {
        return;
    }

    if (fds[0].revents & POLLIN) {
        struct sockaddr_in peer;
        socklen_t peerlen = sizeof(peer);
        int fd = accept(server->fd, (struct sockaddr *)&peer, &peerlen);
        if (fd >= 0) {
            set_nonblock(fd);
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

            RyuSessionImpl *s = calloc(1, sizeof(*s));
            if (!s) {
                close(fd);
            } else {
                s->fd = fd;
                s->alive = true;
                /* ProxyConfig is sent later, from the CreateAccessPoint path,
                 * which is also what assigns the subnet. */
                s->next = server->sessions;
                server->sessions = s;
                LOG_I("session %d: accepted from %s", fd, inet_ntoa(peer.sin_addr));
            }
        }
    }

    for (size_t i = 1; i < n; i++) {
        if (sess[i] && (fds[i].revents & (POLLIN | POLLHUP | POLLERR))) {
            session_readable(server, sess[i]);
        }
    }

    /* reap dead sessions */
    RyuSessionImpl **pp = &server->sessions;
    while (*pp) {
        if (!(*pp)->alive) {
            RyuSessionImpl *dead = *pp;
            *pp = dead->next;
            close(dead->fd);
            free(dead);
        } else {
            pp = &(*pp)->next;
        }
    }
}

