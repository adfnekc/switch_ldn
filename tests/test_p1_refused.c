/*
 * Integration test: the plugin only implements the LDN *host* role, and must
 * loudly refuse a guest that asks to JOIN a network (p1).
 *
 * This exercises ryuldn.c's Connect dispatch on a real socket, with no radio
 * involved. The contract under test:
 *
 *   1. a Connect packet is answered with exactly one NetworkError frame whose
 *      error code is 202 (ConnectionRejected) - never a silent accept;
 *   2. nothing else (no Initialize/Connected/success frame) is sent before or
 *      after that refusal;
 *   3. a guest that already completed the handshake still gets 202 for its
 *      Connect, and its session stays alive afterwards (Ping is still echoed);
 *   4. truncated or malformed frames neither crash the server nor wedge it for
 *      the next (well-formed) packet.
 *
 * All frames are then decoded field by field (magic, version, type, data_size,
 * payload) exactly the way tests/test_handshake.c does it.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ryuldn.h"
#include "common.h"

/* RyuLdn NetworkError codes - see src/ryuldn.c / Ryubing LdnServer. */
#define RYULDN_ERR_NONE 0u
#define CONNECTION_REJECTED 202u

/* ------------------------------------------------------------------------- */
/* Client-side wire helpers (same style as tests/test_handshake.c)           */
/* ------------------------------------------------------------------------- */

static int connect_client(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_pkt(int fd, uint8_t type, const void *payload, uint32_t len)
{
    uint8_t h[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)h, type, (int32_t)len);
    if (send(fd, h, sizeof(h), MSG_NOSIGNAL) != (ssize_t)sizeof(h)) return -1;
    if (len == 0) return 0;
    return send(fd, payload, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

/* Raw bytes, for building truncated/bogus frames on purpose. */
static int send_raw(int fd, const void *buf, size_t len)
{
    return send(fd, buf, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

/*
 * Read one complete frame (header + declared payload) into `out`, which is
 * left holding the frame verbatim: out[0..3] = magic, out[4] = type,
 * out[5] = version, out[8..11] = data_size, out[12..] = payload.
 * Returns 0 on success, -1 on timeout/EOF/decode error.
 */
static int recv_frame(int fd, RyuLdnServer *server, uint8_t *out, size_t out_sz,
                      uint8_t *type, uint32_t *len)
{
    size_t have = 0;
    for (int i = 0; i < 4000; i++) {
        if (have + 1 > out_sz) {
            fprintf(stderr, "reply frame too large for the test buffer (>%zu)\n", out_sz);
            return -1;
        }
        ssize_t n = recv(fd, out + have, out_sz - have, MSG_DONTWAIT);
        if (n > 0) {
            have += (size_t)n;
            if (have >= RYULDN_HEADER_SIZE) {
                uint32_t dlen = rd_le32(out + 8);
                if (have >= (size_t)RYULDN_HEADER_SIZE + dlen) {
                    if (rd_le32(out) != RYULDN_MAGIC || out[5] != RYULDN_VERSION) {
                        fprintf(stderr,
                                "reply frame has bad magic/version "
                                "(magic=%02x%02x%02x%02x version=%u)\n",
                                out[0], out[1], out[2], out[3], out[5]);
                        return -1;
                    }
                    *type = out[4];
                    *len = dlen;
                    return 0;
                }
            }
            continue;
        }
        if (n == 0) {
            fprintf(stderr, "peer closed before a complete frame arrived\n");
            return -1;
        }
        ryuldn_server_poll(server, 0);
        usleep(2 * 1000);
    }
    fprintf(stderr, "timeout waiting for a reply frame\n");
    return -1;
}

/*
 * Assert the peer sends *nothing* for `ms` milliseconds (rounding the server
 * too). Returns 0 = silent, -1 = unexpected bytes arrived, -2 = peer closed.
 */
static int expect_silence(int fd, RyuLdnServer *server, int ms)
{
    uint8_t junk[512];
    for (int i = 0; i < ms / 10; i++) {
        ssize_t n = recv(fd, junk, sizeof(junk), MSG_DONTWAIT);
        if (n > 0) {
            fprintf(stderr, "server sent %zd unexpected extra byte(s)\n", n);
            return -1;
        }
        if (n == 0) return -2;
        ryuldn_server_poll(server, 0);
        usleep(10 * 1000);
    }
    return 0;
}

/* A ConnectRequest (0x500 bytes) as Ryubing would send it. */
static void build_connect_request(uint8_t *payload)
{
    memset(payload, 0, 0x500);
    uint8_t *sc = payload; /* SecurityConfig at 0x00 */
    wr_le16(sc, 1);        /* security_mode = Product */
    wr_le16(sc + 2, 16);   /* passphrase_size */
    memcpy(sc + 4, "0123456789abcdef", 16);
    memcpy(payload + 0x44, "Joiner", 7); /* UserConfig */
}

/* Full guest handshake: Passphrase + Initialize, then read the reply. */
static int handshake(int fd, RyuLdnServer *server, uint8_t *frame)
{
    uint8_t phrase[128] = {0};
    if (send_pkt(fd, RYULDN_PASSPHRASE, phrase, sizeof(phrase)) != 0) return -1;

    uint8_t init_req[22] = {0}; /* all-zero id/MAC = first contact */
    if (send_pkt(fd, RYULDN_INITIALIZE, init_req, sizeof(init_req)) != 0) return -1;

    uint8_t type;
    uint32_t len;
    if (recv_frame(fd, server, frame, 2048, &type, &len) != 0) return -1;
    if (type != RYULDN_INITIALIZE || len != 22) {
        fprintf(stderr, "handshake: expected Initialize(22), got type %u len %u\n",
                type, len);
        return -1;
    }
    return 0;
}

/* Send a Ping and insist it is echoed back with requester = 0. */
static int expect_ping_echo(int fd, RyuLdnServer *server, uint8_t id)
{
    uint8_t ping_req[2] = {1, id}; /* requester, id */
    uint8_t frame[2048], type;
    uint32_t len;

    if (send_pkt(fd, RYULDN_PING, ping_req, sizeof(ping_req)) != 0) {
        fprintf(stderr, "Ping send failed\n");
        return -1;
    }
    if (recv_frame(fd, server, frame, sizeof(frame), &type, &len) != 0) {
        fprintf(stderr, "no reply to Ping(%u)\n", id);
        return -1;
    }
    if (type != RYULDN_PING || len != 2) {
        fprintf(stderr, "Ping(%u): expected Ping(2), got type %u len %u\n", id, type,
                len);
        return -1;
    }
    if (frame[RYULDN_HEADER_SIZE] != 0 || frame[RYULDN_HEADER_SIZE + 1] != id) {
        fprintf(stderr, "Ping(%u): bad reply {%u,%u}\n", id, frame[RYULDN_HEADER_SIZE],
                frame[RYULDN_HEADER_SIZE + 1]);
        return -1;
    }
    printf("    Ping(%u) echoed -> session still usable\n", id);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Case 1: a bare Connect (p1) must be refused with error 202, nothing else  */
/* ------------------------------------------------------------------------- */

static int case_bare_connect_refused(uint16_t port)
{
    RyuLdnHandlers h;
    memset(&h, 0, sizeof(h));

    RyuLdnServer *server = ryuldn_server_create("127.0.0.1", port, &h, NULL);
    if (!server) {
        fprintf(stderr, "server create failed\n");
        return 1;
    }

    int fd = connect_client(port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        ryuldn_server_destroy(server);
        return 1;
    }

    uint8_t payload[0x500];
    build_connect_request(payload);

    uint8_t header[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)header, RYULDN_CONNECT, (int32_t)sizeof(payload));
    send(fd, header, sizeof(header), MSG_NOSIGNAL);
    send(fd, payload, sizeof(payload), MSG_NOSIGNAL);

    uint8_t frame[2048], type;
    uint32_t len;
    if (recv_frame(fd, server, frame, sizeof(frame), &type, &len) != 0) {
        fprintf(stderr, "no response: the Connect packet was swallowed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    /* The very first thing the server says about this Connect must be the
     * refusal - never an Initialize/Connected "you are in" answer. */
    if (type != RYULDN_NETWORK_ERROR) {
        fprintf(stderr, "unexpected packet type %u (want NetworkError)\n", type);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    if (len != 4) {
        fprintf(stderr, "NetworkError payload must be 4 bytes, got %u\n", len);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    uint32_t code = rd_le32(frame + RYULDN_HEADER_SIZE);
    if (code != CONNECTION_REJECTED) {
        fprintf(stderr, "Connect refused with %u, want %u (ConnectionRejected)\n",
                code, CONNECTION_REJECTED);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    printf("    Connect -> NetworkError(%u) [type=%u len=%u]\n", code, type, len);

    /* Requirement: read exactly one reply - nothing else may follow. */
    int quiet = expect_silence(fd, server, 150);
    if (quiet == -1) {
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    if (quiet == -2) {
        printf("    note: server closed the refused session afterwards\n");
    } else {
        printf("    no second frame (no accept/success) followed the refusal\n");
    }

    close(fd);
    ryuldn_server_destroy(server);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Case 2: handshake first, then Connect - still refused, session survives   */
/* ------------------------------------------------------------------------- */

static int case_connect_after_handshake(uint16_t port)
{
    RyuLdnHandlers h;
    memset(&h, 0, sizeof(h));

    RyuLdnServer *server = ryuldn_server_create("127.0.0.1", port, &h, NULL);
    if (!server) {
        fprintf(stderr, "server create failed\n");
        return 1;
    }

    int fd = connect_client(port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        ryuldn_server_destroy(server);
        return 1;
    }

    uint8_t frame[2048];
    if (handshake(fd, server, frame) != 0) {
        fprintf(stderr, "handshake failed before the Connect attempt\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    printf("    handshake done (session id + MAC assigned)\n");

    /* The earlier handshake must not make a Connect preferential in any way. */
    uint8_t payload[0x500];
    build_connect_request(payload);
    if (send_pkt(fd, RYULDN_CONNECT, payload, sizeof(payload)) != 0) {
        fprintf(stderr, "Connect send failed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    uint8_t type;
    uint32_t len;
    if (recv_frame(fd, server, frame, sizeof(frame), &type, &len) != 0) {
        fprintf(stderr, "Connect after a handshake was not answered\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    if (type != RYULDN_NETWORK_ERROR) {
        fprintf(stderr, "Connect after handshake: type %u, want NetworkError\n", type);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    uint32_t code = rd_le32(frame + RYULDN_HEADER_SIZE);
    if (len != 4 || code != CONNECTION_REJECTED) {
        fprintf(stderr, "Connect after handshake: NetworkError(%u) len %u, want 202 len 4\n",
                code, len);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    printf("    Connect -> NetworkError(%u) (handshake does not grant a JOIN)\n", code);

    if (expect_silence(fd, server, 150) != 0) {
        fprintf(stderr, "extra frame(s) around the refusal after a handshake\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    /* The refusal must not tear the session down: Ping is still answered. */
    int alive = 0;
    for (int attempt = 0; attempt < 3 && !alive; attempt++) {
        alive = expect_ping_echo(fd, server, 0x7e) == 0;
    }
    if (!alive) {
        fprintf(stderr, "session was killed by the refusal (Ping unanswered)\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    close(fd);
    ryuldn_server_destroy(server);
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Case 3: truncated / malformed frames must not crash or wedge the server   */
/* ------------------------------------------------------------------------- */

/* Wait for the server to close the connection (it drops bad-magic sessions). */
static int wait_peer_closed(int fd, RyuLdnServer *server, int ms)
{
    uint8_t junk[256];
    for (int i = 0; i < ms / 10; i++) {
        ssize_t n = recv(fd, junk, sizeof(junk), MSG_DONTWAIT);
        if (n == 0) return 0;
        if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            return 0; /* ECONNRESET counts as "closed by the server" */
        }
        ryuldn_server_poll(server, 0);
        usleep(10 * 1000);
    }
    return -1;
}

static int case_truncated_and_garbage(uint16_t port)
{
    RyuLdnHandlers h;
    memset(&h, 0, sizeof(h));

    RyuLdnServer *server = ryuldn_server_create("127.0.0.1", port, &h, NULL);
    if (!server) {
        fprintf(stderr, "server create failed\n");
        return 1;
    }

    /* (a) A truncated frame is just "not finished yet" on a TCP stream: the
     *     server must buffer it, answer nothing, and then serve the client
     *     normally once the rest of the frame shows up. */
    int fd = connect_client(port);
    if (fd < 0) {
        fprintf(stderr, "connect failed\n");
        ryuldn_server_destroy(server);
        return 1;
    }
    uint8_t frame[2048];
    if (handshake(fd, server, frame) != 0) {
        fprintf(stderr, "handshake failed before the garbage test\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    uint8_t hdr[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)hdr, RYULDN_PING, 2); /* 2-byte payload */

    send_raw(fd, hdr, 7); /* cut the header short: no data_size delivered yet */
    int quiet = expect_silence(fd, server, 100);
    if (quiet != 0) {
        fprintf(stderr, "truncated header: server answered (%d) or closed (%d)\n",
                quiet, quiet);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    send_raw(fd, hdr + 7, 5); /* rest of the header, still no payload */
    if (expect_silence(fd, server, 100) != 0) {
        fprintf(stderr, "incomplete frame: server answered early or closed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    uint8_t ping[2] = {1, 0x5a}; /* now finish the Ping */
    send_raw(fd, ping, sizeof(ping));
    if (expect_ping_echo(fd, server, 0x5a) != 0) {
        fprintf(stderr, "completed frame was not served after buffering\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    printf("    truncated Ping: buffered, then answered in order\n");

    /* (b) Garbage with a broken magic: that session is dropped by design, but
     *     the server must survive and keep serving fresh guests. */
    int junk_fd = connect_client(port);
    if (junk_fd < 0) {
        fprintf(stderr, "reconnect failed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    uint8_t junk[20];
    memset(junk, 'X', sizeof(junk));
    send_raw(junk_fd, junk, sizeof(junk));
    if (wait_peer_closed(junk_fd, server, 1000) != 0) {
        fprintf(stderr, "bad-magic session was not dropped\n");
        close(junk_fd);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    close(junk_fd);
    printf("    bad magic: session dropped, server still running\n");

    /* (c) A frame declaring an absurd payload length: no crash, no desync. */
    int liar_fd = connect_client(port);
    if (liar_fd < 0) {
        fprintf(stderr, "reconnect failed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    uint8_t big[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)big, RYULDN_PING, (int32_t)0x40000000);
    send_raw(liar_fd, big, sizeof(big));
    if (expect_silence(liar_fd, server, 100) != 0) {
        fprintf(stderr, "server replied to (or blocked on) a bogus frame length\n");
        close(liar_fd);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    close(liar_fd);
    printf("    bogus data_size: buffered harmlessly\n");

    /* (d) A brand new guest still gets a full session - the wedge check. */
    int fresh_fd = connect_client(port);
    if (fresh_fd < 0) {
        fprintf(stderr, "reconnect failed\n");
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    if (handshake(fresh_fd, server, frame) != 0) {
        fprintf(stderr, "server wedged after garbage: new guest cannot handshake\n");
        close(fresh_fd);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    if (expect_ping_echo(fresh_fd, server, 0x33) != 0) {
        close(fresh_fd);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }
    printf("    fresh guest after the garbage: full session works\n");

    /* The original guest must still be alive too. */
    if (expect_ping_echo(fd, server, 0x11) != 0) {
        fprintf(stderr, "first guest was dropped after the garbage\n");
        close(fresh_fd);
        close(fd);
        ryuldn_server_destroy(server);
        return 1;
    }

    close(fresh_fd);
    close(fd);
    ryuldn_server_destroy(server);
    return 0;
}

/* ------------------------------------------------------------------------- */

int main(void)
{
    static const struct {
        const char *name;
        int (*fn)(uint16_t port);
        uint16_t port;
    } cases[] = {
        {"bare Connect (p1) is refused with ConnectionRejected",
         case_bare_connect_refused, 47911},
        {"handshake then Connect is still refused, session stays usable",
         case_connect_after_handshake, 47921},
        {"truncated/garbage frames do not crash or wedge the server",
         case_truncated_and_garbage, 47922},
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        printf("[%zu/%zu] %s\n", i + 1, sizeof(cases) / sizeof(cases[0]), cases[i].name);
        if (cases[i].fn(cases[i].port) != 0) {
            fprintf(stderr, "FAILED: %s\n", cases[i].name);
            failures++;
        }
    }

    if (failures) {
        fprintf(stderr, "%d p1 refusal case(s) failed\n", failures);
        return 1;
    }
    printf("all p1 refusal tests passed\n");
    return 0;
}
