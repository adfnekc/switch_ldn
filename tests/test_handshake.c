/*
 * Integration test: the RyuLdn handshake must match Ryubing/LdnServer, not the
 * (inaccurate) flow diagram in the protocol document.
 *
 *   1. client -> Passphrase
 *   2. client -> Initialize
 *   3. server -> Initialize   <-- with an assigned session id + MAC (mandatory)
 *   4. client -> Ping
 *   5. server -> Ping {requester = 0, id = ping id}
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ryuldn.h"
#include "common.h"

static const uint16_t PORT = 47912;

static int send_pkt(int fd, uint8_t type, const void *payload, uint32_t len)
{
    uint8_t h[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)h, type, (int32_t)len);
    if (send(fd, h, sizeof(h), MSG_NOSIGNAL) != (ssize_t)sizeof(h)) return -1;
    return send(fd, payload, len, MSG_NOSIGNAL) == (ssize_t)len ? 0 : -1;
}

static int recv_pkt(int fd, RyuLdnServer *server, uint8_t *type, uint8_t *payload,
                    uint32_t *len)
{
    for (int i = 0; i < 100; i++) {
        ssize_t n = recv(fd, payload, 2048, MSG_DONTWAIT);
        if (n < RYULDN_HEADER_SIZE) {
            ryuldn_server_poll(server, 0);
            usleep(5 * 1000);
            continue;
        }
        *type = payload[4];
        *len = rd_le32(payload + 8);
        memmove(payload, payload + RYULDN_HEADER_SIZE, (size_t)(*len));
        return 0;
    }
    return -1;
}

int main(void)
{
    RyuLdnHandlers h;
    memset(&h, 0, sizeof(h));

    RyuLdnServer *server = ryuldn_server_create("127.0.0.1", PORT, &h, NULL);
    if (!server) return 1;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) return 1;

    /* 1. Passphrase */
    uint8_t phrase[128] = {0};
    if (send_pkt(fd, RYULDN_PASSPHRASE, phrase, sizeof(phrase)) != 0) return 1;

    /* 2. Initialize with all-zero id and MAC (first contact) */
    uint8_t init_req[22] = {0};
    if (send_pkt(fd, RYULDN_INITIALIZE, init_req, sizeof(init_req)) != 0) return 1;

    /* 3. must get an Initialize back with a session id and a usable MAC */
    uint8_t buf[2048], type;
    uint32_t len;
    if (recv_pkt(fd, server, &type, buf, &len) != 0) {
        fprintf(stderr, "no reply to Initialize\\n");
        return 1;
    }
    if (type != RYULDN_INITIALIZE) {
        fprintf(stderr, "expected Initialize reply, got type %u\\n", type);
        return 1;
    }
    if (len != 22) {
        fprintf(stderr, "Initialize reply must be 22 bytes, got %u\\n", len);
        return 1;
    }

    const uint8_t *id = buf;
    const uint8_t *mac = buf + 16;
    bool any = false;
    for (int i = 0; i < 16; i++) any |= id[i] != 0;
    for (int i = 0; i < 6; i++) any |= mac[i] != 0;
    if (!any) {
        fprintf(stderr, "server assigned an all-zero id/MAC\\n");
        return 1;
    }

    /* the MAC must be locally administered so it never collides with a real
     * Switch's burned-in address */
    if (!(mac[0] & 0x02)) {
        fprintf(stderr, "assigned MAC is not locally administered\\n");
        return 1;
    }
    printf("Initialize reply: mac=%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2],
           mac[3], mac[4], mac[5]);

    /* 4. Ping -> must echo id with requester = 0 */
    uint8_t ping_req[2] = {1, 0x42}; /* requester, id */
    if (send_pkt(fd, RYULDN_PING, ping_req, sizeof(ping_req)) != 0) return 1;
    if (recv_pkt(fd, server, &type, buf, &len) != 0) {
        fprintf(stderr, "no reply to Ping\\n");
        return 1;
    }
    if (type != RYULDN_PING) {
        fprintf(stderr, "expected Ping reply, got type %u\\n", type);
        return 1;
    }
    if (len != 2) {
        fprintf(stderr, "Ping reply must be 2 bytes, got %u\\n", len);
        return 1;
    }
    if (buf[0] != 0 || buf[1] != 0x42) {
        fprintf(stderr, "Ping reply must be {requester=0, id=0x42}, got {%u,%u}\\n",
                buf[0], buf[1]);
        return 1;
    }
    printf("Ping reply: requester=%u id=%u\n", buf[0], buf[1]);

    close(fd);
    ryuldn_server_destroy(server);
    printf("handshake matches Ryubing/LdnServer\n");
    return 0;
}
