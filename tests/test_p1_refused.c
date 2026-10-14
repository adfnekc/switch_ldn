/*
 * Integration test: the plugin only implements the LDN *host* role, and must
 * loudly refuse a guest that asks to JOIN a network (p1).
 *
 * This exercises ryuldn.c's Connect dispatch on a real socket, with no radio
 * involved.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "ryuldn.h"
#include "common.h"

static const uint16_t PORT = 47911;

int main(void)
{
    RyuLdnHandlers h;
    memset(&h, 0, sizeof(h));

    RyuLdnServer *server = ryuldn_server_create("127.0.0.1", PORT, &h, NULL);
    if (!server) {
        fprintf(stderr, "server create failed\\n");
        return 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "connect failed\\n");
        return 1;
    }

    /* A ConnectRequest (0x500 bytes) as Ryubing would send it. */
    uint8_t payload[0x500];
    memset(payload, 0, sizeof(payload));
    uint8_t *sc = payload;                    /* SecurityConfig at 0x00 */
    wr_le16(sc, 1);                           /* security_mode = Product */
    wr_le16(sc + 2, 16);                      /* passphrase_size */
    memcpy(sc + 4, "0123456789abcdef", 16);
    memcpy(payload + 0x44, "Joiner", 7);      /* UserConfig */

    uint8_t header[RYULDN_HEADER_SIZE];
    ryuldn_header_init((RyuLdnHeader *)header, RYULDN_CONNECT, (int32_t)sizeof(payload));
    wr_le16(header + 6, 0);

    send(fd, header, sizeof(header), MSG_NOSIGNAL);
    send(fd, payload, sizeof(payload), MSG_NOSIGNAL);

    for (int i = 0; i < 50; i++) {
        ryuldn_server_poll(server, 0);
        uint8_t buf[64];
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < RYULDN_HEADER_SIZE) {
            usleep(10 * 1000);
            continue;
        }
        if (buf[4] != RYULDN_NETWORK_ERROR) {
            fprintf(stderr, "unexpected packet type %u (want NetworkError)\\n", buf[4]);
            return 1;
        }
        uint32_t code = rd_le32(buf + RYULDN_HEADER_SIZE);
        printf("p1 correctly refused: NetworkError(%u)\n", code);
        close(fd);
        ryuldn_server_destroy(server);
        return code == 202 ? 0 : 1;
    }

    fprintf(stderr, "no response: the Connect packet was swallowed\\n");
    close(fd);
    ryuldn_server_destroy(server);
    return 1;
}
