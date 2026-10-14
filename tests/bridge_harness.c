/*
 * Interop harness: runs the bridge's real transports and real LDN host core
 * with no radio, so a real Ryubing/Eden client can be pointed at it.
 *
 * This does not duplicate any of the bridge's logic - it #includes main.c (with
 * its main renamed away) to reach the statics, then wires up exactly the same
 * objects main() would, skipping only radio_open() and the argument parser.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#define main switch_ldn_original_main
#include "main.c"
#undef main

int main(int argc, char **argv)
{
    const char *bind_addr = "127.0.0.1";
    unsigned port = 30456, room_port = 24872;
    const char *prodkeys_file = "tests/interop/prod.keys";

    if (argc > 1) bind_addr = argv[1];
    if (argc > 2) port = (unsigned)atoi(argv[2]);
    if (argc > 3) room_port = (unsigned)atoi(argv[3]);
    if (argc > 4) prodkeys_file = argv[4];

    g_stop = 0;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    static ProdKeys prodkeys;
    memset(&prodkeys, 0, sizeof(prodkeys));
    if (prodkeys_load(&prodkeys, prodkeys_file) != 0) {
        return 1;
    }

    Bridge bridge;
    memset(&bridge, 0, sizeof(bridge));
    bridge.prodkeys = &prodkeys;
    bridge.channel = 1;
    bridge.band = 0;
    bridge.guest_proxy_ip = htonl(0x0A720001);

    Bridge *b = &bridge;

    b->server = ryuldn_server_create(bind_addr, port, &k_handlers, b);
    if (!b->server) {
        return 1;
    }
    printf("HARNESS: RyuLdn listening on %s:%u\n", bind_addr, port);

    RoomHandlers rh = {
        .on_join = room_on_join,
        .on_leave = room_on_leave,
        .on_packet = room_on_packet,
    };
    bridge.room_server = room_server_create(bind_addr, room_port, &rh, b,
                                           "switch_ldn", "switch_ldn bridge",
                                           "bridge", LDN_NODE_MAX);
    if (!bridge.room_server) {
        return 1;
    }
    printf("HARNESS: Room listening on %s:%u\n", bind_addr, room_port);
    printf("HARNESS: ready\n");
    fflush(stdout);

    while (!g_stop) {
        ryuldn_server_poll(b->server, 0);
        room_server_poll(b->room_server, 0);
        if (b->host) {
            host_tick(b->host, NULL); /* no radio: nothing is transmitted */
            HostEvent ev;
            while (host_poll_event(b->host, &ev)) {
                notify_station_changed(b, &ev);
            }
        }
        usleep(2000);
    }
    printf("HARNESS: stopped\n");
    return 0;
}
