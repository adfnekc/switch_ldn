/*
 * mgmt_tx_probe - can this driver inject a management frame from userspace on
 * an ordinary interface, without a monitor VIF?
 *
 * The bridge currently injects the LDN advertisement by writing a raw 802.11
 * frame to an AF_PACKET socket on a monitor interface. That needs a second VIF,
 * and on the RTL8812AU vendor driver creating one wedges the kernel. The
 * driver does implement cfg80211's .mgmt_tx, so if this works the advertisement
 * can go out on the AP interface itself and the second VIF disappears from the
 * design.
 *
 * Measured on Debian 13, kernel 6.12, RTL8812AU on the aircrack-ng v5.13.6
 * driver, with hostapd holding the interface in AP mode on channel 1:
 *
 *   $ ./mgmt_tx_probe wlx54c9ff02cd3b
 *   sending 37-byte action frame on wlx54c9ff02cd3b (ifindex 4)
 *   command accepted (ACK)
 *   $ dmesg | tail -2
 *   RTW: RTW_Tx:tx_ch=1, no_cck=0, da=ff:ff:ff:ff:ff:ff
 *   RTW: RTW_Tx:OUI_Subtype=222, dialogToken=173
 *
 * Two things make the difference between -EINVAL and success:
 *   - AP mode. In managed mode and unassociated the kernel answers -ENOTCONN.
 *   - the full channel descriptor. NL80211_ATTR_WIPHY_FREQ alone makes
 *     cfg80211 fail to parse the chandef (-EINVAL); without it the driver
 *     itself returns -EINVAL because params->chan is NULL.
 *
 * Build: apt install libnl-3-dev libnl-genl-3-dev
 *        gcc -O2 -o mgmt_tx_probe mgmt_tx_probe.c \
 *            -I/usr/include/libnl3 -lnl-3 -lnl-genl-3
 * Usage: ./mgmt_tx_probe <ifname>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>

/* A vendor-specific action frame, the shape the LDN advertisement uses. */
static const unsigned char kFrame[] = {
    0xd0, 0x00,             /* action, no flags */
    0x00, 0x00,             /* duration */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* addr1 = broadcast */
    0x54, 0xc9, 0xff, 0x02, 0xcd, 0x3b,  /* addr2 = our MAC (informational) */
    0x54, 0xc9, 0xff, 0x02, 0xcd, 0x3b,  /* addr3 */
    0x00, 0x00,             /* seq */
    0x7f,                   /* category: vendor specific */
    0x00, 0x22, 0xaa,       /* OUI */
    0x00,                   /* OUI type */
    0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04,  /* filler payload */
};

static int ack_seen;

/* libnl routes NLMSG_ERROR here; without this an -EOPNOTSUPP or -EINVAL from
 * the kernel is silently dropped and the test just looks like "no reply". */
static int on_error(struct sockaddr_nl *addr, struct nlmsgerr *err, void *arg)
{
    (void)addr; (void)arg;
    printf("kernel error: %s (%d)\n", strerror(-err->error), err->error);
    ack_seen = 2;
    return NL_STOP;
}

static int on_ack(struct nl_msg *msg, void *arg)
{
    (void)msg; (void)arg;
    printf("command accepted (ACK)\n");
    return NL_OK;
}

static int on_msg(struct nl_msg *msg, void *arg)
{
    (void)arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnl = nlmsg_data(nlh);
    if (gnl->cmd == NL80211_CMD_FRAME_TX_STATUS) {
        struct nlattr *tb[NL80211_ATTR_MAX + 1];
        nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnl, 0),
                  genlmsg_attrlen(gnl, 0), NULL);
        if (tb[NL80211_ATTR_ACK]) {
            printf("ACK received - the frame went out\n");
            ack_seen = 1;
        } else {
            printf("tx status without ACK (sent, but nobody acked)\n");
            ack_seen = 1;
        }
    }
    return NL_OK;
}

int main(int argc, char **argv)
{
    const char *ifname = argc > 1 ? argv[1] : "wlan0";
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "no such interface: %s\n", ifname);
        return 1;
    }

    struct nl_sock *sock = nl_socket_alloc();
    if (!sock) { fprintf(stderr, "nl_socket_alloc failed\n"); return 1; }
    nl_socket_disable_seq_check(sock);
    if (nl_connect(sock, NETLINK_GENERIC) < 0) {
        fprintf(stderr, "nl_connect failed\n");
        return 1;
    }
    int fam = genl_ctrl_resolve(sock, "nl80211");
    if (fam < 0) { fprintf(stderr, "cannot resolve nl80211\n"); return 1; }
    nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, on_msg, NULL);
    nl_socket_modify_err_cb(sock, NL_CB_CUSTOM, on_error, NULL);
    nl_socket_modify_cb(sock, NL_CB_ACK, NL_CB_CUSTOM, on_ack, NULL);

    struct nl_msg *m = nlmsg_alloc();
    if (!m) { fprintf(stderr, "nlmsg_alloc failed\n"); return 1; }

    genlmsg_put(m, 0, 0, fam, 0, 0, NL80211_CMD_FRAME, 0);
    NLA_PUT_U32(m, NL80211_ATTR_IFINDEX, (uint32_t)ifindex);
    /*
     * The channel has to be spelled out in full. The driver rejects the command
     * with -EINVAL when params->chan is NULL (ioctl_cfg80211.c: "if (chan ==
     * NULL)"), and cfg80211 only fills that in from NL80211_ATTR_WIPHY_FREQ -
     * which in turn it refuses to parse without a channel width and the centre
     * frequency. Hence all three.
     */
    NLA_PUT_U32(m, NL80211_ATTR_WIPHY_FREQ, 2412);                    /* ch 1 */
    NLA_PUT_U32(m, NL80211_ATTR_CHANNEL_WIDTH, NL80211_CHAN_WIDTH_20_NOHT);
    NLA_PUT_U32(m, NL80211_ATTR_CENTER_FREQ1, 2412);
    NLA_PUT(m, NL80211_ATTR_FRAME, sizeof(kFrame), kFrame);

    printf("sending %zu-byte action frame on %s (ifindex %d)\n",
           sizeof(kFrame), ifname, ifindex);
    if (nl_send_auto(sock, m) < 0) {
        fprintf(stderr, "nl_send_auto failed\n");
        return 1;
    }
    nlmsg_free(m);

    for (int i = 0; i < 30 && !ack_seen; i++) {
        int rc = nl_recvmsgs_default(sock);
        if (rc < 0) {
            fprintf(stderr, "nl_recvmsgs: %s\n", nl_geterror(rc));
            break;
        }
        usleep(100 * 1000);
    }

    nl_socket_free(sock);
    if (!ack_seen) {
        printf("NO tx status within 3s\n");
        return 2;
    }
    return 0;

nla_put_failure:
    fprintf(stderr, "failed to build the netlink message (frame too large?)\n");
    return 1;
}
