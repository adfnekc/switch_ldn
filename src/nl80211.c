#include "nl80211.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/socket.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <poll.h>

#include "common.h"

struct Nl80211 {
    struct nl_sock *sock;
    int family;
    int ifindex;
    /* Result of the last command, filled in by the ACK/error callbacks. */
    int tx_result;
    bool tx_done;
};

/* ------------------------------------------------------------------ */
/* Netlink plumbing                                                    */
/* ------------------------------------------------------------------ */

static int on_error(struct sockaddr_nl *addr, struct nlmsgerr *err, void *arg)
{
    (void)addr;
    Nl80211 *nl = arg;
    nl->tx_result = err->error;
    nl->tx_done = true;
    return NL_STOP;
}

static int on_ack(struct nl_msg *msg, void *arg)
{
    (void)msg;
    Nl80211 *nl = arg;
    nl->tx_result = 0;
    nl->tx_done = true;
    return NL_STOP;
}

/* A received NL80211_CMD_FRAME: hand the 802.11 frame to the drain callback. */
typedef struct {
    void (*cb)(const uint8_t *, size_t, void *);
    void *user;
    int count;
} DrainCtx;

static int on_frame_msg(struct nl_msg *msg, void *arg)
{
    DrainCtx *ctx = arg;
    struct nlmsghdr *nlh = nlmsg_hdr(msg);
    struct genlmsghdr *gnl = nlmsg_data(nlh);

    if (gnl->cmd != NL80211_CMD_FRAME) {
        return NL_OK;
    }
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    if (nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnl, 0),
                  genlmsg_attrlen(gnl, 0), NULL) < 0) {
        return NL_OK;
    }
    if (tb[NL80211_ATTR_FRAME] && ctx->cb) {
        const uint8_t *frame = nla_data(tb[NL80211_ATTR_FRAME]);
        size_t len = (size_t)nla_len(tb[NL80211_ATTR_FRAME]);
        ctx->cb(frame, len, ctx->user);
        ctx->count++;
    }
    return NL_OK;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

Nl80211 *nl80211_open(const char *ifname)
{
    if (!ifname || !*ifname) {
        LOG_E("nl80211: no interface name given");
        return NULL;
    }
    int ifindex = (int)if_nametoindex(ifname);
    if (!ifindex) {
        LOG_E("nl80211: no such interface '%s'", ifname);
        return NULL;
    }

    Nl80211 *nl = calloc(1, sizeof(*nl));
    if (!nl) {
        return NULL;
    }
    nl->ifindex = ifindex;

    nl->sock = nl_socket_alloc();
    if (!nl->sock) {
        LOG_E("nl80211: nl_socket_alloc failed");
        free(nl);
        return NULL;
    }
    nl_socket_disable_seq_check(nl->sock);
    /*
     * Non-blocking, so draining received frames can stop at "nothing left"
     * instead of sleeping inside nl_recvmsgs.
     */
    nl_socket_set_nonblocking(nl->sock);
    nl_socket_modify_err_cb(nl->sock, NL_CB_CUSTOM, on_error, nl);
    nl_socket_modify_cb(nl->sock, NL_CB_ACK, NL_CB_CUSTOM, on_ack, nl);

    if (nl_connect(nl->sock, NETLINK_GENERIC) < 0) {
        LOG_E("nl80211: cannot open a generic netlink socket");
        nl_socket_free(nl->sock);
        free(nl);
        return NULL;
    }
    nl->family = genl_ctrl_resolve(nl->sock, "nl80211");
    if (nl->family < 0) {
        LOG_E("nl80211: the kernel has no nl80211 family");
        nl_socket_free(nl->sock);
        free(nl);
        return NULL;
    }

    LOG_I("nl80211: management frames enabled on %s (ifindex %d)", ifname, ifindex);
    return nl;
}

void nl80211_close(Nl80211 *nl)
{
    if (!nl) {
        return;
    }
    if (nl->sock) {
        nl_socket_free(nl->sock);
    }
    free(nl);
}

int nl80211_fd(const Nl80211 *nl)
{
    return nl && nl->sock ? nl_socket_get_fd(nl->sock) : -1;
}

/* Send one command and wait for its ACK or error. */
static int transact(Nl80211 *nl, struct nl_msg *msg)
{
    nl->tx_result = -EIO;
    nl->tx_done = false;

    if (nl_send_auto(nl->sock, msg) < 0) {
        nlmsg_free(msg);
        return -EIO;
    }
    nlmsg_free(msg);

    /*
     * Wait for the ACK. NL80211_CMD_FRAME also produces a
     * NL80211_CMD_FRAME_TX_STATUS later, but a broadcast frame is never
     * acknowledged over the air, so that event may not come at all - blocking
     * on it would hang the bridge.
     */
    /* Bounded wait for the ACK; see the comment above about tx status. */
    for (int i = 0; i < 50 && !nl->tx_done; i++) {
        struct pollfd pfd = {.fd = nl_socket_get_fd(nl->sock), .events = POLLIN};
        int prc = poll(&pfd, 1, 10);
        if (prc <= 0) {
            continue;
        }
        int rc = nl_recvmsgs_default(nl->sock);
        if (rc == -NLE_AGAIN) {
            continue;
        }
        if (rc < 0 && !nl->tx_done) {
            return rc;
        }
    }
    if (!nl->tx_done) {
        return -ETIMEDOUT;
    }
    return nl->tx_result;
}

int nl80211_mgmt_tx(Nl80211 *nl, const void *frame, size_t len, uint32_t mhz,
                    uint32_t chan_width, uint32_t center1)
{
    if (!nl || !frame || len < 24) {
        return -EINVAL;
    }

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        return -ENOMEM;
    }
    genlmsg_put(msg, 0, 0, nl->family, 0, 0, NL80211_CMD_FRAME, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, (uint32_t)nl->ifindex);
    /* All three: a bare frequency is not a parseable chandef. */
    NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, mhz);
    NLA_PUT_U32(msg, NL80211_ATTR_CHANNEL_WIDTH, chan_width);
    NLA_PUT_U32(msg, NL80211_ATTR_CENTER_FREQ1, center1);
    NLA_PUT(msg, NL80211_ATTR_FRAME, len, frame);

    int rc = transact(nl, msg);
    if (rc != 0) {
        LOG_W("nl80211: mgmt_tx rejected: %s (-%d)", strerror(-rc), -rc);
        return rc;
    }
    return 0;

nla_put_failure:
    nlmsg_free(msg);
    LOG_E("nl80211: frame too large to encode");
    return -EMSGSIZE;
}

int nl80211_register_action(Nl80211 *nl, const uint8_t oui[3], uint8_t oui_type)
{
    if (!nl || !oui) {
        return -EINVAL;
    }

    /*
     * A vendor-specific action frame: type/subtype 0x00D0, then a 4-byte match
     * of {OUI, OUI type}. Registering once is enough; the kernel keeps sending
     * every matching frame to this socket.
     */
    uint8_t match[4] = {oui[0], oui[1], oui[2], oui_type};

    struct nl_msg *msg = nlmsg_alloc();
    if (!msg) {
        return -ENOMEM;
    }
    genlmsg_put(msg, 0, 0, nl->family, 0, 0, NL80211_CMD_REGISTER_FRAME, 0);
    NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, (uint32_t)nl->ifindex);
    NLA_PUT_U16(msg, NL80211_ATTR_FRAME_TYPE, 0x00D0);
    NLA_PUT(msg, NL80211_ATTR_FRAME_MATCH, sizeof(match), match);

    int rc = transact(nl, msg);
    if (rc != 0) {
        LOG_W("nl80211: register action frame %02x:%02x:%02x/%u rejected: %s",
              oui[0], oui[1], oui[2], oui_type, strerror(-rc));
        return rc;
    }
    LOG_I("nl80211: subscribed to action frames %02x:%02x:%02x/%u", oui[0], oui[1],
          oui[2], oui_type);
    return 0;

nla_put_failure:
    nlmsg_free(msg);
    return -EMSGSIZE;
}

int nl80211_drain(Nl80211 *nl,
                  void (*cb)(const uint8_t *frame, size_t len, void *user),
                  void *user)
{
    if (!nl || !cb) {
        return 0;
    }
    DrainCtx ctx = {.cb = cb, .user = user, .count = 0};

    struct nl_cb *saved = nl_socket_get_cb(nl->sock);
    (void)saved;
    /* Swap in a VALID handler for the duration of the drain. */
    nl_socket_modify_cb(nl->sock, NL_CB_VALID, NL_CB_CUSTOM, on_frame_msg, &ctx);

    for (int i = 0; i < 64; i++) {
        int rc = nl_recvmsgs_default(nl->sock);
        if (rc == -NLE_AGAIN) {
            break; /* nothing left */
        }
        if (rc < 0) {
            break;
        }
    }
    return ctx.count;
}
