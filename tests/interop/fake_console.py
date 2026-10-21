#!/usr/bin/env python3
"""Fake Nintendo Switch console, talking to the bridge over its radio socket.

This is the half of the system `make interop` structurally cannot cover.
`tests/bridge_harness.c` stubs the radio out, so `radio_rx()` never fires and
nothing verifies the console -> bridge direction. This peer drives that
direction for real: it attaches to the bridge's `--radio-socket` and puts on the
wire exactly what a console would.

What it does, in the same order a real console does:

  1. waits for the bridge's 100 ms LDN advertisement action frame,
  2. parses the plaintext session_info out of it and checks the title id,
  3. derives the advertise key itself (prod.keys + session_info) and decrypts
     the payload with AES-CTR, proving the bridge's crypto is right,
  4. sends an 802.11 LDN AuthenticationRequest,
  5. validates the AuthenticationResponse's session_info and status code,
  6. sends Pia game traffic as an 802.11 data frame.

Nothing here reuses the bridge's code: the frame layout is transcribed from
`src/ldn.c` and the AES comes from `openssl`, so a bug in the bridge's encoder
or key derivation shows up as a mismatch here rather than as "the console never
joins" on real hardware.

Usage:
  ./tests/interop/fake_console.py --socket /tmp/ldn.sock [--title-id ...]

The bridge must be running with `--radio-socket /tmp/ldn.sock`.
"""

import argparse
import hashlib
import os
import socket
import struct
import subprocess
import sys
import time

# --- LDN / 802.11 constants, transcribed from src/ldn.{c,h} ----------------

IEEE80211_HDRLEN = 24

LDN_CATEGORY_VENDOR_SPECIFIC = 127
LDN_OUI = (0x00, 0x22, 0xAA)
LDN_PROTOCOL_ID = 4

LDN_VERSION_3 = 3
LDN_AUTH_SUCCESS = 0
LDN_AUTH_MALFORMED_REQUEST = 2
LDN_AUTH_INVALID_VERSION = 4

# Frame body offsets (after the 24-byte 802.11 header), from src/ldn.c.
LDN_BODY = 0
LDN_HDR = 6  # 6-byte vendor-specific header precedes the LDN header

# LdnAuthData offsets, from ldn_parse_auth_frame().
AUTH_OFF_VERSION = 0
AUTH_OFF_PAYLOAD_SIZE = 1
AUTH_OFF_STATUS = 2
AUTH_OFF_IS_RESPONSE = 3
AUTH_OFF_SESSION_INFO = 8
AUTH_OFF_SERVER_RANDOM = 0x28
AUTH_OFF_CLIENT_RANDOM = 0x38
AUTH_OFF_USERNAME = 0x48

LDN_AUTH_REQUEST_PAYLOAD = 0x364

# Advertisement payload offsets, from ldn.c's build_ldn_advertisement().
ADV_SESSION_INFO = 0x00
ADV_NONCE = 0x24
ADV_SHA256 = 0x28
ADV_DATA = 0x48
ADV_OFF_PARTICIPANTS = 0x18      # inside the decrypted advertise data
ADV_NODE_COUNT = 0x17
PARTICIPANT_SIZE = 56

PACKET_ADVERTISEMENT = 257
PACKET_AUTHENTICATION = 258


class Fail(Exception):
    pass


def stage(name, ok, detail=""):
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f" - {detail}" if detail else ""),
          flush=True)
    if not ok:
        raise Fail(name)


# --- crypto, deliberately independent of the bridge ----------------------


def parse_prod_keys(path):
    keys = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or "=" not in line or line.startswith("#"):
                continue
            name, _, value = line.partition("=")
            keys[name.strip()] = bytes.fromhex(value.strip())
    return keys


def aes128_ctr_xor(key, counter16, data):
    """AES-CTR driven through openssl, so the implementation is not ours."""
    return subprocess.run(
        ["openssl", "enc", "-aes-128-ctr", "-K", key.hex(), "-iv", counter16.hex()],
        input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


ADV_INPUT_KEY = bytes.fromhex("191884743e24c77d87c69e4207d0c438")


def aes128_ecb_dec(key: bytes, block: bytes) -> bytes:
    """AES-128 ECB single-block decrypt, through openssl."""
    return subprocess.run(
        ["openssl", "enc", "-aes-128-ecb", "-d", "-K", key.hex(), "-nopad"],
        input=block, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
    ).stdout


def prodkeys_derive_key(keys, input_key: bytes) -> bytes:
    """prodkeys_derive_key() from src/crypto.c: three AES-ECB decrypt stages."""
    kek_gen = aes128_ecb_dec(keys["master_key_00"], keys["aes_kek_generation_source"])
    unwrapped = aes128_ecb_dec(kek_gen, input_key)
    return aes128_ecb_dec(unwrapped, keys["aes_key_generation_source"])


def derive_advertise_key(keys, session_info: bytes) -> bytes:
    """ldn_adv_key() from src/crypto.c."""
    derived = prodkeys_derive_key(keys, ADV_INPUT_KEY)
    digest = hashlib.sha256(session_info).digest()
    # ldn_final_key() calls AES_decrypt() on ONE 16-byte block, so only the
    # first half of the digest is ever used.
    return aes128_ecb_dec(derived, digest[:16])


def derive_data_key(keys, server_random: bytes, passphrase: bytes) -> bytes:
    """ldn_data_key() from src/crypto.c."""
    derived = prodkeys_derive_key(keys, DATA_INPUT_KEY)
    digest = hashlib.sha256(server_random + passphrase).digest()
    return aes128_ecb_dec(derived, digest[:16])


DATA_INPUT_KEY = bytes.fromhex("f1e70184 19a84f71 1da714c2 cf919c9c".replace(" ", ""))


# --- 802.11 / LDN framing ------------------------------------------------


def build_80211(src_mac, dst_mac, subtype_action=True):
    """A minimal 802.11 header. emit() reads addr1 (+4) as the destination and
    addr2 (+10) as the source, so both must be right."""
    fc = 0x00D0 if subtype_action else 0x0008  # action / data frame
    # 802.11 header fields are little-endian; the bridge writes them that way now.
    hdr = struct.pack("<HH", fc, 0)
    hdr += dst_mac + src_mac
    hdr += b"\x00" * 6  # addr3
    hdr += struct.pack("<H", 0)  # sequence
    return hdr


def build_88b7(packet_type):
    return bytes(LDN_OUI) + struct.pack(">H", packet_type) + b"\x00"


def is_ldn_body(body):
    """
    Two framings, transcribed from src/ldn.c:

      advertisement (ldn_build_advertisement_action_frame):
        cat(1) OUI(3) proto(1) pad(1) type(2) @ +6, payload @ +12
      control / auth (build_88b7_header):
        OUI(3) type(2) @ +3, pad(1), LDN header @ +6
    """
    if len(body) < 6:
        return False
    adv = (body[0] == LDN_CATEGORY_VENDOR_SPECIFIC and tuple(body[1:4]) == LDN_OUI and
           body[4] == LDN_PROTOCOL_ID)
    ctrl = tuple(body[0:3]) == LDN_OUI
    return adv or ctrl


def body_type(body):
    if (len(body) >= 8 and body[0] == LDN_CATEGORY_VENDOR_SPECIFIC and
            tuple(body[1:4]) == LDN_OUI):
        return struct.unpack(">H", body[6:8])[0]
    return struct.unpack(">H", body[3:5])[0]


def body_payload(body):
    """Offset of the payload for each framing."""
    if (len(body) >= 12 and body[0] == LDN_CATEGORY_VENDOR_SPECIFIC and
            tuple(body[1:4]) == LDN_OUI):
        return body[12:]
    return body[6:]


def build_auth_request(session_info, server_random, client_random, username):
    """Layout from ldn_parse_auth_frame(): version, payload size, status,
    is_response, padding, session_info(32), server_random(16),
    client_random(16), then the request payload."""
    payload = bytearray(LDN_AUTH_REQUEST_PAYLOAD)
    payload[0:len(username)] = username

    hdr = bytearray()
    hdr.append(LDN_VERSION_3)
    hdr.append(LDN_AUTH_REQUEST_PAYLOAD & 0xFF)
    hdr.append(LDN_AUTH_SUCCESS)
    hdr.append(0)  # is_response = 0
    hdr.append((LDN_AUTH_REQUEST_PAYLOAD >> 8) & 0xFF)
    hdr.append(0)  # format: plaintext
    hdr.append(0)  # padding
    hdr.append(0)  # 8-byte header, matching ldn_parse_auth_frame's buf+8
    # A real console's frame carries the session info byte-reversed: the bridge
    # reverses it back in host_handle_frame() before comparing.
    hdr += bytes(reversed(session_info))
    hdr += server_random
    hdr += client_random
    hdr += payload
    return bytes(hdr)


class FakeConsole:
    def __init__(self, path, prodkeys, passphrase, title_id, verbose, wait_socket=True):
        self.path = path
        self.prodkeys = prodkeys
        self.passphrase = passphrase
        self.want_title = title_id
        self.verbose = verbose
        self.keys = None
        self.ap_mac = None

        # The bridge binds the socket a moment after it starts; do not try to
        # connect before it is there.
        if wait_socket:
            for _ in range(100):
                if os.path.exists(path):
                    break
                time.sleep(0.05)
            else:
                raise Fail(f"no bridge radio socket at {path}")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.bind_path = f"{path}.console"
        try:
            os.unlink(self.bind_path)
        except OSError:
            pass
        self.sock.bind(self.bind_path)
        # Locally administered, unicast. Six bytes - anything else shifts
        # the 802.11 header and the bridge reads the wrong addresses.
        self.mac = bytes.fromhex("024A57534499")

    # -- framing helpers -------------------------------------------------

    def send_ldn_control(self, body):
        """Send an LDN control frame the way the AP interface carries it.

        A real console's authentication frame arrives as an 802.11 *data* frame,
        which hostapd bridges onto the AP interface as an Ethernet frame with
        ethertype 0x88B7. That is the shape the bridge reads (emit()'s
        is_ldn_control path), so the console sends that too - otherwise
        console-sim would be exercising a framing the hardware never produces.
        """
        frame = (self.ap_mac + self.mac + b"\x88\xb7" + body)
        self.sock.sendto(frame, self.path)

    def send_frame(self, body, subtype_action=True):
        frame = build_80211(self.mac, self.ap_mac, subtype_action) + body
        self.sock.sendto(frame, self.path)

    def receive(self, timeout):
        self.sock.settimeout(timeout)
        try:
            data, _ = self.sock.recvfrom(9000)
            if self.verbose:
                print(f"  <recv {len(data)} bytes>", flush=True)
        except (socket.timeout, TimeoutError):
            return None
        # An LDN control frame arrives as an Ethernet frame with ethertype
        # 0x88B7: that is how an AP interface carries it, and how hostapd
        # bridges it to the station. Strip the 14-byte header and hand back the
        # 0x88B7 body, which is what the parsers below expect.
        if len(data) >= 14 and struct.unpack(">H", data[12:14])[0] == 0x88B7:
            if self.verbose:
                print("  <ethernet LDN control>", flush=True)
            return data[14:]
        # Downlink game traffic arrives as Ethernet with ethertype 0x0800. The
        # callers above only care about LDN control, so stash it rather than
        # dropping it: this is the only thing that exercises the bridge's
        # emulator -> console direction.
        if len(data) >= 14 and struct.unpack(">H", data[12:14])[0] == 0x0800:
            self.last_pia = data[14:]
            if self.verbose:
                print(f"  <ethernet IPv4 downlink {len(data) - 14}B>", flush=True)
            return None
        if len(data) < IEEE80211_HDRLEN:
            return None
        # addr1 is the destination (+4), addr2 the transmitter (+10) - the
        # transmitter of anything the bridge sends is the AP, so that is how we
        # learn its MAC.
        self.ap_mac = data[10:16]
        body = data[IEEE80211_HDRLEN:]
        return body

    # -- stages ----------------------------------------------------------

    def wait_advertisement(self, timeout=8.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            body = self.receive(timeout=max(0.05, deadline - time.monotonic()))
            if body is None:
                continue
            if self.verbose:
                print(f"  <body {len(body)}B oui={tuple(body[0:3])} "
                      f"type={body_type(body):#x} want={PACKET_ADVERTISEMENT:#x}>",
                      flush=True)
            if is_ldn_body(body) and body_type(body) == PACKET_ADVERTISEMENT:
                return body
        return None

    def decrypt_advertisement(self, body):
        """Decrypt an advertisement body to (session_info, plain_tail).

        plain_tail[0] is payload offset 0x28 (the hash field), so the advertise
        data itself starts at plain_tail[ADV_DATA - ADV_SHA256]."""
        payload = body_payload(body)
        session_info = payload[ADV_SESSION_INFO:ADV_SESSION_INFO + 32]
        nonce = payload[ADV_NONCE:ADV_NONCE + 4]
        key = derive_advertise_key(self.keys, session_info)
        plain_tail = aes128_ctr_xor(key, nonce + b"\x00" * 12,
                                    payload[ADV_SHA256:])
        return session_info, plain_tail

    def learn_own_ip(self, timeout=6.0):
        """Find our own node entry in a later advertisement and take its IPv4.

        A real console does not invent its LDN address: the host assigns it and
        publishes it in the advertisement's participant list. Hard-coding one
        (as this test used to) means the bridge is right and the test is wrong,
        which is exactly what happened - the station was 169.254.1.3 while the
        fake console claimed 169.254.3.1, so the downlink lookup could not match
        it.
        """
        base = ADV_DATA - ADV_SHA256
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            body = self.wait_advertisement(
                timeout=max(0.05, deadline - time.monotonic()))
            if body is None:
                continue
            _, plain = self.decrypt_advertisement(body)
            if len(plain) < base + ADV_OFF_PARTICIPANTS:
                continue
            count = plain[base + ADV_NODE_COUNT]
            for i in range(min(count, 8)):
                off = base + ADV_OFF_PARTICIPANTS + i * PARTICIPANT_SIZE
                if off + 10 > len(plain):
                    break
                if plain[off + 4:off + 10] == self.mac:
                    ip = plain[off:off + 4]
                    return ".".join(str(b) for b in ip)
        return None

    def check_advertisement(self, body):
        payload = body_payload(body)
        if len(payload) < ADV_DATA:
            raise Fail("advertisement payload is too short")

        session_info = payload[ADV_SESSION_INFO:ADV_SESSION_INFO + 32]
        title = struct.unpack(">Q", session_info[:8])[0]
        scene = struct.unpack(">Q", session_info[8:16])[0]
        nonce = payload[ADV_NONCE:ADV_NONCE + 4]
        blob = payload[ADV_SHA256:]

        stage("advertisement carries a plaintext session_info", True,
              f"title={title:016x} scene={scene:016x}")
        stage("title id is the one the emulator asked for", title == self.want_title,
              f"want={self.want_title:016x}")

        # The real proof of the bridge's crypto: derive the key ourselves and
        # decrypt. If the bridge's key derivation or its AES-CTR counter block
        # is wrong, this mismatches.
        key = derive_advertise_key(self.keys, session_info)
        if self.verbose:
            print(f"  <si={session_info.hex()}>\n  <key={key.hex()}>", flush=True)
        plain_tail = aes128_ctr_xor(key, nonce + b"\x00" * 12,
                                    payload[ADV_SHA256:])
        stage("advertisement decrypts with a key we derived ourselves", True,
              f"advertise key {key.hex()}, {len(payload) - ADV_SHA256} bytes "
              f"-> {len(plain_tail)}")

        # ldn_build_advertisement_action_frame() hashes the whole payload with
        # the hash field zeroed, with the advertise data already in place.
        full = bytearray(payload[:ADV_SHA256]) + bytearray(plain_tail)
        full[ADV_SHA256:ADV_SHA256 + 32] = b"\x00" * 32
        want = hashlib.sha256(bytes(full)).digest()
        stage("decrypted payload hashes to the advertised SHA-256",
              want == plain_tail[:32],
              f"want={want.hex()[:12]} got={plain_tail[:32].hex()[:12]}")
        return session_info, nonce, plain_tail

    def authenticate(self, session_info, server_random):
        req = build_auth_request(
            session_info,
            server_random,
            bytes.fromhex("00112233445566778899aabbccddeeff"),
            b"FakeConsole",
        )
        self.send_ldn_control(build_88b7(PACKET_AUTHENTICATION) + req)
        stage("AuthenticationRequest sent", True, f"{len(req)}-byte header")

        deadline = time.monotonic() + 4.0
        while time.monotonic() < deadline:
            body = self.receive(timeout=max(0.05, deadline - time.monotonic()))
            if body is None or not is_ldn_body(body):
                continue
            if body_type(body) != PACKET_AUTHENTICATION:
                continue
            return body[6:]
        return None

    def check_auth_response(self, resp):
        if resp is None or len(resp) < 0x48 + 0x84:
            raise Fail("no usable AuthenticationResponse arrived")
        status = resp[AUTH_OFF_STATUS]
        is_response = resp[AUTH_OFF_IS_RESPONSE]
        session_info = resp[AUTH_OFF_SESSION_INFO:AUTH_OFF_SESSION_INFO + 32]
        title = struct.unpack(">Q", session_info[:8])[0]

        stage("AuthenticationResponse status is SUCCESS", status == LDN_AUTH_SUCCESS,
              f"status={status}")
        stage("AuthenticationResponse is marked as a response", is_response == 1,
              f"is_response={is_response}")
        stage("response echoes our own session_info", title == self.want_title,
              f"title={title:016x}")
        platform = resp[0x48]
        stage("response payload is present", len(resp) >= 0x49, f"platform={platform:#x}")

    def send_pia(self):
        """A Pia game frame: 802.11 data frame carrying IPv4+UDP."""
        pia = self.passphrase[:16].ljust(16, b"\x00")
        udp = struct.pack(">HHHH", 40000, 30000, 8 + len(pia), 0) + pia
        # A 20-byte IPv4 header, no options - the extra 4 bytes that used to
        # follow here pushed the UDP header four bytes along, so the bridge read
        # the length and checksum fields as the ports.
        ip = struct.pack(">BBHHHBBH", 0x45, 0, 20 + 8 + len(pia), 0, 0, 64, 17, 0)
        # Source is the LDN IP the bridge assigned us, read back out of its own
        # advertisement; destination is the LDN IP it published for the guest.
        assert self.my_ip is not None, "no assigned IP"
        src_ip = bytes(int(x) for x in self.my_ip.split("."))
        ip += src_ip + bytes.fromhex("0A720001")
        ip += udp
        # Pia traffic reaches the AP interface as an Ethernet frame with
        # ethertype 0x0800 - hostapd bridges it - so send that shape.
        eth = self.ap_mac + self.mac + b"\x08\x00" + ip
        self.sock.sendto(eth, self.path)
        stage("Pia frame sent upstream as a data frame", True,
              "{}-byte IP packet".format(len(ip)))

    def expect_downlink(self, timeout=8.0):
        """Wait for the emulator's reply, which is the downlink direction.

        The bridge has to find the station by IPv4 and build a UDP frame for it.
        Until this stage existed, nothing tested that at all, and it was broken.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and self.last_pia is None:
            self.receive(timeout=max(0.05, deadline - time.monotonic()))

        if self.last_pia is None:
            stage("a frame from the emulator reached the console", False,
                  "nothing arrived in %.0f s" % timeout)
            return

        ip = self.last_pia
        if len(ip) < 28:
            stage("a frame from the emulator reached the console", False,
                  "%d-byte IP packet is too short" % len(ip))
            return
        stage("a frame from the emulator reached the console", True,
              "%d-byte IP packet" % len(ip))

        ihl = (ip[0] & 0x0F) * 4
        stage("downlink frame is IPv4/UDP", ip[0] >> 4 == 4 and ip[9] == 17,
              "version=%d proto=%d" % (ip[0] >> 4, ip[9]))
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        sport, dport, ulen = struct.unpack(">HHH", ip[ihl:ihl + 6])
        stage("downlink addressing is right",
              dst == self.my_ip and dport == 40000 and sport == 30000,
              "%s:%u -> %s:%u" % (src, sport, dst, dport))
        payload = ip[ihl + 8:ihl + ulen]
        stage("downlink payload is intact",
              payload == b"switch_ldn_downlink", repr(payload[:32]))

    def handshake_socket(self):
        """
        Introduce ourselves so the bridge can answer.

        The socket backend refuses to transmit until it has heard *something*
        from the peer, which would otherwise deadlock: the bridge will not
        advertise, and the console cannot authenticate until it has decrypted
        one. A hardware console avoids this simply by being present on the
        channel.
        """
        # 0x0000 is not a valid 802.11 frame control field, so emit() and the
        # pump discard this - but recvfrom() has now recorded us as the peer,
        # which is all the bridge needed.
        self.sock.sendto(b"\x00", self.path)
        stage("announced ourselves to the bridge", True, self.path)

    def run(self):
        self.keys = parse_prod_keys(self.prodkeys)
        self.last_pia = None
        self.my_ip = None
        stage("attached to the bridge's radio socket", True, self.path)
        self.handshake_socket()

        body = self.wait_advertisement()
        if body is None:
            raise Fail("no LDN advertisement arrived on the radio socket")
        stage("advertisement received", True, f"{len(body)}-byte body")

        session_info, nonce, plain_tail = self.check_advertisement(body)
        # The decrypted tail starts at payload offset 0x28; the advertise data
        # (and with it server_random, its first field) starts at 0x48.
        cand = plain_tail[0x48 - 0x28: 0x48 - 0x28 + 16]
        server_random = cand
        resp = self.authenticate(session_info, server_random)
        self.check_auth_response(resp)
        self.my_ip = self.learn_own_ip()
        stage("bridge published an address for us in its advertisement",
              self.my_ip is not None, self.my_ip or "no node entry with our MAC")
        # ...and that address has to be in the LDN link-local range. Without
        # this, a byte-swapped address propagates consistently: the bridge
        # advertises 3.1.254.169, we believe it, we send from it, the bridge
        # matches it, and every later stage passes on a nonsense address.
        stage("assigned address is in 169.254.0.0/16",
              self.my_ip is not None and self.my_ip.startswith("169.254."),
              self.my_ip or "-")
        self.send_pia()
        self.expect_downlink()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", required=True)
    ap.add_argument("--prodkeys", default="tests/interop/prod.keys")
    ap.add_argument("--passphrase", default="LDN_PASSPHRASE")
    ap.add_argument("--title-id", default="01006F8002320000")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    title = int(args.title_id, 16)
    con = FakeConsole(args.socket, args.prodkeys, args.passphrase.encode(),
                      title, args.verbose)
    try:
        con.run()
    except Fail as exc:
        print(f"\nFAILED: {exc}", flush=True)
        return 1
    finally:
        try:
            con.sock.close()
            if con.bind_path:
                try:
                    os.unlink(con.bind_path)
                except OSError:
                    pass
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
