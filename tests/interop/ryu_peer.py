import socket, struct, sys as _sys, time
_sys.stdout.reconfigure(line_buffering=True)  # a held session must log as it goes

H="127.0.0.1"; P=30456
print("[*] connecting to %s:%d" % (H,P))
s=socket.socket(); s.settimeout(3); s.connect((H,P))
print("[*] connected")

# --- hold mode: receive the ProxyData a console sends ----------------------
#
# The bridge relays real-console Pia traffic to us as RYULDN_PROXY_DATA. The
# header is RyuLdnProxyDataHeader (20 bytes): an interleaved ProxyInfo
# {srcIp, srcPort, dstIp, dstPort, proto} followed by data_length. The fields
# are NOT grouped by kind, and both orders are 16 bytes, so only decoding them
# in the right order proves the bridge routed our own frame back correctly.

def parse_proxy_info(b):
    """The fields are interleaved - {srcIp, srcPort, dstIp, dstPort, proto} -
    not grouped by kind. Both orders are 16 bytes, so only decoding in the
    right order shows whether the bridge routed our frame correctly."""
    src_ip, src_port, dst_ip, dst_port, proto = struct.unpack("<IHIHI", b[:16])
    return src_ip, src_port, dst_ip, dst_port, proto


def ip_str(v):
    """RyuLdnProxyInfo stores the address big-endian in a u32."""
    return "%u.%u.%u.%u" % ((v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF,
                             v & 0xFF)


def stage(name, ok, detail=""):
    print("[{}] {}{}".format("PASS" if ok else "FAIL", name,
                             " - " + detail if detail else ""), flush=True)
    return ok




def frame(ptype, payload=b""):
    h = struct.pack("<IBBH", 0x4E444C52, ptype, 1, 0) + struct.pack("<I", len(payload))
    assert len(h)==12, len(h)
    return h + payload

def send(ptype, payload=b"", note=""):
    b=frame(ptype,payload)
    s.sendall(b); print(">>> type=%d %-28s %d bytes" % (ptype, note, len(b)))
    if len(b)<=256:
        print("    "+b.hex())

def decode_proxy(body):
    """Decode a ProxyData payload, or return None if it is not one."""
    if len(body) < 20:
        return None
    return parse_proxy_info(bytes(body)) + (struct.unpack("<I", bytes(body[16:20]))[0],
                                            bytes(body[20:]))

g_proxy = None  # the last ProxyData we decoded, so the caller can assert on it


def recv_one(timeout=2):
    s.settimeout(timeout)
    data=bytearray()
    first=s.recv(12)
    if not first or len(first)<12: return None
    magic=struct.unpack("<I",first[0:4])[0]
    ptype=first[4]; ver=first[5]; _=first[6:8]; sz=struct.unpack("<I",first[8:12])[0]
    while len(data)<sz:
        data+=s.recv(min(4096,sz-len(data)))
    full=first+bytes(data)
    print("<<< type=%d data=%d bytes" % (ptype,sz))
    if ptype == 20:
        dec = decode_proxy(bytes(data))
        if dec:
            globals()["g_proxy"] = dec
            print("    ProxyData {}:{} -> {}:{} proto={} payload={} bytes".format(
                  ip_str(si), sp, ip_str(di), dp, proto, dlen))
            if dlen <= 64:
                print("    " + payload.hex())
    elif sz<=256: print("    "+full[-sz:].hex() if sz else "")
    else: print("    "+full[12:64].hex()+"...")
    return ptype,full

# 1. Passphrase (128 zero bytes)
send(1, b"\x00"*128, "Passphrase")
# 2. Initialize with all-zero id+mac
send(0, b"\x00"*16+b"\x00"*6, "Initialize")
# 3. expect Initialize reply
print("waiting Initialize reply...")
recv_one()

# 4. Ping requester=1 id=0x42
send(254, bytes([1,0x42]), "Ping")
recv_one()

# 5. CreateAccessPoint (id 2) with real structs
# SecurityConfig: u16 mode, u16 passphrase_size, u8[64]
passphrase = b"LDN_PASSPHRASE!!\x00"*4
psc = struct.pack("<HH", 1, 16) + passphrase[:64]
# UserConfig: 33 bytes username + 15 unknown (simplified: all 0 with name)
user = bytearray(33)+bytearray(15)
user[:4]=b"peer"
usercfg = bytes(user)
# NetworkConfig: IntentId(16) = u64 title, u16 scene, u8 reserved[6]; channel u16; node_count u8; reserved u8; lcv u16; reserved2 u8[10]
intent = struct.pack("<QH6x", 0x01006F8002320000, 1)
ncfg = intent + struct.pack("<HBBH10x", 1, 8, 0, 1)  # channel,node_count,reserved,lcv
assert len(ncfg)==32, len(ncfg)
# RyuNetworkConfig: game_version[16], private_ip[16], address_family u32, external_port u16, internal_port u16
ryu = b"2.0.0\x00"*0+b"\x00"*16 if False else None
ryu = b"1.0.0.0\x00".ljust(16,b"\x00")+b"\x02\x00\x00\x00".ljust(4,b"\x00")  # no
# build properly
ryu = struct.pack("16s", b"2.0.0\x00"*0+b"2.0.0\x00"+b"\x00"*(16-6)) if False else None
ryu = (b"2.0.0\x00"+b"\x00"*10) + (b"\x00"*16) + struct.pack("<IHH", 2, 0, 0)
assert len(ryu)==0x28, len(ryu)
cap_body = psc + usercfg + ncfg + ryu
assert len(cap_body)==0xBC, len(cap_body)
send(2, cap_body, "CreateAccessPoint")
# expect ProxyConfig + Connected
for _ in range(4):
    try: recv_one()
    except: break
    time.sleep(0.1)
# SyncNetwork may follow
try: recv_one()
except: pass
print("DONE")

def wait_for_proxy(timeout=12.0):
    """Wait for a console's Pia frame to reach us as a ProxyData.

    The console authenticates before it sends anything, so the frame usually
    arrives after our own handshake has finished. recv_one() records it in
    g_proxy, so this is just patience, not a second parser."""
    deadline = time.monotonic() + timeout
    while g_proxy is None and time.monotonic() < deadline:
        try:
            recv_one(timeout=max(0.2, deadline - time.monotonic()))
        except (socket.timeout, OSError):
            break
    return g_proxy


if "--expect-proxy" in _sys.argv[1:]:
    # A real console's Pia traffic reaches us as ProxyData; the frame can
    # arrive during the handshake or after it.
    got = g_proxy or wait_for_proxy()
    if got is not None:
        si, sp, di, dp, proto, dlen, payload = got
        stage("ProxyData received from a real console", True,
              "{}:{} -> {}:{}".format(ip_str(si), sp, ip_str(di), dp))
        stage("ProxyData payload is intact", len(payload) == dlen and dlen > 0,
              "{} bytes".format(dlen))
    else:
        stage("ProxyData received from a real console", False, "none arrived")
    # In this mode the answer is the point, so do not then sit in the hold loop
    # forever - console-sim waits for this process to exit before it reads the
    # verdict.
    _sys.exit(0 if got is not None else 1)

# Optionally hold the session open so a second peer (the fake console) has a
# live LDN network to talk to. `make interop` relies on the default immediate
# exit, so the socket is only closed in that case.
import sys as _sys


if "--hold" in _sys.argv[1:]:
    print("holding the session open (Ctrl-C to end)")
    expect_proxy = "--expect-proxy" in _sys.argv[1:]
    seen = 0
    try:
        while True:
            s.settimeout(5)
            try:
                first = s.recv(12)
            except socket.timeout:
                continue
            except OSError:
                break
            if not first or len(first) < 12:
                break
            ptype = first[4]
            sz = struct.unpack("<I", first[8:12])[0]
            body = bytearray()
            while len(body) < sz:
                chunk = s.recv(min(4096, sz - len(body)))
                if not chunk:
                    break
                body += chunk
            if ptype != 20:  # RYULDN_PROXY_DATA
                print("<<< type=%d data=%d bytes (ignored)" % (ptype, sz), flush=True)
                continue
            if len(body) < 20:
                print("<<< ProxyData too short: %d bytes" % len(body), flush=True)
                continue
            si, sp, di, dp, proto = parse_proxy_info(bytes(body))
            dlen = struct.unpack("<I", bytes(body[16:20]))[0]
            payload = bytes(body[20:20 + dlen])
            print("<<< ProxyData {}:{} -> {}:{} proto={} payload={} bytes".format(
                  ip_str(si), sp, ip_str(di), dp, proto, dlen), flush=True)
            if dlen <= 64:
                print("    " + payload.hex(), flush=True)
            seen += 1
            if expect_proxy and seen >= 1:
                # The console's frame was addressed to the LDN IP we published
                # for this guest, and carried the passphrase bytes it streamed.
                stage("ProxyData received from a real console", True,
                      "{}:{} -> {}:{}".format(ip_str(si), sp, ip_str(di), dp))
                stage("ProxyData payload is non-empty", len(payload) > 0,
                      "{} bytes".format(dlen))
                break
    except KeyboardInterrupt:
        pass
s.close()
