import socket, struct, time

H="127.0.0.1"; P=30456
print("[*] connecting to %s:%d" % (H,P))
s=socket.socket(); s.settimeout(3); s.connect((H,P))
print("[*] connected")

def frame(ptype, payload=b""):
    h = struct.pack("<IBBH", 0x4E444C52, ptype, 1, 0) + struct.pack("<I", len(payload))
    assert len(h)==12, len(h)
    return h + payload

def send(ptype, payload=b"", note=""):
    b=frame(ptype,payload)
    s.sendall(b); print(">>> type=%d %-28s %d bytes" % (ptype, note, len(b)))
    if len(b)<=256:
        print("    "+b.hex())

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
    if sz<=256: print("    "+full[-sz:].hex() if sz else "")
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
s.close()
