# Real RyuLdn peer — Python reference that drives the bridge exactly as Ryujinx emits.
import socket, struct, sys, time

HOST=sys.argv[1] if len(sys.argv)>1 else '127.0.0.1'
PORT=int(sys.argv[2]) if len(sys.argv)>2 else 30456

def hx(x): return x[0:128]

def hdr(ptype, sz):
    return struct.pack('<IBBH',0x4E444C52,ptype,1,0) + struct.pack('<I',sz)

s=socket.socket(); s.settimeout(3); s.connect((HOST,PORT))
print("connected to",HOST,PORT)

def send(t,payload=b'',note=None):
    b=hdr(t,len(payload))+payload
    s.sendall(b)
    print(">>>", t, (note or ''), len(b), "bytes")
    print(b.hex())

def recv():
    h=s.recv(12)
    if len(h)<12: return None,h
    sz=struct.unpack('<I',h[8:12])[0]
    buf=bytearray()
    while len(buf)<sz:
        d=s.recv(4096)
        if not d: break
        buf+=d
    print("<<< type=%d data=%d bytes"%(h[4],sz))
    print(h.hex()+buf.hex())
    return h[4], bytes(buf[:sz])

send(1, b'\x00'*128, "Passphrase (id=1)")
send(0, b'\x00'*22, "Initialize (id=0)")
print("waiting Initialize reply..."); recv()
send(254, bytes([1,0x42]), "Ping")
recv()
psc=struct.pack('<HH',1,16)+b'LDN_PASSPHRASE!!'.ljust(64,b'\x00')
user=bytearray(33+15)
usercfg=bytes(user)
intent=struct.pack('<QHxxxxxx',0x01006F8002320000,1)
ncfg=intent+struct.pack('<HBBH',1,8,0,1)+b'\x00'*10
ryu=(b'2.0.0\x00'+b'\x00'*10).ljust(16,b'\x00') + (b'\x00'*16) + struct.pack('<IHH',2,0,0)
cap=psc+usercfg+ncfg+ryu
send(2, cap, "CreateAccessPoint")
for _ in range(3):
    try: recv()
    except socket.timeout: break
try: recv()
except socket.timeout: pass
s.close(); print("DONE")
