# 使用说明

按场景组织。三件事先说清楚：

1. **桥不挑模拟器，但同时只监听两个端口**——Ryubing 连 30456，Eden 连 24872，
   两边可以同时在线。
2. **真机永远是被动方**：你（或朋友）在模拟器里建房间，真机本地无线里就能看到。
3. **桥只需要 `--prodkeys` 一个参数**。密语、title id、版本号全部由模拟器里的
   游戏自己提供。

---

## 兼容性矩阵

两套传输、一个 LDN 核心，同时监听，切换模拟器不用重新配置。

| 模拟器家族 | 协议 | 端口 | 状态 | 备注 |
|---|---|---|---|---|
| **Ryubing**（Ryujinx fork） | RyuLdn over TCP | `30456` | ✅ | 游戏的 `CreateNetwork` 原样转发，无需逐游戏配置 |
| **Ryujinx**（pre-2024） | RyuLdn over TCP | `30456` | ✅ | 同上 |
| **Eden** | Room over UDP | `24872` | ✅ | 需先打 `patches/eden-room-passphrase.patch` |
| **Citron / Sudachi / yuzu** | Room over UDP | `24872` | ✅ | 同 Eden |

两条传输都支持双向真实游戏流量：`IdProxyPacket`（Room）与 `ProxyData`（RyuLdn）互为镜像。
注意 Room 侧有两个字段**不是** IP 头的编号——`Domain::INET = 1`、`Protocol::UDP = 4`（不是 17），
且 payload 必须经过 zstd 压缩，因为 Eden 只在最终的游戏 socket 侧解压
（`ProxySocket::SendPacket` 压缩 / `HandleProxyPacket` 解压），桥作为中继必须自己解压还原。

## 场景 A：Ryubing（最省事，推荐先跑通）

```bash
./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon --channel 1 --prodkeys prod.keys
```

然后 Ryubing：`Multiplayer → LDN → Mode: RyuLDN`，服务器填 `127.0.0.1`，端口 `30456`。

密语、title id、版本号全部由 Ryubing 里的游戏自动提供——它把游戏自己的
`CreateNetwork` 调用转发给桥了。**这条路径不需要你做任何逐游戏配置。**

## 场景 B：Eden / Citron / Sudachi

命令和场景 A **完全一样**：

```bash
./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon --channel 1 --prodkeys prod.keys
```

然后 Eden：`Multiplayer → Direct Connect → 127.0.0.1:24872`。

前提是先给 Eden 打一个补丁（见下）。不打补丁 Eden 路径用不了，桥会明确报错。

### 为什么 Eden 需要补丁，Ryubing 不需要

| | RyuLdn（Ryubing） | Room（Eden） |
|---|---|---|
| 协议里有没有 `SecurityConfig` | **有** | **没有** |
| 桥能自动拿到密语吗 | 能 | 不能 |

Eden 其实**收到过**密语，只是自己扔了。确切位置：

```
IUserLocalCommunicationService::CreateNetwork(create_config)
    └─ create_config.security_config              ← 密语在这里，完整传入
         └─ LANDiscovery::CreateNetwork(security_config, ...)
              network_info.ldn.security_mode = security_config.security_mode;
              // passphrase / passphrase_size 再也没被读过   ← 就在这里丢的
```

`src/core/hle/service/ldn/lan_discovery.cpp`。补丁把它捡回来，做法是
**追加式、向后兼容**：

```bash
git -C eden apply < switch_ldn/patches/eden-room-passphrase.patch
```

密语追加在 `IdLdnPacket` 的 `data` 字段**之后**。三个理由让它双向都不破坏：

1. Room 服务器是哑中继，原样转发整包 → 多余字节自动透传，Eden 的 room 服务端零改动
2. `HandleLdnPackets()` 只读自己认识的字段 → 会自然读过尾部字节
3. stock Eden 发出的包和新格式在已读字段上完全一致 → 桥靠"data 之后还有没有字节"判断

打完重建 Eden，之后什么都不用配，桥在第一个 `IdLdnPacket` 里就学到密语。

**补丁的实际改动**是 4 个文件 17 行：`LDNPacket` 加一个 `std::vector<u8> passphrase`、
`SendLdnPacket` 里 `data` 之后写它、`LANDiscovery` 存一份并在 `SendPacket` 时带上。

### 不打补丁会怎样

桥会明确报错并断开该 Eden 成员：

```
ERROR Room transport: cannot build the LDN network for title 01001b300b9be000,
      because the LDN crypto passphrase never arrived. Stock Eden drops it in
      LANDiscovery::CreateNetwork(); apply patches/eden-room-passphrase.patch.
```

不会出现"看着连上了但真机搜不到"的静默失败。

## 场景 C：Ryubing 和 Eden 同时在线

不需要任何额外参数，两个端口本来就都开着。Ryubing 指 30456，Eden 指 24872，
桥背后是同一套 LDN 网络，两边看到的是同一个房间、同一批真机玩家。

---

## 完整启动顺序

射频部分需要 root，模拟器部分不需要：

```bash
# 1. 探测网卡能力（都不支持就换芯片，见下）
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh selfcheck

# 2. 起网卡：一个 AP 接口 + 一个 monitor 接口
sudo IFACE=wlan0 CHANNEL=1 scripts/setup-ap.sh up

# 3. hostapd：隐藏 SSID + 开放认证 + 无 WPA
hostapd config/ldn-ap.conf &

# 4. 桥
sudo ./switch_ldn --ap-iface wlan0_ap --mon-iface wlan0_mon \
    --channel 1 --prodkeys prod.keys
```

`config/ldn-ap.conf` 里 `interface=` 要改成第 2 步实际生成的 AP 接口名
（默认 `wlan0_ap`），channel 要和 `--channel` 一致。

## 自检

```bash
# 不插网卡也能跑
./switch_ldn --selfcheck lo
make test        # 4 套协议测试，全过说明 wire 格式没问题
```

`make test` 不碰射频，覆盖 RyuLdn 握手、Room wire 格式、帧结构和 p1 拒绝路径。
剩下的未知项只有 `TODO-1`（AES-CTR counter block 布局），那个必须真机抓包。

## 不需要的东西

| 项 | 说明 |
|---|---|
| 破解的真机 | 不需要。桥自己当 LDN 主机，真机以普通本地无线身份加入 |
| `ldn_mitm` / `switch-lan-play` | 不需要，那是让真机迁就模拟器的路子，我们是反过来的 |
| 联网 | 不需要。`setup-ap.sh` 会把 NetworkManager 停掉，纯本地 |
| 第二台电脑 | 不需要，一个进程同时是 AP、LDN 主机和 RyuLdn/Room 服务器 |
| 逐游戏配置 | 不需要。没有密语表、没有 title id 表，游戏自己会报 |

## 硬件要求

必须是能进 monitor 模式**并支持帧注入**的网卡。当前适配的是 RTL8812AU
（配 aircrack-ng 的 out-of-tree 驱动）。

已知坑：该驱动的虚拟接口支持不稳定（aircrack-ng/rtl8812au issue #93、#376）。
`setup-ap.sh selfcheck` 会先探，如果 monitor VIF 建不出来，退路是单 monitor
接口 + 自己实现 802.11 MAC 状态机，见 `DESIGN.md §3b`。换 mt7610u / mt7612u /
mt7921au 这类内核原生支持好的芯片会省事很多。

## 房间的可见性

**任何 Switch 都能扫到帧，但只有同款游戏会把它列出来、也只有同款游戏能加入。**

三道关卡，细节和推导见 `docs/ROOM_VISIBILITY.md`：

| 关卡 | 层级 | 是否按游戏过滤 |
|---|---|---|
| 解密 advertisement | 密码学 | ❌ 不按游戏——帧头是明文 |
| 游戏的 Scan 过滤器 | 游戏自己 | ✅ 按 title id 过滤 |
| 加入时的 data key | 密码学 | ✅ 需要该游戏的密语 |

所以不同游戏不是"看不到"，而是**列不出来**；就算强行加入，密语不匹配也会在数据层挂掉。桥这边不需要为此做任何事，协议本身就是安全的。

**一个例外**:共用密语的游戏能互相看到并真正加入（比如朱紫和阿尔宙斯）。

桥这边的兜底：`host.c` 会校验认证请求里的 session_info（title id + scene id），
不一致就按 malformed（status 2）拒掉，所以不会出现"连上了但莫名失败"的静默失败。

## 什么时候会静默失败

下面这些是桥不会提前拦截、只能靠现象排查的失败；以前"看着连上了却真机搜不到/进不去"的路径现在都会明确报错，不再静默。

| 现象 | 大概率原因 |
|---|---|
| 真机完全搜不到房间 | 信道不匹配；或 monitor 接口注入失败（看日志有没有 advertisement） |
| 真机能看到房但进不去 | 密语不对，或游戏版本不匹配（游戏自己比 `local_communication_version`） |
| 模拟器侧一直转圈 | 端口没连到桥；Room 路径检查补丁是否已打 |

桥现在会明确报错、不再静默失败的情况：

- Eden 未打补丁：`ERROR Room transport: cannot build the LDN network for title ...,
  because the LDN crypto passphrase never arrived.`
- 认证请求的 session_info（title id + scene id）与桥不一致：按 malformed（status 2）拒掉
- p1（模拟器加入真机房间）：返回 `NetworkError(ConnectionRejected)`，不挂起
- Room 里房间已满 / 协议版本不匹配：直接回 `IdRoomIsFull` / `IdVersionMismatch`，
  不再把拒绝报文丢掉让模拟器一直转圈

Room 的成员表有一条 60 秒静默回收（`room_server_set_idle_timeout_ms` 可调，设 0 关闭）:
Room 协议本身没有断连也没有心跳，一个关掉的成员会一直占着位置，所以桥会在房间需要
空位时回收静默超限的成员，否则房间会被永久占满、之后谁都进不来。活跃成员不受影响。

AES-CTR counter block 布局已经用 kinnay/LDN 的参考向量钉死了（`tests/test_ctr_vectors.c`），
不再是未知项；`ChallengeResponse` 也不需要——真机根本不解析房主回的 challenge
（见 `README.md` 的 "Why no ChallengeResponse is needed"）。
