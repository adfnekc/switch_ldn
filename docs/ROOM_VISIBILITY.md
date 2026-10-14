# Room visibility: who can see the room, who can join

Short answer: **发现不等于能加入。任何一个 Switch 都能扫到帧，但只有同款游戏能进。**

Three separate gates, at two different layers.

## What an advertisement frame actually contains

```
[802.11 header]                            明文
[vendor action body]                       明文
  category 127, OUI 00:22:AA, proto 4      明文
  packet type 257                          明文
  0x00  session_info (32)                  ← 明文！含 title id 和 game mode
  0x20  LDN version                        ← 明文
  0x21  encryption type                    ← 明文
  0x22  advertise data size                ← 明文
  0x24  nonce (4)                          ← 明文
  0x28  SHA-256                            ← 密文
  0x48  advertisement data                 ← 密文
```

The session info is **plaintext**. It has to be: the receiving console needs the
title id to derive the key that decrypts the rest, and the key derivation only
takes the session info as input.

## The three gates

### Gate 1 — decryption (cryptographic, per game)

`advertisement_key = f(prod.keys, session_info)`

It depends **only** on the session info, not on the game's passphrase. So any
console holding a valid `prod.keys` can decrypt any other game's advertisement
and read its contents. This gate does *not* filter by game.

The passphrase only enters the **data** key:

```
data_key = f(prod.keys, server_random || game passphrase)
```

### Gate 2 — the game's scan filter (game level)

`Scan` takes a `ScanFilter` containing the `network_id` and a flag. The
**game** fills this in, and it filters on `local_communication_id` — the title
id it read out of the frame's plaintext header.

So the game's UI simply never lists a room belonging to a different game. This
is where "different games ignore it" actually happens: not by failing, but by
**never being offered**.

### Gate 3 — joining (cryptographic, per game)

To join, the client must derive the data key, which needs the game's passphrase
— a constant compiled into that specific game's binary. A console running game B
does not know game A's passphrase, so:

- it cannot produce a valid `AuthenticationRequest` the host can decrypt, or
- if the host accepts anyway, no subsequent data frame can be read by either
  side.

Result: joining fails. Not a clean "wrong game" dialog, just a dead connection.

## What this means for the bridge

Same conclusion from either direction:

- A console running game Y scans and sees our room's raw frame, but its game
  filters it out of the list because the title id differs. Nothing happens.
- If it tried to join anyway, the passphrase mismatch would break the data
  path.

So the bridge does not have to do anything to be "game safe" — the protocol
already is. But it *does* matter that our advertisement carries the right title
id, and that is exactly what we take from the emulator's own `CreateNetwork`
call.

There is one place the bridge adds protection: `host_handle_frame()` rejects an
`AuthenticationRequest` whose session_info does not match ours (title id and
scene id), replying with status code 2 (malformed). Without that check a
wrong-game console would associate at the LDN layer and then fail silently
later, which is far harder to diagnose.

## Practical consequence

**Games that share a passphrase can see each other's rooms.** This is real: the
NintendoClients passphrase table shows Pokémon Scarlet/Violet and Pokémon
Legends: Arceus all using the same value. If you host one of those, the other
two can scan it, and joining will actually get somewhere.
