# Emulator sources used for the interop tests

Where the real Ryujinx-family and yuzu-family client code lives, and why these
specific sources.

## Ryujinx family (RyuLdn TCP, port 30456)

`https://github.com/Ryujinx/Ryujinx` — **gone**. The project was taken down on
2024-10-01 after its author was forced to abandon it; GitHub now answers
`Repository not found`.

The actively maintained successor is **Ryubing**, self-hosted on a Forgejo
instance:

    https://git.ryujinx.app/ryubing/ryujinx      # per https://docs.ryujinx.app/dev/compilation/

That host is behind an anti-bot wall (and refuses plain TLS from here), so it is
not reachable from this machine. The GitHub `Ryubing/ryujinx` alias likewise
does not exist, and the Axenov Museum mirror (`git.axenov.dev/Museum/ryujinx`,
HEAD 2024-10-24) predates RyuLdn support entirely.

The source actually cloned for the interop test:

    https://github.com/NextendoNetwork/Ryujinx-Nextendo
    # fork of Ryujinx with an online-play client baked in; HEAD 2026-10-13

It contains the genuine RyuLdn client, which is what matters:

    src/Ryujinx.HLE/HOS/Services/Ldn/UserServiceCreator/LdnRyu/
        RyuLdnProtocol.cs          packet framing
        Types/PacketId.cs          packet ids
        Types/InitializeMessage.cs
        Types/PassphraseMessage.cs
        Types/RyuNetworkConfig.cs  <- carries SecurityConfig + the passphrase
        Types/LdnHeader.cs, ProxyInfo.cs, ProxyConnectResponse.cs ...

Caveat: it is a *fork*, so its RyuLdn additions are its own. For anything that
looks like a vendor extension rather than core RyuLdn, cross-check against
Ryubing's own reference implementation before trusting it:

    https://github.com/Ryubing/LdnServer     # 32 stars, maintained
    # LdnServer/Network/RyuLdnProtocol.cs is the byte-for-byte reference the
    # protocol must stay compatible with

## yuzu family (Room UDP, port 24872)

    https://git.eden-emu.dev/eden-emu/eden     (HEAD 218c6705, 2026-10-13)

Cloned directly; no workaround needed.

    src/network/room.cpp          Room client
    src/network/packet.{h,cpp}    Packet serialisation
    src/network/room_member.{h,cpp}
    patches/eden-room-passphrase.patch  our patch, forwards the LDN passphrase

## How the bridge is driven

`tests/bridge_harness.c` compiles `src/main.c` (with its `main` renamed away)
plus the real transport and LDN-core objects, so it runs the identical code path
as `./switch_ldn` minus hostapd and frame injection. That is exactly the surface
an emulator peer talks to, so interop can be tested without radio hardware.

The Eden/Yuzu side needs one patch to be useful for testing, because stock Eden
throws the LDN passphrase away. See [EDEN_PATCH.md](EDEN_PATCH.md) for what it
changes, why it stays wire-compatible, and how to verify it with
`scripts/build_eden.sh`.
