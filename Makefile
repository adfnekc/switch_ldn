CC      ?= gcc
CFLAGS  ?= -O2 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter
# OpenSSL 3 deprecates the low-level AES API; the EVP layer needs more plumbing for now.
CFLAGS  += -Wno-deprecated-declarations
# nl80211 lives under libnl3's own include prefix on Debian/Ubuntu.
CFLAGS  += -I/usr/include/libnl3
# Track header dependencies. Without this, editing radio.h or ldn.h rebuilds
# nothing: the old object files stay, the link still succeeds, and the result is
# a binary mixing two struct layouts. That is how a change to RadioFrame
# produced a bridge that ran but silently stopped dispatching console frames.
CFLAGS  += -MMD -MP
CPPFLAGS = -D_GNU_SOURCE
LDLIBS   = -lcrypto -lzstd -lnl-3 -lnl-genl-3

SRCDIR := src
OBJDIR := build
BIN    := switch_ldn

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
TEST_OBJS := build/crypto.o build/ldn.o build/ryuldn.o build/room.o build/radio.o build/nl80211.o build/util.o
# host.o lives outside TEST_OBJS because only the host-side tests need it, but
# `make test` must still build it or those links fail from a clean tree.
BRIDGE_OBJS := build/crypto.o build/ldn.o build/ryuldn.o build/room.o build/radio.o build/nl80211.o build/util.o build/host.o

.PHONY: all clean check test interop console-sim

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

-include $(OBJS:.o=.d)

clean:
	rm -rf $(OBJDIR) $(BIN) build/room_peer
	rm -f /tmp/ldn-console.*

# ---------------------------------------------------------------------------
# Tests. All of them are socket-level and need no radio hardware.
# ---------------------------------------------------------------------------
test: $(TEST_OBJS) build/host.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_wire tests/test_wire.c \
	    $(TEST_OBJS) $(LDLIBS)
	./build/test_wire
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_p1_refused tests/test_p1_refused.c \
	    build/ryuldn.o build/util.o $(LDLIBS)
	./build/test_p1_refused
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_handshake tests/test_handshake.c \
	    build/ryuldn.o build/util.o $(LDLIBS)
	./build/test_handshake
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -Itests -o build/test_room_wire tests/test_room_wire.c \
	    build/room.o build/util.o $(LDLIBS)
	./build/test_room_wire
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -Itests -o build/test_ctr_vectors tests/test_ctr_vectors.c \
	    build/crypto.o build/util.o $(LDLIBS)
	./build/test_ctr_vectors
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -Itests -o build/test_auth_frame tests/test_auth_frame.c \
	    build/ldn.o build/crypto.o build/util.o $(LDLIBS)
	./build/test_auth_frame
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_advert_nonce tests/test_advert_nonce.c \
	    build/host.o $(TEST_OBJS) $(LDLIBS)
	./build/test_advert_nonce
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_host_watchdog tests/test_host_watchdog.c \
	    build/host.o $(TEST_OBJS) $(LDLIBS)
	./build/test_host_watchdog
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -Itests -o build/test_advert_hash tests/test_advert_hash.c \
	    build/ldn.o build/crypto.o build/util.o $(LDLIBS)
	./build/test_advert_hash
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_frame_classify tests/test_frame_classify.c \
	    build/ldn.o build/crypto.o build/util.o $(LDLIBS)
	./build/test_frame_classify
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_prodkeys_load tests/test_prodkeys_load.c \
	    build/crypto.o build/util.o $(LDLIBS)
	./build/test_prodkeys_load
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o build/test_multi_station tests/test_multi_station.c \
	    build/host.o $(TEST_OBJS) $(LDLIBS)
	./build/test_multi_station

# ---------------------------------------------------------------------------
# CLI smoke test, also without radio hardware.
# ---------------------------------------------------------------------------
check: $(BIN)
	./$(BIN) --help
	@echo "--- selfcheck on loopback (expected: no wireless extensions) ---"
	./$(BIN) --selfcheck lo || true
	@echo "--- selfcheck must FAIL for an interface that is not there ---"
	@if ./$(BIN) --selfcheck __no_such_iface >/dev/null 2>&1; then \
	    echo "ERROR: selfcheck on a missing interface exited 0"; exit 1; \
	else echo "correctly nonzero"; fi
	@echo "--- live mode must refuse to start without --ap-iface ---"
	@if ./$(BIN) --prodkeys tests/interop/prod.keys >/dev/null 2>&1; then \
	    echo "ERROR: should have failed"; exit 1; \
	else echo "correctly refused"; fi
	@echo "--- prod.keys is found in the default location, no flag needed ---"
	@h=$$(mktemp -d); mkdir -p $$h/.config/switch_ldn; \
	cp tests/interop/prod.keys $$h/.config/switch_ldn/prod.keys; \
	if XDG_CONFIG_HOME= HOME=$$h timeout 3 ./$(BIN) --radio-socket /tmp/check-keys.sock 2>&1 \
	    | grep -q "using prod.keys from $$h/.config/switch_ldn/prod.keys"; then \
	    echo "found it"; else echo "ERROR: default lookup did not find prod.keys"; rm -rf $$h /tmp/check-keys.sock; exit 1; fi; \
	rm -rf $$h /tmp/check-keys.sock*
	@echo "--- XDG_CONFIG_HOME takes precedence over HOME, as XDG says it must ---"
	@h=$$(mktemp -d); mkdir -p $$h/.config/switch_ldn $$h/xdg/switch_ldn; \
	cp tests/interop/prod.keys $$h/xdg/switch_ldn/prod.keys; \
	if XDG_CONFIG_HOME=$$h/xdg HOME=$$h timeout 3 ./$(BIN) --radio-socket /tmp/check-xdg.sock 2>&1 \
	    | grep -q "using prod.keys from $$h/xdg/switch_ldn/prod.keys"; then \
	    echo "XDG won"; else echo "ERROR: XDG_CONFIG_HOME was ignored"; rm -rf $$h /tmp/check-xdg.sock; exit 1; fi; \
	rm -rf $$h /tmp/check-xdg.sock*
	@echo "--- a missing prod.keys must name the paths it tried ---"
	@h=$$(mktemp -d); \
	if XDG_CONFIG_HOME= HOME=$$h ./$(BIN) --radio-socket /tmp/check-nokeys.sock >$$h/out 2>&1; then \
	    echo "ERROR: started without any prod.keys"; rm -rf $$h; exit 1; \
	fi; \
	for p in prod.keys .config/switch_ldn/prod.keys .switch/prod.keys; do \
	    grep -q "$$p" $$h/out || { echo "ERROR: error message omits $$p"; cat $$h/out; rm -rf $$h; exit 1; }; \
	done; \
	echo "named all three"; rm -rf $$h /tmp/check-nokeys.sock*
	@echo "--- the driver patch is well formed and still touches 4 files ---"
	@n=$$(git apply --numstat patches/rtl8812au-linux-6.12.patch | wc -l); \
	[ "$$n" = 4 ] || { echo "ERROR: driver patch touches $$n files, expected 4"; exit 1; }; \
	echo "4 files, ok"
	@echo "--- build_rtl8812au.sh must reject a non-driver path ---"
	@if scripts/build_rtl8812au.sh /__no_such_dir >/dev/null 2>&1; then \
	    echo "ERROR: accepted a directory that is not a driver checkout"; exit 1; \
	else echo "correctly rejected"; fi
	@echo "--- removed options must stay removed ---"
	@for opt in --passphrase-hex --title-id --dump-adv --only; do \
	    if ./$(BIN) $$opt x --help 2>&1 | grep -q "unrecognized option"; then \
	        echo "  $$opt: removed"; \
	    else echo "  $$opt: STILL PRESENT"; exit 1; fi; \
	done


# ---------------------------------------------------------------------------
# Interop: real Ryubing-style client talking to the bridge's real transports.
# ---------------------------------------------------------------------------
build/bridge_harness: tests/bridge_harness.c $(BRIDGE_OBJS) | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -Isrc -o $@ $< $(BRIDGE_OBJS) $(LDLIBS)

# Source-based Eden/yuzu Room peer. Compiles on demand; never committed.
build/room_peer: tests/interop/room/room_peer.cpp tests/interop/room/packet.cpp \
                 tests/interop/room/packet.h tests/interop/room/common_types.h | $(OBJDIR)
	g++ -std=c++20 -O2 -Wall -Wextra -Itests/interop/room -o $@ \
	    tests/interop/room/room_peer.cpp tests/interop/room/packet.cpp -lzstd

interop: build/bridge_harness build/room_peer tests/interop/prod.keys
	@./build/bridge_harness >build/interop.log 2>&1 & bp=$$!; \
	  for i in $$(seq 1 50); do grep -q "HARNESS: ready" build/interop.log 2>/dev/null && break; sleep 0.1; done; \
	  echo "--- RyuLdn peer ---"; python3 tests/interop/ryu_peer.py; r1=$$?; \
	  echo "--- Room peer ---"; ./build/room_peer; r2=$$?; \
	  kill $$bp 2>/dev/null || true; wait $$bp 2>/dev/null || true; \
	  if [ $$r1 -eq 0 ] && [ $$r2 -eq 0 ]; then exit 0; else exit 1; fi

# ---------------------------------------------------------------------------
# Fake-console simulation. Drives the REAL binary (not the harness, whose radio
# is stubbed out) with --radio-socket, so the console -> bridge direction that
# `make interop` structurally cannot cover actually runs: the guest creates a
# network, and a fake console decrypts the advertisement, authenticates, and
# sends Pia traffic. Needs no NIC and no root.
# ---------------------------------------------------------------------------
# Both halves must pass: the console's own stages AND the peer's ProxyData
# check. Reading only the console's exit code let the peer's assertions fail
# silently, which is exactly the "asserted something adjacent" trap.
console-sim: $(BIN) tests/interop/prod.keys
	@sock=/tmp/ldn-console.sock; rm -f $$sock $$sock.console; \
	./$(BIN) --radio-socket $$sock --prodkeys tests/interop/prod.keys >build/console.log 2>&1 & bp=$$!; \
	for i in $$(seq 1 50); do [ -S $$sock ] && break; sleep 0.1; done; \
	[ -S $$sock ] || { echo "the bridge radio socket never appeared:"; cat build/console.log; exit 1; }; \
	python3 -u tests/interop/ryu_peer.py --hold --expect-proxy --send-proxy >build/console-ryu.log 2>&1 & rp=$$!; \
	sleep 2; \
	echo "--- fake console ---"; \
	python3 -u tests/interop/fake_console.py --socket $$sock --title-id 01006F8002320000; rc=$$?; \
	echo "--- the emulator side of that frame ---"; \
	wait $$rp 2>/dev/null || true; \
	grep -E "ProxyData|\\[PASS\\]|\\[FAIL\\]" build/console-ryu.log || true; \
	kill $$bp 2>/dev/null || true; wait $$bp 2>/dev/null || true; \
	rm -f $$sock $$sock.console; \
	if [ $$rc -ne 0 ]; then exit $$rc; fi; \
	if grep -q "\\[FAIL\\]" build/console-ryu.log; then \
	    echo "console-sim: the emulator-side check failed"; exit 1; fi; \
	exit 0


