CC      ?= gcc
CFLAGS  ?= -O2 -g -std=gnu11 -Wall -Wextra -Wno-unused-parameter
# OpenSSL 3 deprecates the low-level AES API; the EVP layer needs more plumbing for now.
CFLAGS  += -Wno-deprecated-declarations
CPPFLAGS = -D_GNU_SOURCE
LDLIBS   = -lcrypto

SRCDIR := src
OBJDIR := build
BIN    := switch_ldn

SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))
TEST_OBJS := build/crypto.o build/ldn.o build/ryuldn.o build/room.o build/radio.o build/util.o

.PHONY: all clean check test

all: $(BIN)

$(BIN): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(BIN)

# ---------------------------------------------------------------------------
# Tests. All of them are socket-level and need no radio hardware.
# ---------------------------------------------------------------------------
test: $(TEST_OBJS)
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

# ---------------------------------------------------------------------------
# CLI smoke test, also without radio hardware.
# ---------------------------------------------------------------------------
check: $(BIN)
	./$(BIN) --help
	@echo "--- selfcheck on loopback (expected: unknown mode) ---"
	./$(BIN) --selfcheck lo || true
	@echo "--- live mode must refuse to start without --ap-iface ---"
	@if ./$(BIN) --prodkeys /dev/null >/dev/null 2>&1; then \
	    echo "ERROR: should have failed"; exit 1; \
	else echo "correctly refused"; fi
	@echo "--- removed options must stay removed ---"
	@for opt in --passphrase-hex --title-id --dump-adv --only; do \
	    if ./$(BIN) $$opt x --help 2>&1 | grep -q "unrecognized option"; then \
	        echo "  $$opt: removed"; \
	    else echo "  $$opt: STILL PRESENT"; exit 1; fi; \
	done
