# ---------------------------------------------------------------------------
# pxlview — PS5 kernel/HV inspector (read-only payload with on-screen UI)
#
#   make             -> build/pxlview-v$(VERSION).elf
#   make clean
#
# Requires: PS5_PAYLOAD_SDK (root scripts/bootstrap_sdk.sh)
# SDL2:     third_party/SDL2 (git submodule), built static by this Makefile
# ---------------------------------------------------------------------------

PS5_PAYLOAD_SDK ?= ../../sdk/ps5-payload-sdk
VERSION  ?= 0.1.0
BUILD    := build
ELF      := $(BUILD)/pxlview-v$(VERSION).elf
LATEST   := $(BUILD)/pxlview-latest.elf

SDL2_DIR := third_party/SDL2
SDL2_BLD := $(SDL2_DIR)/build-ps5
SDL2_A   := $(SDL2_BLD)/libSDL2.a

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined - run scripts/bootstrap_sdk.sh)
endif

# pxlview has no inline-asm single-stepping / HV hook, so -O2 is safe here
# (unlike the byepv-pxl payload which must stay -O0).
CFLAGS += -O2 -Wall -Werror -Wno-unused-parameter -Isrc
LDFLAGS += -L$(SDL2_BLD)

SRCS := src/main.c src/kmem.c src/panels.c src/console_ui.c src/notify.c

all: $(ELF)

# One-time static SDL2 build with the prospero toolchain. Flags mirror the
# port's tested build-scripts/ps5-payload-sdk.sh.
$(SDL2_A): $(SDL2_DIR)/CMakeLists.txt
	@echo "building static SDL2 (first time, takes a few minutes) ..."
	cmake -DCMAKE_BUILD_TYPE=Release -DSDL_OPENGL=YES -DSDL_LOADSO=YES \
	      -B $(SDL2_BLD) -S $(SDL2_DIR)
	$(MAKE) -C $(SDL2_BLD)

$(ELF): $(SRCS) $(SDL2_A)
	@mkdir -p $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(SDL2_A)
	ln -sf pxlview-v$(VERSION).elf $(LATEST)
	@echo "built: $@ (version=$(VERSION))"

clean:
	rm -rf $(BUILD)
	rm -rf $(SDL2_BLD)

.PHONY: all clean
