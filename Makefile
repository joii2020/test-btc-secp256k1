TARGET := riscv64-unknown-linux-gnu
CC := $(TARGET)-gcc
LD := $(TARGET)-gcc
OBJCOPY := $(TARGET)-objcopy

CFLAGS := -fPIC -g -O0 \
	-nostdinc -nostdlib -nostartfiles \
	-fno-builtin-printf -fno-builtin-memcmp \
	-fvisibility=hidden -fdata-sections -ffunction-sections \
	-I deps/ckb-c-stdlib \
	-I deps/ckb-c-stdlib/libc \
	-I deps/ckb-c-stdlib/molecule \
	-I deps/secp256k1/src \
	-I deps/secp256k1
LDFLAGS := -Wl,-static -fdata-sections -ffunction-sections -Wl,--gc-sections

all: ckb_verify

BUILDER_DOCKER := nervos/ckb-riscv-gnu-toolchain@sha256:aae8a3f79705f67d505d1f1d5ddc694a4fd537ed1c7e9622420a470d59ba2ec3

all-via-docker: ${PROTOCOL_HEADER}
	docker run --rm -v `pwd`:/code ${BUILDER_DOCKER} bash -c "cd /code && make"

ckb_verify: ckb_verify.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $<
	cp $@ $@.debug
	$(OBJCOPY) --strip-debug --strip-all $@
	ls -lah $@

run: 
	ckb-debugger --bin ckb_verify

clean:
	rm -rf ckb_verify ckb_verify.debug
