TARGET_DIR=target
OUT_DIR=target/bin

all:


build:
	cargo build --release --target $(TARGET) --target-dir $(TARGET_DIR)
	mkdir -p $(OUT_DIR)
	cp $(TARGET_DIR)/$(TARGET)/release/theseus $(OUT_DIR)/theseus:$(TARGET)
	cp $(TARGET_DIR)/$(TARGET)/release/theseusg $(OUT_DIR)/theseusg:$(TARGET)

x86_64-unknown-linux-musl:
	$(MAKE) build TARGET=$@

aarch64-apple-darwin:
	$(MAKE) build TARGET=$@



clean:
	cargo clean
	rm -r $(TARGET_DIR)
