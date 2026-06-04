APP := netpulse_server
BUILD_DIR := build
SRC := src/netpulse_server.c

CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
CPPFLAGS ?=
LDFLAGS ?=
LDLIBS ?= -lpcap -lpthread
PREFIX ?= /usr/local/netpulse

.PHONY: all clean install package openwrt-dynamic package-openwrt

all: $(BUILD_DIR)/$(APP)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/$(APP): $(SRC) | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

openwrt-dynamic: | $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)/openwrt
	$(CC) $(CPPFLAGS) $(CFLAGS) -DNETPULSE_DYNAMIC_PCAP -o $(BUILD_DIR)/openwrt/$(APP) $(SRC) $(LDFLAGS) -lpthread -ldl

install: all
	install -d $(DESTDIR)$(PREFIX)/web
	install -d $(DESTDIR)$(PREFIX)/scripts
	install -m 0755 $(BUILD_DIR)/$(APP) $(DESTDIR)$(PREFIX)/$(APP)
	install -m 0644 web/index.html web/style.css web/app.js $(DESTDIR)$(PREFIX)/web/
	install -m 0755 scripts/firewall.sh $(DESTDIR)$(PREFIX)/scripts/

package: all
	rm -rf $(BUILD_DIR)/netpulse-openwrt
	mkdir -p $(BUILD_DIR)/netpulse-openwrt
	cp -r $(BUILD_DIR)/$(APP) web scripts docs README.md Makefile $(BUILD_DIR)/netpulse-openwrt/
	tar -C $(BUILD_DIR) -czf $(BUILD_DIR)/netpulse-openwrt.tar.gz netpulse-openwrt

package-openwrt: openwrt-dynamic
	rm -rf $(BUILD_DIR)/netpulse-openwrt-upload
	mkdir -p $(BUILD_DIR)/netpulse-openwrt-upload
	cp $(BUILD_DIR)/openwrt/$(APP) $(BUILD_DIR)/netpulse-openwrt-upload/
	cp -r web scripts README.md docs $(BUILD_DIR)/netpulse-openwrt-upload/
	tar -C $(BUILD_DIR) -czf $(BUILD_DIR)/netpulse-openwrt-upload.tar.gz netpulse-openwrt-upload

clean:
	rm -rf $(BUILD_DIR)
