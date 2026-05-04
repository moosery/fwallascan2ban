# =============================================================================
# Makefile for fwallascan2ban
# =============================================================================

CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -g -D_GNU_SOURCE -I./include
LDFLAGS = -lcurl -lpcre2-8

SRCDIR  = src
INCDIR  = include
OBJDIR  = obj

# Daemon sources (everything except the client)
DAEMON_SRCS = $(SRCDIR)/fwallascan2ban.c \
              $(SRCDIR)/config.c \
              $(SRCDIR)/firewalla.c \
              $(SRCDIR)/logmon.c \
              $(SRCDIR)/filter.c \
              $(SRCDIR)/ignore.c

# Client sources
CLIENT_SRCS = $(SRCDIR)/fwallascan2ban-client.c

# Object files
DAEMON_OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(DAEMON_SRCS))
CLIENT_OBJS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(CLIENT_SRCS))

# Targets
DAEMON_BIN  = fwallascan2ban
CLIENT_BIN  = fwallascan2ban-client

# =============================================================================
# Default target - build everything
# =============================================================================
all: $(OBJDIR) $(DAEMON_BIN) $(CLIENT_BIN)

# =============================================================================
# Create obj directory if it doesn't exist
# =============================================================================
$(OBJDIR):
	mkdir -p $(OBJDIR)

# =============================================================================
# Build the daemon binary
# =============================================================================
$(DAEMON_BIN): $(DAEMON_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $(DAEMON_BIN)"

# =============================================================================
# Build the client binary
# =============================================================================
$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "Built $(CLIENT_BIN)"

# =============================================================================
# Compile source files to object files
# =============================================================================
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# =============================================================================
# Install - copy binaries and config to system locations
# =============================================================================
install: all
	@echo "Installing fwallascan2ban..."
	install -d /etc/fwallascan2ban
	install -d /var/lib/fwallascan2ban
	install -d /run/fwallascan2ban
	install -m 755 $(DAEMON_BIN) /usr/local/sbin/$(DAEMON_BIN)
	install -m 755 $(CLIENT_BIN) /usr/local/bin/$(CLIENT_BIN)
	@if [ ! -f /etc/fwallascan2ban/fwallascan2ban.conf ]; then \
		install -m 640 fwallascan2ban.conf.example /etc/fwallascan2ban/fwallascan2ban.conf; \
		echo "Installed default config to /etc/fwallascan2ban/fwallascan2ban.conf"; \
	else \
		echo "Config already exists, skipping /etc/fwallascan2ban/fwallascan2ban.conf"; \
	fi
	@if [ ! -f /etc/fwallascan2ban/fwallascan2ban.env ]; then \
		install -m 600 fwallascan2ban.env.example /etc/fwallascan2ban/fwallascan2ban.env; \
		echo "Installed default env file to /etc/fwallascan2ban/fwallascan2ban.env"; \
	else \
		echo "Env file already exists, skipping /etc/fwallascan2ban/fwallascan2ban.env"; \
	fi
	install -m 644 fwallascan2ban.service /etc/systemd/system/fwallascan2ban.service
	install -m 644 rsyslog-safeline.conf.example /etc/fwallascan2ban/rsyslog-safeline.conf.example
	systemctl daemon-reload
	@echo "Installation complete."
	@echo "Edit /etc/fwallascan2ban/fwallascan2ban.env with your MSP credentials."
	@echo "Edit /etc/fwallascan2ban/fwallascan2ban.conf to match your setup."
	@echo "Then run: systemctl enable --now fwallascan2ban"

# =============================================================================
# install-safeline - install the SafeLine WAF event poller
#
# Installs a Python polling script + systemd timer that fetches denied-IP
# events from the SafeLine open API every 60 seconds and writes them to
# /var/log/safeline-waf/attacks.log for fwallascan2ban to monitor.
#
# Prerequisites:
#   1. Add to /etc/fwallascan2ban/fwallascan2ban.env:
#        SAFELINE_API_TOKEN=<your SafeLine API token>
#        SAFELINE_HOST=<SafeLine VM IP>
#   2. Add [Log:safeline] section to /etc/fwallascan2ban/fwallascan2ban.conf
#      (see fwallascan2ban.conf.example for the full example)
#   3. Enable the timer:
#        systemctl enable --now safeline-poll.timer
#   4. Reload fwallascan2ban:
#        fwallascan2ban-client reload
# =============================================================================
install-safeline:
	@echo "Installing SafeLine WAF event poller..."
	install -d /var/log/safeline-waf
	install -m 755 safeline-poll /usr/local/sbin/safeline-poll
	install -m 644 safeline-poll.service /etc/systemd/system/safeline-poll.service
	install -m 644 safeline-poll.timer /etc/systemd/system/safeline-poll.timer
	systemctl daemon-reload
	@echo ""
	@echo "SafeLine poller installed. Next steps:"
	@echo "  1. Set in /etc/fwallascan2ban/fwallascan2ban.env:"
	@echo "       SAFELINE_API_TOKEN=<your token>"
	@echo "       SAFELINE_HOST=<SafeLine VM IP>"
	@echo "  2. Add [Log:safeline] to /etc/fwallascan2ban/fwallascan2ban.conf"
	@echo "       (see fwallascan2ban.conf.example)"
	@echo "  3. systemctl enable --now safeline-poll.timer"
	@echo "  4. fwallascan2ban-client reload"

# =============================================================================
# Uninstall - remove binaries and systemd service
# =============================================================================
uninstall:
	@echo "Uninstalling fwallascan2ban..."
	systemctl stop fwallascan2ban 2>/dev/null || true
	systemctl disable fwallascan2ban 2>/dev/null || true
	rm -f /usr/local/sbin/$(DAEMON_BIN)
	rm -f /usr/local/bin/$(CLIENT_BIN)
	rm -f /etc/systemd/system/fwallascan2ban.service
	systemctl daemon-reload
	@echo "Uninstall complete."
	@echo "Config and state files in /etc/fwallascan2ban and /var/lib/fwallascan2ban"
	@echo "have been preserved. Remove manually if desired."

# =============================================================================
# uninstall-safeline - remove SafeLine poller
# =============================================================================
uninstall-safeline:
	@echo "Uninstalling SafeLine WAF event poller..."
	systemctl stop safeline-poll.timer safeline-poll.service 2>/dev/null || true
	systemctl disable safeline-poll.timer 2>/dev/null || true
	rm -f /usr/local/sbin/safeline-poll
	rm -f /etc/systemd/system/safeline-poll.service
	rm -f /etc/systemd/system/safeline-poll.timer
	systemctl daemon-reload
	@echo "Uninstall complete."
	@echo "Log file /var/log/safeline-waf/attacks.log and state file"
	@echo "/var/lib/fwallascan2ban/safeline-poll.state preserved."

# =============================================================================
# Clean - remove build artifacts
# =============================================================================
clean:
	rm -rf $(OBJDIR) $(DAEMON_BIN) $(CLIENT_BIN)
	@echo "Cleaned build artifacts."

# =============================================================================
# Rebuild - clean then build
# =============================================================================
rebuild: clean all

# =============================================================================
# Debug build - extra debug flags
# =============================================================================
debug: CFLAGS += -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: all

# =============================================================================
# Declare phony targets
# =============================================================================
.PHONY: all clean rebuild install uninstall install-safeline uninstall-safeline debug
