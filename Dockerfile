FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    dnsutils \
    wget \
    unzip \
    curl \
    ca-certificates \
    gcc \
    python3-dev \
    build-essential \
    git \
    procps \
    bsdextrautils \
    && rm -rf /var/lib/apt/lists/*

# Install SQLMap
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -s /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Install nuclei via binary (faster and more reliable) - v3.3.6 (supports -dast flag)
# v3.3.6 is the latest stable v3.3.x - avoids v3.4.x which produces 0 findings (BROKEN)
# Upgraded from v3.1.5 to enable DAST mode (headless browser scanning)
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.3.6/nuclei_3.3.6_linux_amd64.zip \
    && unzip nuclei_3.3.6_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.3.6_linux_amd64.zip README.md LICENSE.md \
    && nuclei -version \
    && nuclei -update-templates || echo "Template update skipped"

# Install katana web crawler (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        KATANA_ARCH="arm64"; \
    else \
        KATANA_ARCH="amd64"; \
    fi && \
    wget https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_${KATANA_ARCH}.zip \
    && unzip katana_1.1.0_linux_${KATANA_ARCH}.zip \
    && mv katana /usr/local/bin/ \
    && rm katana_1.1.0_linux_${KATANA_ARCH}.zip README.md LICENSE.md \
    && chmod +x /usr/local/bin/katana

# Install dirsearch web directory brute forcer
RUN pip install dirsearch

# Install Dalfox XSS scanner (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        DALFOX_ARCH="arm64"; \
    else \
        DALFOX_ARCH="amd64"; \
    fi && \
    wget https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_${DALFOX_ARCH}.tar.gz \
    && tar xzf dalfox_2.9.3_linux_${DALFOX_ARCH}.tar.gz \
    && mv dalfox /usr/local/bin/ \
    && rm -f dalfox_2.9.3_linux_${DALFOX_ARCH}.tar.gz LICENSE README.md \
    && chmod +x /usr/local/bin/dalfox

# Install testssl.sh TLS scanner
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl \
    && ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl \
    && chmod +x /opt/testssl/testssl.sh

# Install Commix command injection scanner (from official GitHub, not pip)
RUN git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix \
    && ln -s /opt/commix/commix.py /usr/local/bin/commix \
    && chmod +x /opt/commix/commix.py

# Install subfinder subdomain enumeration (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        SUBFINDER_ARCH="arm64"; \
    else \
        SUBFINDER_ARCH="amd64"; \
    fi && \
    wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.7/subfinder_2.6.7_linux_${SUBFINDER_ARCH}.zip \
    && unzip subfinder_2.6.7_linux_${SUBFINDER_ARCH}.zip \
    && mv subfinder /usr/local/bin/ \
    && rm -f subfinder_2.6.7_linux_${SUBFINDER_ARCH}.zip README.md LICENSE.md \
    && chmod +x /usr/local/bin/subfinder

# Install ffuf web fuzzer (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then FFUF_ARCH="arm64"; else FFUF_ARCH="amd64"; fi && \
    wget https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_${FFUF_ARCH}.tar.gz \
    && tar xzf ffuf_2.1.0_linux_${FFUF_ARCH}.tar.gz && mv ffuf /usr/local/bin/ \
    && rm -f ffuf_2.1.0_linux_${FFUF_ARCH}.tar.gz CHANGELOG.md LICENSE README.md \
    && chmod +x /usr/local/bin/ffuf

# Install default wordlist for ffuf web fuzzer
RUN mkdir -p /usr/share/wordlists/dirb && \
    wget -q https://raw.githubusercontent.com/v0re/dirb/master/wordlists/common.txt -O /usr/share/wordlists/dirb/common.txt

# Install CORScanner CORS misconfiguration scanner
RUN git clone --depth 1 https://github.com/chenjj/CORScanner.git /opt/CORScanner && \
    cd /opt/CORScanner && pip install -r requirements.txt

# Install crlfuzz CRLF injection scanner (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then CRLF_ARCH="arm64"; else CRLF_ARCH="amd64"; fi && \
    wget https://github.com/dwisiswant0/crlfuzz/releases/download/v1.4.1/crlfuzz_1.4.1_linux_${CRLF_ARCH}.tar.gz \
    && tar xzf crlfuzz_1.4.1_linux_${CRLF_ARCH}.tar.gz && mv crlfuzz /usr/local/bin/ \
    && rm -f crlfuzz_1.4.1_linux_${CRLF_ARCH}.tar.gz LICENSE README.md \
    && chmod +x /usr/local/bin/crlfuzz

# Install waybackurls URL discovery (Go build - no arm64 binary release available)
RUN ARCH=$(dpkg --print-architecture) && \
    GO_VERSION="1.22.5" && \
    if [ "$ARCH" = "arm64" ]; then GO_ARCH="arm64"; else GO_ARCH="amd64"; fi && \
    wget https://dl.google.com/go/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    rm go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    /usr/local/go/bin/go install github.com/tomnomnom/waybackurls@latest && \
    mv /root/go/bin/waybackurls /usr/local/bin/ && \
    rm -rf /usr/local/go /root/go && \
    chmod +x /usr/local/bin/waybackurls

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install httpx HTTP probe AFTER pip install (pip's httpx Python package creates
# a wrapper at /usr/local/bin/httpx that would overwrite the Go binary)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then \
        HTTPX_ARCH="arm64"; \
    else \
        HTTPX_ARCH="amd64"; \
    fi && \
    wget https://github.com/projectdiscovery/httpx/releases/download/v1.6.9/httpx_1.6.9_linux_${HTTPX_ARCH}.zip \
    && unzip httpx_1.6.9_linux_${HTTPX_ARCH}.zip \
    && mv httpx /usr/local/bin/ \
    && rm -f httpx_1.6.9_linux_${HTTPX_ARCH}.zip README.md LICENSE.md \
    && chmod +x /usr/local/bin/httpx

# Install Playwright browsers (Phase 2: Scripted browser login)
# Note: Using default browser path, not custom PLAYWRIGHT_BROWSERS_PATH
RUN NODE_TLS_REJECT_UNAUTHORIZED=0 playwright install chromium --with-deps

# Symlink Playwright's Chromium so GoWitness and other tools can find it as google-chrome
RUN CHROME_PATH=$(find /root/.cache/ms-playwright -path '*/chrome-linux/chrome' -type f 2>/dev/null | head -1) && \
    if [ -n "$CHROME_PATH" ]; then \
        ln -sf "$CHROME_PATH" /usr/local/bin/google-chrome; \
    else \
        CHROME_PATH=$(find /root/.cache/ms-playwright -name 'chrome' -type f 2>/dev/null | head -1) && \
        if [ -n "$CHROME_PATH" ]; then ln -sf "$CHROME_PATH" /usr/local/bin/google-chrome; fi; \
    fi && \
    echo "Chrome symlink: $(ls -la /usr/local/bin/google-chrome 2>/dev/null || echo 'NOT FOUND')"

# Install GoWitness screenshot tool (architecture-aware)
RUN ARCH=$(dpkg --print-architecture) && \
    if [ "$ARCH" = "arm64" ]; then GOWITNESS_ARCH="arm64"; else GOWITNESS_ARCH="amd64"; fi && \
    wget -q https://github.com/sensepost/gowitness/releases/download/3.0.5/gowitness-3.0.5-linux-${GOWITNESS_ARCH} \
    -O /usr/local/bin/gowitness && \
    chmod +x /usr/local/bin/gowitness

# Install Arjun parameter discovery
RUN pip install arjun

# Install Node.js and npm (required for Origami MCP server)
RUN apt-get update && \
    apt-get install -y --no-install-recommends nodejs npm && \
    rm -rf /var/lib/apt/lists/* && \
    ln -sf "$(which nodejs)" /usr/local/bin/node && \
    node --version && npm --version

# Install Origami Chrome extension + MCP server for headless browser DAST
RUN git clone --depth 1 https://github.com/iamveene/origami.git /opt/origami && \
    rm -rf /opt/origami/.git && \
    cd /opt/origami/mcp-server && npm install --production

# Patch Origami extension: auto-enable MCP bridge with fixed auth token
# In headless mode, chrome.storage.sync is empty so DEFAULT_SETTINGS is used directly
# bridge.js already supports ORIGAMI_WS_TOKEN env var for token override
RUN sed -i '/mcpBridge: {/{n;s/enabled: false/enabled: true/}' /opt/origami/background.js && \
    sed -i "s|wsUrl: 'ws://127.0.0.1:9340'|wsUrl: 'ws://127.0.0.1:9340',\n    wsToken: 'xasm-origami-bridge-token'|" /opt/origami/background.js && \
    echo "Patched background.js: MCP bridge enabled with fixed token"

# Patch manifest.json: Add "tabs" permission so chrome.tabs.query returns tab URLs
# (extension only has "activeTab" which hides URLs from query results in headless mode)
RUN python3 -c "\
import json; f='/opt/origami/manifest.json'; m=json.load(open(f)); \
perms=m.setdefault('permissions',[]); \
[perms.append(p) for p in ['tabs'] if p not in perms]; \
json.dump(m,open(f,'w'),indent=2); \
print('Patched manifest.json: added tabs permission')"

# Patch mcp-bridge.js: _getActiveTab() fails in headless mode because
# chrome.tabs.query({active:true, currentWindow:true}) returns empty (no "current window").
# Fallback: query ALL tabs and pick the first one with an http(s) URL.
RUN python3 -c "\
f='/opt/origami/mcp-bridge.js'; s=open(f).read(); \
old='const tabs = await chrome.tabs.query({ active: true, currentWindow: true });'; \
new='let tabs = await chrome.tabs.query({ active: true, currentWindow: true }); if (!tabs.length) { tabs = (await chrome.tabs.query({})).filter(t => t.url && t.url.startsWith(\"http\")); }'; \
s=s.replace(old, new, 1); open(f,'w').write(s); \
print('Patched _getActiveTab in mcp-bridge.js for headless mode')"

# Pre-configure MCP auth token file (matches ORIGAMI_WS_TOKEN env var used at runtime)
RUN mkdir -p /root/.origami-mcp && \
    echo -n "xasm-origami-bridge-token" > /root/.origami-mcp/ws-token

# Install whois and numpy for brand monitoring enrichment and screenshot entropy
RUN apt-get update && apt-get install -y whois python3-numpy && rm -rf /var/lib/apt/lists/*

# Copy agent code
COPY . .

# Run agent via entrypoint (updates nuclei templates on startup)
CMD ["./entrypoint.sh"]
