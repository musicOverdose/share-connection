# 🚀 share-connection

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20BSD-orange.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20StdLib)-purple.svg)]()

> **Universal Connection Sharing Proxy (PdaNet / EveryProxy Style)**
> Instantly share whatever VPN, proxy, or direct connection your PC is using with your iPhone, Android, or any device on your Wi-Fi network.

---

## 🌟 Highlights & Features

- **⚡ Zero Dependencies**: Pure Python 3 standard library. No `pip install`, no root/sudo required.
- **🔄 Universal Multi-VPN Auto-Detection**:
  - **Local Proxy Mode**: Automatically detects and forwards through **FlClash**, **Clash Verge**, **Mihomo**, or **Sing-box** (`127.0.0.1:7890`) or **Xray/V2Ray** (`127.0.0.1:10809`).
  - **System VPN Tunnel Mode**: Automatically routes through **OpenVPN** (`tun0`), **WireGuard** (`wg0`), **Tailscale**, or **AmneziaWG**.
  - **Direct Mode**: Fallback to physical network interface if no VPN is running.
- **🍏 Apple iOS & iPhone Optimizations**:
  - **Captive Portal Instant Validation**: Immediately returns `200 Success` for Apple captive checks (`captive.apple.com`). iOS will never show "No Internet Connection" or drop Wi-Fi!
  - **iCloud Private Relay Unblocker**: Gracefully informs iOS that Private Relay is not supported on proxy networks (`503`), preventing Safari from freezing or stalling.
- **💬 WhatsApp In-App Proxy & Raw TLS SNI Support**:
  - Works via standard iOS Wi-Fi Manual Proxy.
  - Also works via **WhatsApp In-App Proxy** (*Settings → Storage and Data → Proxy*) with automatic Server Name Indication (SNI) routing.
- **🚀 High-Performance Non-Blocking Streaming**:
  - Full bidirectional multiplexing using `select` with proper TCP half-close (`shutdown(SHUT_WR)`).
  - Preserves early handshake bytes, zero truncated downloads, zero dropped packets.
- **🛡️ Pure IPv4 DNS Resolution**:
  - Eliminates the 10–15s IPv6 blackhole timeouts common when tunneling across VPNs.
- **⚙️ Flexible Port Configuration**:
  - Specify any port on the fly (e.g., `share-connection 8888`), with automatic port conflict detection and fallback.

---

## 📥 Quick Install

### One-Liner (Linux / macOS):
```bash
curl -fsSL https://raw.githubusercontent.com/musicOverdose/share-connection/main/install.sh | bash
```

### Manual Install:
```bash
git clone https://github.com/musicOverdose/share-connection.git
cd share-connection
chmod +x share_connection.py
mkdir -p ~/.local/bin
ln -sf $(pwd)/share_connection.py ~/.local/bin/share-connection
```

---

## 🚀 Usage

Simply run:
```bash
share-connection
```

To specify a custom port:
```bash
share-connection 8888
# or
share-connection -p 9090
```

To force a specific routing mode:
```bash
share-connection --flclash    # Force FlClash / Clash (127.0.0.1:7890)
share-connection --vpn        # Force System VPN (tun0 / wg0)
share-connection --direct     # Force Direct physical network
```

### Interactive Output

```
====================================================================
  🚀 UNIVERSAL CONNECTION SHARING ACTIVE v1.0.0 (PdaNet Style)
====================================================================
  📱 CONFIGURE YOUR PHONE:

     [Method 1 - Standard iPhone Wi-Fi Proxy]
       • Server (IP) :  192.168.1.104
       • Port        :  8080

     [Method 2 - WhatsApp In-App Proxy (Settings -> Storage -> Proxy)]
       • Proxy IP    :  192.168.1.104
       • Chat Port   :  8080
--------------------------------------------------------------------
  ℹ️  SYSTEM ROUTING STATE:
     Active Mode : Auto -> FlClash (127.0.0.1:7890) Active
     FlClash 7890: 🟢 Listening
     System VPN  : 🟢 tun0
     Exit Status : Detecting public IP in background...
====================================================================
  🟢 Ready & forwarding! Live phone traffic will appear below:
  🛑 Press [Ctrl+C] anytime to stop sharing.

  🌍 VERIFIED LAPTOP EXIT IP: 185.53.231.234 (Bishkek, KG - AS29061)

  📱 [192.168.1.101] CAPTIVE Instant Success (Apple Check)
  📱 [192.168.1.101] RELAY-BYPASS gateway.icloud.com:443 (Unblocked Safari)
  📱 [192.168.1.101] CONNECT web.whatsapp.com:443 [FlClash (7890)]
```

---

## 📱 Client Setup Guide

### 🍎 iPhone / iPad (iOS)

#### Method 1: Wi-Fi Manual Proxy (All Apps & Safari)
1. Open **Settings** ➔ **Wi-Fi** ➔ Tap your connected network **(i)**.
2. Scroll to the bottom and tap **Configure Proxy** ➔ Select **Manual**.
3. Enter:
   - **Server**: Your laptop IP (e.g. `192.168.1.104`)
   - **Port**: The port shown by the script (default `8080`)
   - **Authentication**: Leave OFF.
4. Tap **Save** in the top right.

#### Method 2: WhatsApp In-App Proxy (For OTPs & Messaging)
1. Open **WhatsApp** ➔ **Settings** ➔ **Storage and Data** ➔ **Proxy**.
2. Toggle **Use Proxy** ON.
3. Tap **Set Proxy**:
   - **Proxy IP**: Your laptop IP (e.g. `192.168.1.104`)
   - **Chat Port**: `8080` (or your configured port)
4. Tap **Save**. The status will display **Connected**.

---

### 🤖 Android
1. Open **Settings** ➔ **Network & internet** ➔ **Wi-Fi**.
2. Tap the settings gear `⚙️` or long-press your Wi-Fi network ➔ **Modify network**.
3. Under **Advanced options**, set **Proxy** to **Manual**.
4. Enter your laptop IP and Port. Tap **Save**.

---

## 📄 License

This project is open-sourced under the [MIT License](LICENSE).
Made with ❤️ by [Farzad](https://github.com/musicOverdose).
