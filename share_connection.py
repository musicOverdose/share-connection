#!/usr/bin/env python3
"""
Universal Connection Sharing Proxy (PdaNet / EveryProxy Style)
https://github.com/musicOverdose/share-connection

Author: Farzad (musicOverdose)
License: MIT

Shares whatever VPN or internet connection your PC is using with your phone / other devices.
Zero dependencies — pure Python 3 standard library.
"""

import sys
import os
import socket
import select
import threading
import argparse
import subprocess
import urllib.request
import json
import time
import struct

VERSION = "1.1.0"
DEFAULT_PORT = 8080
FLCLASH_PORT = 7890
XRAY_PORT = 10809
BUFFER_SIZE = 65536
CONNECT_TIMEOUT = 12
IDLE_TIMEOUT = 120

APPLE_RELAY_DOMAINS = (
    "mask.icloud.com",
    "mask-h2.icloud.com",
    "mask-api.icloud.com",
    "gateway.icloud.com",
)

APPLE_CAPTIVE_DOMAINS = (
    "captive.apple.com",
    "hotspot-detect.html",
    "library/test/success.html",
)

GOOGLE_204_DOMAINS = (
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
)

def get_local_ip():
    """Detect the laptop local Wi-Fi / LAN IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.168.1.1', 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def check_port(host, port, timeout=0.25):
    """Check if a TCP port is open and listening."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def find_available_port(preferred_port):
    """Find preferred port or search for the next free port."""
    for p in range(preferred_port, preferred_port + 25):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except OSError:
            continue
    return preferred_port

def get_active_vpn_interface():
    """Check if an active VPN tunnel interface (tun, wg, ppp) is default route."""
    try:
        out = subprocess.check_output(['ip', 'route'], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.startswith('default'):
                parts = line.split()
                if 'dev' in parts:
                    idx = parts.index('dev') + 1
                    dev = parts[idx]
                    if any(dev.startswith(p) for p in ['tun', 'wg', 'ppp', 'amnezia']):
                        return dev
    except Exception:
        pass
    return None

def fetch_exit_status(flclash_active=False):
    """Fetch exit IP and location details with fast fallbacks."""
    proxy_url = f"http://127.0.0.1:{FLCLASH_PORT}" if flclash_active else None
    handlers = []
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}))
    opener = urllib.request.build_opener(*handlers)

    # 1. Fast check via api.ipify.org
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/8.0"})
        with opener.open(req, timeout=5) as resp:
            ip = resp.read().decode().strip()
            if ip:
                try:
                    req_d = urllib.request.Request(f"https://ipinfo.io/{ip}/json", headers={"User-Agent": "curl/8.0"})
                    with opener.open(req_d, timeout=3) as resp_d:
                        data = json.loads(resp_d.read().decode())
                        return f"{ip} ({data.get('city', '')}, {data.get('country', '')} - {data.get('org', '')})"
                except Exception:
                    return f"{ip} (Active Exit)"
    except Exception:
        pass

    # 2. Check via ipinfo.io
    try:
        req = urllib.request.Request("https://ipinfo.io/json", headers={"User-Agent": "curl/8.0"})
        with opener.open(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            ip = data.get("ip", "")
            return f"{ip} ({data.get('city', '')}, {data.get('country', '')} - {data.get('org', '')})"
    except Exception:
        pass

    return "Connected (Exit verified)"

def parse_sni(data):
    """Extract SNI hostname from TLS ClientHello packet."""
    if len(data) < 43 or data[0] != 0x16 or data[5] != 0x01:
        return None
    try:
        session_id_len = data[43]
        pos = 44 + session_id_len
        cipher_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2 + cipher_len
        comp_len = data[pos]
        pos += 1 + comp_len
        ext_total_len = int.from_bytes(data[pos:pos+2], 'big')
        pos += 2
        end = pos + ext_total_len
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos+2], 'big')
            ext_len = int.from_bytes(data[pos+2:pos+4], 'big')
            pos += 4
            if ext_type == 0:  # SNI
                sni_len = int.from_bytes(data[pos+3:pos+5], 'big')
                return data[pos+5:pos+5+sni_len].decode('utf-8', errors='ignore')
            pos += ext_len
    except Exception:
        return None
    return None

def resolve_ipv4(host, port):
    """Resolve domain to IPv4 to prevent IPv6 blackhole timeouts."""
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4]
    except Exception:
        pass
    return None

def tunnel(client, remote, leftover=b'', timeout=IDLE_TIMEOUT):
    """
    High-performance non-blocking bidirectional streaming.
    Handles TCP half-close, leftover handshake bytes, and inactivity timeout.
    """
    if leftover:
        try:
            client.sendall(leftover)
        except Exception:
            return

    client.setblocking(False)
    remote.setblocking(False)

    sockets = [client, remote]
    last_active = time.time()
    client_closed = False
    remote_closed = False

    while sockets:
        r, _, _ = select.select(sockets, [], [], 1.0)
        if not r:
            if time.time() - last_active > timeout:
                break
            continue

        last_active = time.time()
        for s in r:
            try:
                data = s.recv(BUFFER_SIZE)
            except Exception:
                data = b""

            if s is client:
                if not data:
                    client_closed = True
                    if client in sockets:
                        sockets.remove(client)
                    try:
                        remote.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                    if remote_closed:
                        return
                else:
                    try:
                        remote.sendall(data)
                    except Exception:
                        return
            else:  # remote
                if not data:
                    remote_closed = True
                    if remote in sockets:
                        sockets.remove(remote)
                    try:
                        client.shutdown(socket.SHUT_WR)
                    except Exception:
                        pass
                    if client_closed:
                        return
                else:
                    try:
                        client.sendall(data)
                    except Exception:
                        return

def connect_upstream(host, port, forced_mode='auto'):
    """
    Connect to upstream target directly or via local proxy.
    Returns (socket, route_label, leftover_bytes)
    """
    use_flclash = False
    if forced_mode == 'flclash':
        use_flclash = True
    elif forced_mode in ('direct', 'vpn'):
        use_flclash = False
    else:  # auto mode
        use_flclash = check_port('127.0.0.1', FLCLASH_PORT)

    if use_flclash:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect(('127.0.0.1', FLCLASH_PORT))

        connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: Keep-Alive\r\n\r\n".encode()
        s.sendall(connect_req)

        res_data = b""
        while b"\r\n\r\n" not in res_data:
            chunk = s.recv(4096)
            if not chunk:
                break
            res_data += chunk

        idx = res_data.find(b"\r\n\r\n")
        if idx == -1:
            s.close()
            raise RuntimeError(f"FlClash closed connection for {host}:{port}")

        status_line = res_data[:idx].split(b"\r\n")[0].decode(errors='ignore')
        if "200" not in status_line:
            s.close()
            raise RuntimeError(f"FlClash rejected connection: {status_line}")

        leftover = res_data[idx + 4:]
        s.settimeout(None)
        return s, 'FlClash (7890)', leftover
    else:
        target_addr = resolve_ipv4(host, port)
        if not target_addr:
            target_addr = (host, port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect(target_addr)
        s.settimeout(None)
        vpn_dev = get_active_vpn_interface()
        mode_label = f"VPN ({vpn_dev})" if vpn_dev else "Direct"
        return s, mode_label, b""

def handle_socks5(client_sock, client_addr, peek_data, forced_mode='auto'):
    """Handle SOCKS5 proxy handshake (Used by Telegram, Outline, SOCKS5 clients)."""
    remote_sock = None
    try:
        # SOCKS5 greeting: client sends [VER=0x05, NMETHODS, METHODS...]
        # Reply No Authentication required: [VER=0x05, METHOD=0x00]
        client_sock.sendall(b"\x05\x00")

        # Read SOCKS5 connection request
        req = client_sock.recv(512)
        if len(req) < 7 or req[0] != 0x05 or req[1] != 0x01:
            return

        atyp = req[3]
        if atyp == 1:  # IPv4
            host = socket.inet_ntoa(req[4:8])
            port = struct.unpack("!H", req[8:10])[0]
        elif atyp == 3:  # Domain
            dlen = req[4]
            host = req[5:5+dlen].decode('utf-8', errors='ignore')
            port = struct.unpack("!H", req[5+dlen:5+dlen+2])[0]
        elif atyp == 4:  # IPv6
            host = socket.inet_ntop(socket.AF_INET6, req[4:20])
            port = struct.unpack("!H", req[20:22])[0]
        else:
            return

        remote_sock, route_mode, leftover = connect_upstream(host, port, forced_mode)
        try:
            remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        # Send SOCKS5 success reply: [VER=0x05, REP=0x00, RSV=0x00, ATYP=0x01, BND.ADDR=0.0.0.0, BND.PORT=0]
        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[36m✈️ SOCKS5\033[0m {host}:{port} \033[36m[{route_mode}]\033[0m")
        sys.stdout.flush()

        tunnel(client_sock, remote_sock, leftover=leftover)
    except Exception:
        pass
    finally:
        for s in (client_sock, remote_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass

def handle_client(client_sock, client_addr, forced_mode='auto'):
    remote_sock = None
    try:
        try:
            client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        client_sock.settimeout(15)
        peek_data = client_sock.recv(4096)
        if not peek_data:
            return

        # Case 1: SOCKS5 Protocol (Telegram Proxy, Outline, SOCKS5 clients)
        if peek_data[0] == 0x05:
            handle_socks5(client_sock, client_addr, peek_data, forced_mode)
            return

        # Case 2: Raw TLS Handshake (WhatsApp In-App Proxy or direct TLS)
        if peek_data[0] == 0x16:
            sni = parse_sni(peek_data) or "g.whatsapp.net"
            remote_sock, route_mode, leftover = connect_upstream(sni, 443, forced_mode)
            try:
                remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass
            remote_sock.sendall(peek_data)
            print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[35mTLS/SNI\033[0m {sni}:443 \033[36m[{route_mode}]\033[0m")
            sys.stdout.flush()
            tunnel(client_sock, remote_sock, leftover=leftover)
            return

        first_line = peek_data.split(b"\r\n")[0].decode(errors="ignore")
        parts = first_line.split()
        if len(parts) < 2:
            return

        method, target = parts[0], parts[1]

        # Case 2: Apple Captive Portal Instant Validation
        if any(d in target for d in APPLE_CAPTIVE_DOMAINS):
            if method == "GET":
                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 68\r\n"
                    b"Connection: close\r\n\r\n"
                    b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"
                )
                client_sock.sendall(resp)
                print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[33mCAPTIVE\033[0m Instant Success (Apple Check)")
                sys.stdout.flush()
                return

        # Case 3: Google 204 Connectivity Check
        if any(d in target for d in GOOGLE_204_DOMAINS):
            if method == "GET":
                resp = b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"
                client_sock.sendall(resp)
                print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[33m204-CHECK\033[0m Instant Success (Google Check)")
                sys.stdout.flush()
                return

        # Case 4: HTTPS CONNECT
        if method == "CONNECT":
            if ":" in target:
                host, port_str = target.split(":")
                port = int(port_str)
            else:
                host = target
                port = 443

            # Apple iCloud Private Relay Ingress Bypass:
            # Returning 503 instructs iOS that Private Relay is not supported on this network,
            # prompting iOS to gracefully fall back to direct proxy traffic. This unblocks Safari!
            if any(host.endswith(d) for d in APPLE_RELAY_DOMAINS):
                client_sock.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[33mRELAY-BYPASS\033[0m {host}:{port} \033[90m(Unblocked Safari)\033[0m")
                sys.stdout.flush()
                return

            remote_sock, route_mode, leftover = connect_upstream(host, port, forced_mode)
            try:
                remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

            client_sock.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[32mCONNECT\033[0m {host}:{port} \033[36m[{route_mode}]\033[0m")
            sys.stdout.flush()
            tunnel(client_sock, remote_sock, leftover=leftover)

        # Case 5: Plain HTTP request
        else:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target.split(":")[0]
            port = parsed.port or 80
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query

            remote_sock, route_mode, leftover = connect_upstream(host, port, forced_mode)
            try:
                remote_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

            if 'FlClash' in route_mode:
                remote_sock.sendall(peek_data)
            else:
                new_req = peek_data.replace(target.encode(), path.encode(), 1)
                new_req = new_req.replace(b"Proxy-Connection:", b"Connection:")
                remote_sock.sendall(new_req)

            print(f"  \033[90m📱 [{client_addr[0]}]\033[0m \033[34m{method}\033[0m {host}:{port}{path} \033[36m[{route_mode}]\033[0m")
            sys.stdout.flush()
            tunnel(client_sock, remote_sock, leftover=leftover)

    except Exception:
        pass
    finally:
        for s in (client_sock, remote_sock):
            if s:
                try:
                    s.close()
                except Exception:
                    pass

def main():
    parser = argparse.ArgumentParser(
        description="Universal Connection Sharing Proxy (PdaNet Style) — Share your PC VPN/Internet with your phone."
    )
    parser.add_argument("port_pos", nargs="?", type=int, default=None,
                        help=f"Port to listen on (e.g. 8080, 8888, 9090)")
    parser.add_argument("--port", "-p", type=int, default=None,
                        help=f"Port to listen on (default: {DEFAULT_PORT})")
    parser.add_argument("--mode", "-m", choices=['auto', 'flclash', 'vpn', 'direct'], default='auto',
                        help="Routing mode: auto (default), flclash, vpn, direct")
    parser.add_argument("--flclash", action="store_true", help="Force routing via FlClash (127.0.0.1:7890)")
    parser.add_argument("--vpn", action="store_true", help="Force routing via system VPN (tun0/wg0)")
    parser.add_argument("--version", "-v", action="version", version=f"share-connection v{VERSION}")
    args = parser.parse_args()

    requested_port = args.port_pos or args.port or DEFAULT_PORT
    actual_port = find_available_port(requested_port)
    port_switched = (actual_port != requested_port)

    forced_mode = 'auto'
    if args.flclash:
        forced_mode = 'flclash'
    elif args.vpn:
        forced_mode = 'vpn'
    elif args.mode != 'auto':
        forced_mode = args.mode

    local_ip = get_local_ip()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", actual_port))
    except OSError as e:
        print(f"\033[1;31mError: Unable to bind to port {actual_port}: {e}\033[0m")
        sys.exit(1)

    server.listen(512)

    flclash_up = check_port('127.0.0.1', FLCLASH_PORT)
    vpn_dev = get_active_vpn_interface()

    if forced_mode == 'flclash':
        active_mode_str = "Forced FlClash (127.0.0.1:7890)"
    elif forced_mode == 'vpn':
        active_mode_str = f"Forced System VPN ({vpn_dev or 'tun0'})"
    elif forced_mode == 'direct':
        active_mode_str = "Forced Direct (Physical Interface)"
    else:
        if flclash_up:
            active_mode_str = "Auto -> FlClash (127.0.0.1:7890) Active"
        elif vpn_dev:
            active_mode_str = f"Auto -> System VPN ({vpn_dev} - OpenVPN/WireGuard) Active"
        else:
            active_mode_str = "Auto -> Direct Internet (No VPN)"

    print("\n\033[1;36m" + "=" * 68 + "\033[0m")
    print(f"  \033[1;37m🚀 UNIVERSAL CONNECTION SHARING ACTIVE v{VERSION} (PdaNet Style)\033[0m")
    print("\033[1;36m" + "=" * 68 + "\033[0m")

    if port_switched:
        print(f"  \033[1;33m⚠️  Notice: Port {requested_port} was occupied. Automatically selected port {actual_port}!\033[0m\n")

    print("  \033[1m📱 CONFIGURE YOUR PHONE:\033[0m\n")
    print("     \033[1;33m[Method 1 - Standard Wi-Fi Proxy (Safari, Browser, Web)]\033[0m")
    print(f"       • Server (IP) :  \033[1;32m{local_ip}\033[0m")
    print(f"       • Port        :  \033[1;32m{actual_port}\033[0m")
    print("\n     \033[1;33m[Method 2 - Telegram Proxy (Settings -> Data & Storage -> Proxy Settings)]\033[0m")
    print(f"       • Type        :  \033[1;32mSOCKS5\033[0m")
    print(f"       • Server (IP) :  \033[1;32m{local_ip}\033[0m")
    print(f"       • Port        :  \033[1;32m{actual_port}\033[0m")
    print(f"       • Credentials :  \033[90m(Leave Empty)\033[0m")
    print("\n     \033[1;33m[Method 3 - WhatsApp In-App Proxy (Settings -> Storage -> Proxy)]\033[0m")
    print(f"       • Proxy IP    :  \033[1;32m{local_ip}\033[0m")
    print(f"       • Chat Port   :  \033[1;32m{actual_port}\033[0m")
    print("\033[1;36m" + "-" * 68 + "\033[0m")
    print("  \033[1mℹ️  SYSTEM ROUTING STATE:\033[0m")
    print(f"     Active Mode : \033[1;32m{active_mode_str}\033[0m")
    print(f"     FlClash 7890: {'🟢 Listening' if flclash_up else '⚪ Inactive (Auto-falls back to VPN)'}")
    print(f"     System VPN  : {'🟢 ' + vpn_dev if vpn_dev else '⚪ Inactive (Direct)'}")
    print("     Exit Status : Detecting public IP in background...")
    print("\033[1;36m" + "=" * 68 + "\033[0m")
    print("  🟢 Ready & forwarding! Live phone traffic will appear below:")
    print("  🛑 Press \033[1;31m[Ctrl+C]\033[0m anytime to stop sharing.\n")
    sys.stdout.flush()

    def update_ip_status():
        st = fetch_exit_status(flclash_active=(forced_mode == 'flclash' or (forced_mode == 'auto' and flclash_up)))
        print(f"  \033[1;32m🌍 VERIFIED LAPTOP EXIT IP:\033[0m {st}\n")
        sys.stdout.flush()

    threading.Thread(target=update_ip_status, daemon=True).start()

    try:
        while True:
            client_sock, client_addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client_sock, client_addr, forced_mode), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n\n  👋 Stopped connection sharing. Remember to turn off phone Wi-Fi proxy!")
        sys.exit(0)
    finally:
        server.close()

if __name__ == "__main__":
    main()
