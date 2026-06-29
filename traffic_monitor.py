# traffic_monitor.py
# IoT Security Scanner — Live Traffic Monitor & Attack Detector
#
# Sniffs packets on the local interface using Scapy (already installed).
# Detects DDoS signatures in real time and logs alerts.
#
# Usage (standalone):
#   python traffic_monitor.py
#
# Usage (from main.py):
#   python main.py --monitor-traffic
#   python main.py --monitor-traffic --block
#
# Detection signatures:
#   - SYN Flood     : >200 TCP SYN packets/sec from one IP
#   - ICMP Flood    : >100 ICMP packets/sec from one IP
#   - UDP Flood     : >300 UDP packets/sec from one IP
#   - Port Scan     : >20 unique destination ports/sec from one IP
#   - ARP Spoof     : same IP announced by two different MACs

import os
import time
import threading
import datetime
import collections
from colorama import Fore, Style, init

init(autoreset=True)

# ── Configuration ─────────────────────────────────────────────────────────────

THRESHOLDS = {
    'syn_flood':    200,    # TCP SYN packets per second per source IP
    'icmp_flood':   100,    # ICMP packets per second per source IP
    'udp_flood':    300,    # UDP packets per second per source IP
    'port_scan':     20,    # unique dst ports per second per source IP
}

WINDOW_SECONDS  = 5        # rolling window for rate calculation
BLOCKLIST_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'blocklist.txt')
ALERT_LOG_FILE  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'traffic_alerts.log')

# ── Shared state (thread-safe) ─────────────────────────────────────────────────

_lock        = threading.Lock()
_running     = False
_stats       = {
    'packets_seen':   0,
    'alerts_fired':   0,
    'blocked_ips':    set(),
    'start_time':     None,
}

# Rolling counters — keyed by source IP
# Each value is a deque of timestamps
_syn_times   = collections.defaultdict(lambda: collections.deque())
_icmp_times  = collections.defaultdict(lambda: collections.deque())
_udp_times   = collections.defaultdict(lambda: collections.deque())
_dst_ports   = collections.defaultdict(lambda: collections.deque())   # (timestamp, port)
_arp_table   = {}    # ip -> mac (for ARP spoof detection)

_alert_callbacks  = []   # functions called on every new alert
_packet_callbacks = []   # functions called on EVERY packet (live feed)

# Protocol counters for breakdown bar
_proto_counts = {
    'TCP':  0,
    'UDP':  0,
    'ICMP': 0,
    'ARP':  0,
    'OTHER':0,
}


# ── Alert system ───────────────────────────────────────────────────────────────

def _fire_alert(attack_type: str, src_ip: str, detail: str,
                 auto_block: bool = False) -> None:
    """Logs, prints, and optionally blocks a detected attack."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    msg       = f"[{timestamp}] [{attack_type}] Source: {src_ip} — {detail}"

    # Fire packet callbacks with alert flag so GUI highlights it
    alert_pkt = {
        'src':   src_ip,
        'dst':   '—',
        'proto': attack_type,
        'port':  '—',
        'size':  0,
        'ts':    datetime.datetime.now().strftime('%H:%M:%S'),
        'alert': True,
        'detail': detail,
    }
    for cb in _packet_callbacks:
        try:
            cb(alert_pkt)
        except Exception:
            pass

    # Console output
    print(f"\n{Fore.RED}  [!] ATTACK DETECTED{Style.RESET_ALL}")
    print(f"      Type   : {Fore.RED}{attack_type}{Style.RESET_ALL}")
    print(f"      Source : {Fore.YELLOW}{src_ip}{Style.RESET_ALL}")
    print(f"      Detail : {detail}")

    # Write to alert log
    try:
        with open(ALERT_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(msg + '\n')
    except Exception:
        pass

    # Auto-block: add to blocklist file
    if auto_block or src_ip in _stats['blocked_ips']:
        _block_ip(src_ip, attack_type)
    else:
        # Always add to blocklist as a RECOMMENDED block (not enforced)
        _add_to_blocklist(src_ip, attack_type, enforced=False)

    with _lock:
        _stats['alerts_fired'] += 1

    # Notify external callbacks (e.g. module7 watch mode)
    for cb in _alert_callbacks:
        try:
            cb(attack_type, src_ip, detail, timestamp)
        except Exception:
            pass


def _block_ip(ip: str, reason: str) -> None:
    """Adds IP to the block-list with BLOCKED status."""
    with _lock:
        _stats['blocked_ips'].add(ip)
    _add_to_blocklist(ip, reason, enforced=True)
    print(f"      Status : {Fore.RED}[BLOCKED]{Style.RESET_ALL} "
          f"Added to {BLOCKLIST_FILE}")


def _add_to_blocklist(ip: str, reason: str, enforced: bool) -> None:
    """Writes an entry to blocklist.txt."""
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status    = 'BLOCKED' if enforced else 'FLAGGED'
    line      = f"{ip:<18} {status:<10} {reason:<25} {timestamp}\n"
    try:
        with open(BLOCKLIST_FILE, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass


# ── Rate helpers ───────────────────────────────────────────────────────────────

def _prune(dq: collections.deque, now: float) -> None:
    """Removes entries older than WINDOW_SECONDS from a deque."""
    cutoff = now - WINDOW_SECONDS
    while dq and dq[0] < cutoff:
        dq.popleft()


def _prune_ports(dq: collections.deque, now: float) -> None:
    """Prunes (timestamp, port) tuples older than window."""
    cutoff = now - WINDOW_SECONDS
    while dq and dq[0][0] < cutoff:
        dq.popleft()


def _rate(dq: collections.deque) -> float:
    """Returns events per second in the current window."""
    return len(dq) / WINDOW_SECONDS


# ── Packet handler ─────────────────────────────────────────────────────────────

def _extract_packet_info(pkt) -> dict:
    """
    Extracts human-readable info from a packet for the live feed.
    Returns None for packets we don't care about displaying.
    Returns dict: {src, dst, proto, port, size, timestamp}
    """
    from scapy.all import IP, TCP, UDP, ICMP, ARP
    import datetime

    ts = datetime.datetime.now().strftime('%H:%M:%S')

    try:
        # ARP
        if pkt.haslayer(ARP):
            return {
                'src':   pkt[ARP].psrc,
                'dst':   pkt[ARP].pdst,
                'proto': 'ARP',
                'port':  '—',
                'size':  len(pkt),
                'ts':    ts,
                'alert': False,
            }

        if not pkt.haslayer(IP):
            return None

        src  = pkt[IP].src
        dst  = pkt[IP].dst
        size = len(pkt)

        # Skip loopback
        if src.startswith('127.') or dst.startswith('127.'):
            return None

        # TCP
        if pkt.haslayer(TCP):
            port = pkt[TCP].dport
            return {
                'src':   src,
                'dst':   dst,
                'proto': 'TCP',
                'port':  str(port),
                'size':  size,
                'ts':    ts,
                'alert': False,
            }

        # UDP
        if pkt.haslayer(UDP):
            port = pkt[UDP].dport
            return {
                'src':   src,
                'dst':   dst,
                'proto': 'UDP',
                'port':  str(port),
                'size':  size,
                'ts':    ts,
                'alert': False,
            }

        # ICMP
        if pkt.haslayer(ICMP):
            return {
                'src':   src,
                'dst':   dst,
                'proto': 'ICMP',
                'port':  '—',
                'size':  size,
                'ts':    ts,
                'alert': False,
            }

        # Other IP
        return {
            'src':   src,
            'dst':   dst,
            'proto': 'OTHER',
            'port':  '—',
            'size':  size,
            'ts':    ts,
            'alert': False,
        }

    except Exception:
        return None


def _handle_packet(pkt) -> None:
    """Called for every sniffed packet. Checks all detection signatures."""
    from scapy.all import IP, TCP, UDP, ICMP, ARP

    now = time.time()

    with _lock:
        _stats['packets_seen'] += 1

    # ── Build live packet info + fire packet callbacks ─────────────────────────
    pkt_info = _extract_packet_info(pkt)
    if pkt_info:
        with _lock:
            _proto_counts[pkt_info['proto']] = (
                _proto_counts.get(pkt_info['proto'], 0) + 1
            )
        for cb in _packet_callbacks:
            try:
                cb(pkt_info)
            except Exception:
                pass

    # ── ARP Spoof detection ────────────────────────────────────────────────────
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:   # ARP reply
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc
        with _lock:
            known_mac = _arp_table.get(src_ip)
            if known_mac is None:
                _arp_table[src_ip] = src_mac
            elif known_mac != src_mac:
                _fire_alert(
                    'ARP SPOOFING',
                    src_ip,
                    f"IP {src_ip} now claims MAC {src_mac} (was {known_mac}). "
                    f"Possible MITM attack.",
                    auto_block=False,
                )
                _arp_table[src_ip] = src_mac   # update to latest
        return

    if not pkt.haslayer(IP):
        return

    src_ip = pkt[IP].src

    # Skip localhost / broadcast
    if src_ip.startswith('127.') or src_ip.endswith('.255'):
        return

    # Already blocked — silently count but don't re-alert
    if src_ip in _stats['blocked_ips']:
        return

    # ── SYN Flood detection ────────────────────────────────────────────────────
    if pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        dport = pkt[TCP].dport

        if flags & 0x02:   # SYN flag
            with _lock:
                _syn_times[src_ip].append(now)
                _prune(_syn_times[src_ip], now)
                rate = _rate(_syn_times[src_ip])

            if rate > THRESHOLDS['syn_flood']:
                _fire_alert(
                    'SYN FLOOD',
                    src_ip,
                    f"{rate:.0f} SYN packets/sec (threshold: "
                    f"{THRESHOLDS['syn_flood']})",
                    auto_block=True,
                )
                with _lock:
                    _syn_times[src_ip].clear()   # reset after alert

        # ── Port Scan detection ────────────────────────────────────────────────
        with _lock:
            _dst_ports[src_ip].append((now, dport))
            _prune_ports(_dst_ports[src_ip], now)
            unique_ports = len(set(p for _, p in _dst_ports[src_ip]))

        if unique_ports > THRESHOLDS['port_scan']:
            _fire_alert(
                'PORT SCAN',
                src_ip,
                f"{unique_ports} unique ports targeted in {WINDOW_SECONDS}s",
                auto_block=False,
            )
            with _lock:
                _dst_ports[src_ip].clear()

    # ── ICMP Flood detection ───────────────────────────────────────────────────
    elif pkt.haslayer(ICMP):
        with _lock:
            _icmp_times[src_ip].append(now)
            _prune(_icmp_times[src_ip], now)
            rate = _rate(_icmp_times[src_ip])

        if rate > THRESHOLDS['icmp_flood']:
            _fire_alert(
                'ICMP FLOOD',
                src_ip,
                f"{rate:.0f} ICMP packets/sec (threshold: "
                f"{THRESHOLDS['icmp_flood']})",
                auto_block=True,
            )
            with _lock:
                _icmp_times[src_ip].clear()

    # ── UDP Flood detection ────────────────────────────────────────────────────
    elif pkt.haslayer(UDP):
        with _lock:
            _udp_times[src_ip].append(now)
            _prune(_udp_times[src_ip], now)
            rate = _rate(_udp_times[src_ip])

        if rate > THRESHOLDS['udp_flood']:
            _fire_alert(
                'UDP FLOOD',
                src_ip,
                f"{rate:.0f} UDP packets/sec (threshold: "
                f"{THRESHOLDS['udp_flood']})",
                auto_block=True,
            )
            with _lock:
                _udp_times[src_ip].clear()


# ── Stats printer ──────────────────────────────────────────────────────────────

def _print_stats_loop(interval: int = 10) -> None:
    """Background thread that prints a live stats summary every N seconds."""
    while _running:
        time.sleep(interval)
        if not _running:
            break

        with _lock:
            pkts    = _stats['packets_seen']
            alerts  = _stats['alerts_fired']
            blocked = len(_stats['blocked_ips'])
            elapsed = time.time() - (_stats['start_time'] or time.time())

        rate = pkts / max(elapsed, 1)
        ts   = datetime.datetime.now().strftime('%H:%M:%S')

        print(f"\n  {Fore.CYAN}[{ts}] Traffic Monitor{Style.RESET_ALL}  "
              f"Packets: {pkts}  |  "
              f"Rate: {rate:.0f}/s  |  "
              f"{Fore.YELLOW}Alerts: {alerts}{Style.RESET_ALL}  |  "
              f"{Fore.RED}Blocked: {blocked}{Style.RESET_ALL}")


# ── Public API ─────────────────────────────────────────────────────────────────

def get_proto_counts() -> dict:
    """Returns current protocol breakdown counts (thread-safe copy)."""
    with _lock:
        return dict(_proto_counts)


def start_monitor(auto_block: bool = False,
                  stats_interval: int = 10,
                  alert_callback=None,
                  packet_callback=None,
                  blocking: bool = True) -> None:
    """
    Starts the live packet sniffer. Runs until Ctrl+C.

    Args:
        auto_block      : If True, automatically block IPs that trigger alerts
        stats_interval  : How often to print the stats summary (seconds)
        alert_callback  : Optional function(attack_type, src_ip, detail, ts)
                          called on every detected attack
        packet_callback : Optional function(pkt_info: dict) called on EVERY
                          packet — used for live GUI feed
        blocking        : If True, sniff() blocks until Ctrl+C.
                          If False, sniff runs in a background thread.
    """
    from scapy.all import sniff

    global _running

    if alert_callback:
        _alert_callbacks.append(alert_callback)

    if packet_callback:
        _packet_callbacks.append(packet_callback)

    _running             = True
    _stats['start_time'] = time.time()

    # Start stats thread
    stats_thread = threading.Thread(
        target = _print_stats_loop,
        args   = (stats_interval,),
        daemon = True,
    )
    stats_thread.start()

    # Print header
    print(f"\n{Fore.CYAN}{'=' * 65}")
    print(f"  Live Traffic Monitor")
    print(f"  Thresholds: SYN>{THRESHOLDS['syn_flood']}/s  "
          f"ICMP>{THRESHOLDS['icmp_flood']}/s  "
          f"UDP>{THRESHOLDS['udp_flood']}/s  "
          f"Ports>{THRESHOLDS['port_scan']}/win")
    print(f"  Auto-block : {'ON' if auto_block else 'OFF (FLAGGED only)'}")
    print(f"  Alert log  : {ALERT_LOG_FILE}")
    print(f"  Block list : {BLOCKLIST_FILE}")
    print(f"{'=' * 65}{Style.RESET_ALL}")
    print(f"  Sniffing... press {Fore.YELLOW}Ctrl+C{Style.RESET_ALL} to stop.\n")

    def _sniff_target():
        try:
            sniff(
                prn    = _handle_packet,
                store  = False,
                filter = "ip or arp",
            )
        except Exception as e:
            print(f"\n  [!] Sniffer error: {e}")

    if blocking:
        try:
            _sniff_target()
        except KeyboardInterrupt:
            pass
        finally:
            stop_monitor()
    else:
        t = threading.Thread(target=_sniff_target, daemon=True)
        t.start()
        return t


def stop_monitor() -> dict:
    """Stops the monitor and returns final stats."""
    global _running
    _running = False

    # Clear callbacks so they don't accumulate on restart
    _alert_callbacks.clear()
    _packet_callbacks.clear()

    with _lock:
        summary = {
            'packets_seen': _stats['packets_seen'],
            'alerts_fired': _stats['alerts_fired'],
            'blocked_ips':  list(_stats['blocked_ips']),
        }
        # Reset proto counts for next session
        for k in _proto_counts:
            _proto_counts[k] = 0

    print(f"\n{Fore.CYAN}  Traffic Monitor stopped.")
    print(f"  Packets seen : {summary['packets_seen']}")
    print(f"  Alerts fired : {summary['alerts_fired']}")
    print(f"  Blocked IPs  : {len(summary['blocked_ips'])}{Style.RESET_ALL}\n")

    return summary


def get_blocklist() -> list:
    """Returns current list of blocked/flagged IPs from blocklist.txt."""
    if not os.path.exists(BLOCKLIST_FILE):
        return []
    try:
        with open(BLOCKLIST_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='IoT Scanner — Traffic Monitor')
    parser.add_argument('--block', action='store_true',
                        help='Auto-block IPs that trigger attack alerts')
    parser.add_argument('--interval', type=int, default=10,
                        help='Stats print interval in seconds (default: 10)')
    args = parser.parse_args()

    start_monitor(
        auto_block     = args.block,
        stats_interval = args.interval,
        blocking       = True,
    )
