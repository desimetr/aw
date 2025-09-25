#!/usr/bin/env python3
"""
ultra_fast_rdp_scanner.py - Super fast RDP scanner (extended)
- Accepts a file containing mixed entries (one per line):
    - single IP: 192.0.2.1
    - CIDR: 192.0.2.0/24
    - range: 192.0.2.1-192.0.2.254
    - hostname: example.com
- Also accepts interactive comma-separated input of the same forms.
- Streams IP expansion (generator) to avoid large memory use.
- Submits scan tasks to ThreadPoolExecutor in a streaming manner.
- Prompts user where to save active results (default good.txt).
- Use only on networks you are authorized to scan.
"""

import ipaddress
import socket
import os
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED

DEFAULT_RDP_PORT = 3389
DEFAULT_WORKERS = 100  # Default concurrency
TIMEOUT = 10             # Max 10 seconds per IP
DEFAULT_OUTPUT_FILE = "good.txt"
MAX_WARN_IPS = 200_000   # warn if expansion is huge

RDP_CLIENT_HANDSHAKE = bytes([
    0x03,0x00,0x00,0x13,0x0e,0xd0,0x00,0x00,0x12,0x34,0x00,0x02,
    0x01,0x00,0x08,0x00,0x03,0x00,0x00
])

GREEN = "\033[92m"
RESET = "\033[0m"

def check_rdp(ip, port, timeout=TIMEOUT):
    """Return True if RDP responds, False otherwise (timeout enforced)"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.send(RDP_CLIENT_HANDSHAKE)
        sock.settimeout(1)  # short recv timeout
        resp = sock.recv(7)
        sock.close()
        return bool(resp)
    except Exception:
        return False

def expand_entry_to_ips(entry):
    entry = entry.strip()
    if not entry:
        return
    # CIDR
    if '/' in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            for ip in net.hosts():
                yield str(ip)
            return
        except Exception:
            pass

    # Range
    if '-' in entry:
        try:
            start_str, end_str = entry.split('-', 1)
            start = ipaddress.IPv4Address(start_str.strip())
            end = ipaddress.IPv4Address(end_str.strip())
            if int(end) < int(start):
                return
            for i in range(int(start), int(end) + 1):
                yield str(ipaddress.IPv4Address(i))
            return
        except Exception:
            pass

    # Single IP
    try:
        ip = ipaddress.IPv4Address(entry)
        yield str(ip)
        return
    except Exception:
        pass

    # Hostname
    try:
        resolved = socket.gethostbyname(entry)
        yield resolved
        return
    except Exception:
        return

def ips_from_file_stream(file_path):
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    with open(file_path, 'r') as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            parts = [p.strip() for p in line.split(',') if p.strip()]
            for p in parts:
                for ip in expand_entry_to_ips(p):
                    yield ip

def ips_from_list_input(input_str):
    parts = [p.strip() for p in input_str.split(',') if p.strip()]
    for p in parts:
        for ip in expand_entry_to_ips(p):
            yield ip

def count_expansion_estimate(sources):
    total = 0
    for entry in sources:
        e = entry.strip()
        if not e:
            continue
        try:
            if '/' in e:
                net = ipaddress.ip_network(e, strict=False)
                na = net.num_addresses
                if net.version == 4 and net.prefixlen <= 30:
                    hosts_count = na - 2
                    if hosts_count < 1:
                        hosts_count = na
                else:
                    hosts_count = na
                total += hosts_count
                continue
            if '-' in e:
                start_str, end_str = e.split('-', 1)
                start = int(ipaddress.IPv4Address(start_str.strip()))
                end = int(ipaddress.IPv4Address(end_str.strip()))
                if end >= start:
                    total += (end - start + 1)
                else:
                    total += 0
                continue
            total += 1
        except Exception:
            total += 1
    return total

def save_active_hosts(active_hosts, output_path, append=True):
    """
    Save active_hosts to output_path.
    If append=True, merge with existing unique entries; else overwrite with the new set.
    """
    # Ensure parent dir exists
    parent = os.path.dirname(os.path.abspath(output_path))
    if parent and not os.path.exists(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except Exception as e:
            print(f"Could not create directory {parent}: {e}")
            return

    # Normalize ips to a set
    new_set = set(active_hosts)

    if append and os.path.exists(output_path):
        try:
            with open(output_path, 'r') as f:
                existing = set(line.strip() for line in f if line.strip())
        except Exception:
            existing = set()
        combined = existing.union(new_set)
    else:
        combined = new_set

    try:
        with open(output_path, 'w') as f:
            # sort numerically by octet
            def sort_key(s):
                try:
                    return tuple(int(p) for p in s.split('.'))
                except Exception:
                    return (0, 0, 0, 0)
            for ip in sorted(combined, key=sort_key):
                f.write(ip + "\n")
    except Exception as e:
        print(f"Failed to write to {output_path}: {e}")

def stream_scan(ip_generator, port, workers, timeout):
    active_hosts = []
    future_to_ip = {}
    pending = set()

    with ThreadPoolExecutor(max_workers=workers) as executor:
        max_outstanding = max(10, workers * 2)
        try:
            while True:
                # fill outstanding
                while len(pending) < max_outstanding:
                    try:
                        ip = next(ip_generator)
                    except StopIteration:
                        break
                    fut = executor.submit(check_rdp, ip, port, timeout)
                    pending.add(fut)
                    future_to_ip[fut] = ip

                if not pending:
                    break

                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for fut in done:
                    ip = future_to_ip.pop(fut, "<unknown>")
                    try:
                        if fut.result():
                            print(f"{GREEN}{ip} - Active{RESET}")
                            active_hosts.append(ip)
                    except Exception:
                        pass
                    print(f"Active found: {len(active_hosts)}", end='\r', flush=True)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
    return active_hosts

def interactive_ip_generator():
    initial = input("Enter 'file' to use a file, filename directly, or press Enter to input CIDRs/ranges: ").strip()
    # @path
    if initial.startswith('@'):
        file_path = initial[1:].strip()
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return iter([])
        entries = []
        with open(file_path, 'r') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    parts = [p.strip() for p in s.split(',') if p.strip()]
                    entries.extend(parts)
        estimate = count_expansion_estimate(entries)
        if estimate > MAX_WARN_IPS:
            print(f"Warning: file expands to approximately {estimate} IPs (>{MAX_WARN_IPS}).")
            confirm = input("Continue? (yes/no) [no]: ").strip().lower()
            if confirm not in ('y', 'yes'):
                print("Aborted by user.")
                return iter([])
        return ips_from_file_stream(file_path)

    # 'file' or 'file <path>'
    if initial.lower().startswith('file'):
        parts = initial.split(maxsplit=1)
        if len(parts) == 2:
            file_path = parts[1].strip()
        else:
            file_path = input("Enter file path: ").strip()
        if not os.path.isfile(file_path):
            print(f"File not found: {file_path}")
            return iter([])
        entries = []
        with open(file_path, 'r') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    parts = [p.strip() for p in s.split(',') if p.strip()]
                    entries.extend(parts)
        estimate = count_expansion_estimate(entries)
        if estimate > MAX_WARN_IPS:
            print(f"Warning: file expands to approximately {estimate} IPs (>{MAX_WARN_IPS}).")
            confirm = input("Continue? (yes/no) [no]: ").strip().lower()
            if confirm not in ('y', 'yes'):
                print("Aborted by user.")
                return iter([])
        return ips_from_file_stream(file_path)

    # direct filename
    if initial and os.path.isfile(initial):
        file_path = initial
        entries = []
        with open(file_path, 'r') as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith('#'):
                    parts = [p.strip() for p in s.split(',') if p.strip()]
                    entries.extend(parts)
        estimate = count_expansion_estimate(entries)
        if estimate > MAX_WARN_IPS:
            print(f"Warning: file expands to approximately {estimate} IPs (>{MAX_WARN_IPS}).")
            confirm = input("Continue? (yes/no) [no]: ").strip().lower()
            if confirm not in ('y', 'yes'):
                print("Aborted by user.")
                return iter([])
        return ips_from_file_stream(file_path)

    # interactive list
    cidrs_input = initial if initial else input("Enter CIDRs, IPs or ranges (comma-separated): ").strip()
    if not cidrs_input:
        print("No input. Exiting.")
        return iter([])
    parts = [p.strip() for p in cidrs_input.split(',') if p.strip()]
    estimate = count_expansion_estimate(parts)
    if estimate > MAX_WARN_IPS:
        print(f"Warning: that input expands to approximately {estimate} IPs (>{MAX_WARN_IPS}).")
        confirm = input("Continue? (yes/no) [no]: ").strip().lower()
        if confirm not in ('y', 'yes'):
            print("Aborted by user.")
            return iter([])
    return ips_from_list_input(cidrs_input)

def main():
    print("=== ULTRA FAST RDP SCANNER (extended) ===")
    ip_gen = interactive_ip_generator()
    ip_gen = iter(ip_gen)

    # Ask for RDP port
    port_input = input(f"Enter RDP port [default {DEFAULT_RDP_PORT}]: ").strip()
    if port_input:
        try:
            rdp_port = int(port_input)
            if not (1 <= rdp_port <= 65535):
                print("Invalid port, using default.")
                rdp_port = DEFAULT_RDP_PORT
        except ValueError:
            print("Invalid port, using default.")
            rdp_port = DEFAULT_RDP_PORT
    else:
        rdp_port = DEFAULT_RDP_PORT

    # Ask for concurrency
    conc_input = input(f"Enter number of concurrent threads [default {DEFAULT_WORKERS}]: ").strip()
    if conc_input:
        try:
            workers = int(conc_input)
            if workers < 1:
                print("Invalid concurrency, using default.")
                workers = DEFAULT_WORKERS
        except ValueError:
            print("Invalid concurrency, using default.")
            workers = DEFAULT_WORKERS
    else:
        workers = DEFAULT_WORKERS

    # Ask where to save results
    out_path = input(f"Enter path to save active results [default {DEFAULT_OUTPUT_FILE}]: ").strip()
    if not out_path:
        out_path = DEFAULT_OUTPUT_FILE

    append_choice = 'a'
    if os.path.exists(out_path):
        choice = input(f"File {out_path} exists. [A]ppend (default) or [O]verwrite? ").strip().lower()
        if choice.startswith('o'):
            append_choice = 'w'
        else:
            append_choice = 'a'
    else:
        # file doesn't exist; create parent dir if needed later
        append_choice = 'a'

    append_flag = (append_choice == 'a')

    print(f"\nScanning for RDP on port {rdp_port} with timeout {TIMEOUT}s using up to {workers} threads...\n")
    active_hosts = stream_scan(ip_gen, rdp_port, workers, TIMEOUT)

    if active_hosts:
        save_active_hosts(active_hosts, out_path, append=append_flag)
        mode = "appended to" if append_flag else "written to"
        print(f"\n\nScan completed. {len(active_hosts)} active RDP hosts {mode} {out_path}")
    else:
        print("\n\nScan completed. No active RDP hosts found.")

if __name__ == "__main__":
    main()
