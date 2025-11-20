#!/usr/bin/env python3
import subprocess
import sys
import shutil
import time
import ipaddress
import os
import json
import datetime

# --- CONFIGURATION ---
DEFAULT_OUTPUT = "nmap_scan"
STATE_FILE = "internal_state.json"
SESSION_LOG = "full_terminal_output.log"
TIME_LOG = "execution_timings.log"
FINAL_REPORT = "final_network_summary.log"
LIVE_LIST = "live_hosts_list.txt"
OVERVIEW_FILE = "active_ports_overview.txt"

NMAP_TIMING = "-T3" 
SWEEP_PASSES = 2 

# ANSI Colors (Functional)
GREEN = "\033[92m"
BOLD = "\033[1m"
RESET = "\033[0m"
DIM = "\033[90m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

class DualLogger(object):
    def __init__(self):
        self.terminal = sys.stdout
        self.log = open(SESSION_LOG, "a") 
    def write(self, message):
        self.terminal.write(message)
        clean_msg = message.replace(GREEN, "").replace(BOLD, "").replace(RESET, "").replace(DIM, "").replace(RED, "").replace(YELLOW, "").replace(CYAN, "").replace(MAGENTA, "")
        self.log.write(clean_msg)
        self.log.flush()  
    def flush(self):
        self.terminal.flush()
        self.log.flush()

def check_dependencies():
    if shutil.which("nmap") is None:
        print(f"{RED}Error: 'nmap' is not installed.{RESET}", file=sys.stderr)
        sys.exit(1)

def log_time_stat(target_dir, message):
    try:
        path = os.path.join(target_dir, TIME_LOG)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(path, "a") as f: f.write(f"[{timestamp}] {message}\n")
    except: pass 

def get_known_ports(target_ip, protocol="tcp", strip_plus=True):
    try:
        state_path = os.path.join(f"./{target_ip}", STATE_FILE)
        if os.path.exists(state_path):
            with open(state_path, 'r') as f:
                data = json.load(f)
                raw_list = []
                if protocol == "tcp": 
                    raw_list = data.get("tcp", []) if "tcp" in data else data.get("open_ports", [])
                else:
                    raw_list = data.get(protocol, [])
                
                if strip_plus:
                    return [p.replace("+", "") for p in raw_list]
                return raw_list
    except: pass
    return []

def get_host_port_count(target_ip):
    t = len(get_known_ports(target_ip, "tcp"))
    u = len(get_known_ports(target_ip, "udp"))
    return t + u

def parse_nmap_results(filename):
    formatted_lines = []
    ports_dict = {"tcp": [], "udp": []}
    try:
        with open(f"{filename}.nmap", "r") as f:
            for line in f:
                if "open" in line and ("/tcp" in line or "/udp" in line) and "Discovered" not in line:
                    parts = line.split()
                    port_protocol = parts[0]
                    if "/" in port_protocol: 
                        p_num, p_proto = port_protocol.split("/")
                    else: continue
                    
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    version = (version[:35] + '..') if len(version) > 35 else version
                    formatted_lines.append(f"{port_protocol:<10} {service:<12} {version}")
                    
                    if p_proto in ports_dict:
                        if p_num not in ports_dict[p_proto]:
                            ports_dict[p_proto].append(p_num)
    except FileNotFoundError: pass
    return formatted_lines, ports_dict

def print_summary(target, formatted_lines):
    print("\n" + "="*60)
    print(f" SUMMARY: {target}")
    print("-" * 60)
    if formatted_lines:
        print(f"{'PORT':<10} {'SERVICE':<12} {'VERSION'}")
        print("-" * 60)
        for line in formatted_lines: print(line)
    else: print("[-] No open ports found.")
    print("="*60 + "\n")

def run_extra_deep_scan(target_ip, output_dir, new_ports):
    ports_str = ",".join(new_ports)
    filename = os.path.join(output_dir, "extra_deep_scan")
    
    if os.path.exists(filename + ".xml") and os.path.getsize(filename + ".xml") > 100:
        _, ports_dict = parse_nmap_results(filename)
        return ports_dict.get("tcp", []) 

    print(f"\n{MAGENTA}[+] New Ports Discovered: {ports_str}{RESET}")
    print(f"{MAGENTA}[*] Starting targeted Deep Scan on new ports...{RESET}")
    
    cmd = ["nmap", "-n", "-Pn", "-sS", "-sC", "-sV", "-p", ports_str, "-oA", filename, target_ip]
    
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        lines, ports_dict = parse_nmap_results(filename)
        if lines:
            print("-" * 60)
            for line in lines: print(f"{MAGENTA}{line}{RESET}")
            print("-" * 60)
        log_time_stat(f"./{target_ip}", f"Extra Deep Scan ran on ports: {ports_str}")
        return ports_dict.get("tcp", [])
    except Exception as e: 
        print(f"{RED}[!] Extra scan failed: {e}{RESET}")
        return []

def get_stage_folder_name(stage):
    if stage == 1: return "stage_1_default"
    elif stage == 2: return "stage_2_deep"
    elif stage == 3: return "stage_3_udp"
    elif stage == 4: return "stage_4_full"
    return None

def check_previous_scan(target_ip, stage):
    """Checks if the output folder for a specific stage exists."""
    folder_name = get_stage_folder_name(stage)
    if not folder_name: return False
    path = os.path.join(f"./{target_ip}", folder_name)
    return os.path.exists(os.path.join(path, DEFAULT_OUTPUT + ".xml"))

# ==========================================
# SCANNER LOGIC
# ==========================================
def run_host_scan(stage, target_ip, network_sweep_time=None, force_rescan=False):
    try:
        target_dir = f"./{target_ip}"
        os.makedirs(target_dir, exist_ok=True)
        state_path = os.path.join(target_dir, STATE_FILE)
        stage_name = get_stage_folder_name(stage)
        if not stage_name: return

        output_dir = os.path.join(target_dir, stage_name)
        os.makedirs(output_dir, exist_ok=True)
        filename = os.path.join(output_dir, DEFAULT_OUTPUT)
        
        print(f"\n{BOLD}[*] Target: {target_ip} | Stage: {stage} | Dir: {output_dir}{RESET}")
        
        if stage == 1 and network_sweep_time is not None:
            log_time_stat(target_dir, f"--- SCAN INITIALIZATION ---")
            log_time_stat(target_dir, f"Network Discovery (Ping Sweep) Duration: {network_sweep_time:.2f}s")
    
    except Exception as e:
        print(f"{RED}[!] Failed to create directory: {e}{RESET}")
        return

    common_flags = ["-vv", "-n", "-Pn", NMAP_TIMING, "-oA", filename]
    
    pre_scan_tcp_ports = []
    if stage == 4: pre_scan_tcp_ports = get_known_ports(target_ip, "tcp", strip_plus=True)

    cmd = []
    log_msg = ""
    skip_scan = False

    if stage == 1:
        cmd = ["nmap", "-sS"] + common_flags + [target_ip]
        log_msg = "Stage 1 (Default TCP)"
    elif stage == 2:
        ports_list = get_known_ports(target_ip, "tcp", strip_plus=True)
        if ports_list:
            ports_str = ",".join(ports_list)
            print(f"{YELLOW}[*] State file found. Scanning {len(ports_list)} TCP ports...{RESET}")
            cmd = ["nmap", "-sS", "-p", ports_str] + common_flags + ["-sC", "-sV", target_ip]
            log_msg = f"Stage 2 (Deep Scan) on {len(ports_list)} ports"
        else:
            print(f"{YELLOW}[!] No TCP ports known for this host. Skipping Deep Scan.{RESET}")
            log_time_stat(target_dir, "Stage 2 Skipped: No known TCP ports.")
            return
    elif stage == 3:
        cmd = ["nmap", "-vv", "-n", "-Pn", "-sU", "--top-ports", "100", "-oA", filename, target_ip]
        log_msg = "Stage 3 (UDP Top 100)"
    elif stage == 4: 
        cmd = ["nmap"] + common_flags + ["-p-", target_ip]
        log_msg = "Stage 4 (Full TCP 1-65535)"
    
    # --- Overwrite Protection ---
    if os.path.exists(filename + ".xml") and os.path.getsize(filename + ".xml") > 100:
        if force_rescan:
            print(f"{RED}[!] Force Rescan enabled. Overwriting existing scan...{RESET}")
            skip_scan = False
        else:
            print(f"{GREEN}[!] Output file exists. Skipping execution.{RESET}")
            print(f"{DIM}[*] Parsing existing file to update state...{RESET}")
            skip_scan = True
    elif not cmd: 
        return

    if not skip_scan:
        print(f"{DIM}[*] Executing: {' '.join(cmd)}{RESET}")
        print("-" * 60)
        scan_start = time.time()
        log_time_stat(target_dir, f"STARTED: {log_msg}")
        try:
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            for line in process.stdout:
                line = line.strip()
                if not line: continue
                if "Discovered open port" in line: print(f"{GREEN}[+] {line}{RESET}")
                elif any(x in line for x in ["Scanning", "Completed", "NSE"]): print(f"{DIM}[*] {line}{RESET}")
            process.wait()
        except KeyboardInterrupt:
            print(f"\n{RED}[!] Scan cancelled. Propagating exit...{RESET}")
            log_time_stat(target_dir, f"CANCELLED: {log_msg}")
            raise KeyboardInterrupt 
        log_time_stat(target_dir, f"FINISHED: {log_msg}")
        log_time_stat(target_dir, f"DURATION: {time.time() - scan_start:.2f}s")

    # --- UPDATE STATE ---
    formatted_lines, new_ports_dict = parse_nmap_results(filename)
    
    current_state = {"tcp": [], "udp": []}
    if os.path.exists(state_path):
        try:
            with open(state_path, 'r') as f:
                loaded = json.load(f)
                if "open_ports" in loaded: current_state["tcp"] = loaded["open_ports"]
                else: current_state = loaded
        except: pass 

    state_changed = False
    
    def merge_state(proto, new_ports, is_deep_scan=False):
        changed = False
        existing_map = {}
        for p in current_state.get(proto, []):
            is_det = "+" in p
            clean_p = p.replace("+", "")
            existing_map[clean_p] = is_det
        
        for p in new_ports:
            if p not in existing_map:
                existing_map[p] = is_deep_scan 
                changed = True
            elif is_deep_scan and not existing_map[p]:
                existing_map[p] = True 
                changed = True
        
        if changed:
            final_list = []
            for p, is_det in existing_map.items():
                final_list.append(f"{p}+" if is_det else p)
            current_state[proto] = final_list
            return True
        return False

    if stage in [1, 4]:
        if merge_state("tcp", new_ports_dict["tcp"], is_deep_scan=False):
            state_changed = True
    elif stage == 2: 
        if merge_state("tcp", new_ports_dict["tcp"], is_deep_scan=True):
            state_changed = True
    elif stage == 3:
        if merge_state("udp", new_ports_dict["udp"], is_deep_scan=False):
            state_changed = True

    if state_changed:
        try:
            with open(state_path, 'w') as f: json.dump(current_state, f, indent=4)
            print(f"{GREEN}[+] State file updated.{RESET}")
        except: pass

    print_summary(target_ip, formatted_lines)

    if stage == 4:
        found_in_full = new_ports_dict["tcp"]
        newly_discovered = [p for p in found_in_full if p not in pre_scan_tcp_ports]
        
        if newly_discovered:
            found_in_extra = run_extra_deep_scan(target_ip, output_dir, newly_discovered)
            if found_in_extra and merge_state("tcp", found_in_extra, is_deep_scan=True):
                 with open(state_path, 'w') as f: json.dump(current_state, f, indent=4)
                 print(f"{GREEN}[+] State updated with Extra Deep Scan details.{RESET}")

def perform_sweep(network_cidr):
    cmd = ["nmap", "-sn", "-n", NMAP_TIMING, network_cidr]
    found_hosts = set()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            if "Nmap scan report" in line:
                parts = line.split()
                if len(parts) >= 6: ip = parts[5].strip("()")
                else: ip = parts[4]
                found_hosts.add(ip)
    except: pass
    return found_hosts

def run_network_scan(stage, network_cidr, force_rescan, known_hosts=None, cached_sweep_time=0.0):
    print(f"\n{BOLD}[*] MODE: Network Scan (Serial) - Stage {stage}{RESET}")
    sorted_hosts = []
    sweep_time = cached_sweep_time

    if known_hosts:
        print(f"{GREEN}[*] Using cached list of {len(known_hosts)} hosts.{RESET}")
        sorted_hosts = known_hosts
    else:
        print(f"{BOLD}[*] Performing {SWEEP_PASSES} Ping Sweep passes on {network_cidr}...{RESET}")
        sweep_start = time.time()
        master_host_set = set()
        for i in range(1, SWEEP_PASSES + 1):
            print(f"{DIM}[*] Pass {i}/{SWEEP_PASSES}...{RESET}", end="", flush=True)
            pass_hosts = perform_sweep(network_cidr)
            master_host_set.update(pass_hosts)
            print(f" Found {len(pass_hosts)} hosts")
            time.sleep(0.5) 
        sweep_time = time.time() - sweep_start
        try: sorted_hosts = sorted(list(master_host_set), key=lambda ip: int(ipaddress.IPv4Address(ip)))
        except: sorted_hosts = sorted(list(master_host_set))
        if sorted_hosts:
            with open(LIVE_LIST, "w") as f:
                for ip in sorted_hosts: f.write(f"{ip}\n")
    
    if not sorted_hosts:
        print(f"{RED}[-] No active hosts found.{RESET}")
        return [], 0.0

    if stage == 4:
        print(f"\n{CYAN}[*] OPTIMIZING QUEUE FOR FULL SCAN...{RESET}")
        empty, found = [], []
        for ip in sorted_hosts:
            if get_host_port_count(ip) > 0: found.append(ip)
            else: empty.append(ip)
        sorted_hosts = empty + found
        print(f"{CYAN}[+] Priority: {len(empty)} Empty Hosts -> {len(found)} Established Hosts{RESET}")

    print(f"\n{GREEN}[+] Starting Stage {stage} on {len(sorted_hosts)} hosts...{RESET}")
    
    try:
        for i, host_ip in enumerate(sorted_hosts):
            print("\n" + "="*60)
            print(f"{BOLD}Scanning Host {i+1}/{len(sorted_hosts)}: {host_ip}{RESET}")
            run_host_scan(stage, host_ip, network_sweep_time=sweep_time, force_rescan=force_rescan)
            
            try:
                t_ports = get_known_ports(host_ip, "tcp", strip_plus=False)
                u_ports = get_known_ports(host_ip, "udp", strip_plus=False)
                t_str = ",".join(t_ports) if t_ports else "None"
                u_str = ",".join(u_ports) if u_ports else "None"
                print(f"{DIM}State: TCP:[{t_str}] UDP:[{u_str}]{RESET}")
            except: pass
            print(f"{BOLD}Finished {host_ip}{RESET}")
            
    except KeyboardInterrupt:
        print(f"\n{RED}[!] Network Scan Aborted by user.{RESET}")
        raise KeyboardInterrupt

    with open(OVERVIEW_FILE, "w") as f:
        f.write(f"Active Ports Summary - Stage {stage}\n{'-'*60}\n")
        for ip in sorted_hosts:
             t_ports = get_known_ports(ip, "tcp", strip_plus=False)
             u_ports = get_known_ports(ip, "udp", strip_plus=False)
             t_str = ",".join(t_ports) if t_ports else "None"
             u_str = ",".join(u_ports) if u_ports else "None"
             f.write(f"{ip:<15} : TCP: {t_str} | UDP: {u_str}\n")
             
    print(f"\n{GREEN}[+] Active Ports Overview saved to '{OVERVIEW_FILE}'{RESET}")
    return sorted_hosts, sweep_time

def generate_final_report(hosts):
    print(f"\n{CYAN}[*] GENERATING REPORT...{RESET}")
    ghosts, established = [], []
    for ip in hosts:
        if get_host_port_count(ip) == 0: ghosts.append(ip)
        else: established.append(f"{ip} ({get_host_port_count(ip)} ports)")
    
    with open(FINAL_REPORT, "w") as f:
        f.write(f"NETSCANNER v1.6 STATISTICS\n{'='*40}\nTotal: {len(hosts)}\n\n")
        f.write(f"[EMPTY HOSTS] ({len(ghosts)})\n{'-'*40}\n")
        for ip in ghosts: f.write(f"{ip}\n")
        f.write(f"\n[ACTIVE HOSTS] ({len(established)})\n{'-'*40}\n")
        for ip in established: f.write(f"{ip}\n")
    print(f"{GREEN}[+] Report saved: {FINAL_REPORT}{RESET}")

def main():
    sys.stdout = DualLogger()
    check_dependencies()
    try:
        print(f"\n{BOLD}NETSCANNER v1.6{RESET}")
        print(f"{DIM}>> SESSION LOG -> {SESSION_LOG}{RESET}")
        base_input = input("\n[>] ENTER TARGET IP / RANGE: ").strip()
        if not base_input: sys.exit(1)
        
        if any(x in base_input for x in ["/", "-", ","]): 
            target, is_network = base_input, True
        else:
             mask = input("Enter Mask (e.g. /24) [ENTER for Single]: ").strip()
             if mask: target, is_network = base_input + ("/" + mask if not mask.startswith("/") else mask), True
             else: target, is_network = base_input, False
    except KeyboardInterrupt: 
        sys.exit(0)

    print(f"\n{BOLD}Target: {target}{RESET}")
    print("1) Default (Top 1000)\n2) Deep (Scripts)\n3) UDP Scan\n4) Full Scan (Priority Queue)")
    try: 
        start_stage = int(input("Start Stage: ").strip())
    except: 
        return

    current_stage = start_stage
    cached_hosts, cached_time = [], 0.0
    
    while True:
        try:
            force_rescan = False
            should_ask = False
            
            if is_network:
                if cached_hosts and check_previous_scan(cached_hosts[0], current_stage): should_ask = True
            else:
                if check_previous_scan(target, current_stage): should_ask = True

            if should_ask:
                print(f"{YELLOW}[?] Previous results found for Stage {current_stage}. Force Rescan (Overwrite)? [y/N]{RESET}")
                if input("Select: ").strip().lower() in ['y', 'yes']:
                    force_rescan = True
            
            if is_network: 
                cached_hosts, cached_time = run_network_scan(current_stage, target, force_rescan, cached_hosts, cached_time)
            else: 
                run_host_scan(current_stage, target, force_rescan=force_rescan)
                cached_hosts = [target]

            print("\n" + "-" * 50)
            print(f"{YELLOW}[?] Stage {current_stage} Finished. Select Next Step:{RESET}")
            print("    [1] Default  [2] Deep  [3] UDP  [4] Full")
            print("    [Enter] Next Stage  [q] Quit")
            
            sel = input(">> ").strip().lower()
            if sel == 'q': 
                generate_final_report(cached_hosts)
                break
            elif sel == '': 
                current_stage += 1 
            elif sel in ['1','2','3','4']: 
                current_stage = int(sel) 
                print(f"\n{BOLD}[*] Jumping to Stage {current_stage}...{RESET}")
            else:
                print(f"{RED}[!] Invalid selection. Exiting.{RESET}")
                break
                
            if current_stage > 4:
                print(f"\n{BOLD}[*] All stages completed.{RESET}")
                generate_final_report(cached_hosts)
                break

        except KeyboardInterrupt: 
            print(f"\n{RED}[!] Abort signal caught. Generating final report...{RESET}")
            generate_final_report(cached_hosts)
            break

if __name__ == "__main__":
    main()