# NETSCANNER

Automated multi-stage network scanner built around Nmap.
Designed for repeatable, stateful, and fully logged host enumeration.

## Features

* Stateful port tracking (internal_state.json)
* Multi-stage TCP/UDP scanning
* Automatic deep-scan on newly discovered ports
* Network-wide queueing with priority ordering
* Full session transcript logging
* Execution timing logs
* Final network-wide summary report

## Scan Stages

### Stage 1 — Default TCP

Top 1000 TCP ports (-sS -vv -n -Pn -T3)

### Stage 2 — Deep Scan

Deep script+version scan on ports discovered earlier (-sC -sV)

### Stage 3 — UDP Top 100

Quick UDP enumeration (-sU --top-ports 100)

### Stage 4 — Full TCP Scan

1–65535 TCP ports (-p-)
Auto-detects newly found ports and triggers extra deep scan.

## Directory Structure
```
./<ip>/
internal_state.json
stage_1_default/nmap_scan.*
stage_2_deep/nmap_scan.*
stage_3_udp/nmap_scan.*
stage_4_full/nmap_scan.*
full_terminal_output.log
execution_timings.log
active_ports_overview.txt
live_hosts_list.txt
final_network_summary.log
```
## Installation
```bash
chmod +x netscanner.py
sudo apt install nmap
```
## Running

### Single Host

./netscanner.py
```bash
> 10.10.10.5
> Start Stage: 1
```
### Network Range
```bash
./netscanner.py

> 10.10.10.0/24
> Start Stage: 1
```
### Navigation

Enter → next stage
1/2/3/4 → jump directly
q → quit

## State Tracking

TCP port lists stored as ASCII:
80   = discovered
80+  = deep-scan completed

## Extra Deep Scan

Triggered when Stage 4 finds new ports.
Performs: `-sS -sC -sV -p <port>`

## Logging
```
full_terminal_output.log
execution_timings.log
active_ports_overview.txt
final_network_summary.log
```
## Sweep Logic

Two passes of: `nmap -sn -n -T3 <cidr>`
Hosts sorted numerically.
Stage 4 scans empty hosts first, active hosts after.

## Shutdown Behavior

`Ctrl+C` generates final report.

## Purpose

Stable, incremental network recon with persistent host state.
