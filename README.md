# VectorCore TWAG

VectorCore TWAG is a Trusted WLAN Access Gateway implementation for lab and carrier-style 3GPP Wi-Fi access testing. It bridges WPA2/WPA3 Enterprise 802.1X access on the WLAN side to a PGW over GTP-C/GTP-U, using 3GPP AAA over Diameter STa/SWx-style EAP-AKA′ authentication.

The current implementation is focused on trusted non-3GPP WLAN access where the UE authenticates through an AP using RADIUS/EAP, the TWAG exchanges EAP-AKA′ with the AAA/HSS path, creates a PGW session, receives a subscriber IP address, and provides the UE with DHCP/ARP/access forwarding into the GTP user-plane path.

---

## Status

This project is under active development and lab validation.

Currently implemented or being validated:

- RADIUS server for WPA2/WPA3 Enterprise AP integration
- EAP-AKA′ authentication over Diameter STa
- RADIUS Access-Challenge / Access-Accept flow
- MPPE key export for 802.1X
- RADIUS VLAN assignment
- PGW GTP-C Create Session / Delete Session
- Kernel GTP-U session installation using Linux `gtp0`
- PGW-assigned subscriber IP handling
- Access-side DHCP for UE IP delivery
- ARP proxy for a configurable virtual gateway
- Access-side forwarding integration
- GTP-C transaction correlation
- GTP-C Echo watchdog
- PGW-initiated GTP-C Echo Request handling
- GTP-U Error Indication handling
- Session recovery tombstones
- Duplicate Create Session / StarOS context-replacement protection
- Graceful shutdown improvements

Items still being hardened:

- GTP-U Echo support through Linux kernel GTP generic netlink where supported
- RADIUS Disconnect / CoA recovery against AP/NAS
- Post-activation user-plane health checks
- Broader AP compatibility testing
- Long-duration stability testing

---

## Architecture

```text
UE
 |
 | WPA2/WPA3 Enterprise / 802.1X / EAP-AKA′
 |
Wi-Fi AP / NAS
 |
 | RADIUS Access-Request / Access-Challenge / Access-Accept
 |
VectorCore TWAG
 |
 | Diameter STa / EAP exchange
 |
3GPP AAA / DRA / HSS
 |
VectorCore TWAG
 |
 | GTP-C Create Session / Delete Session
 | GTP-U user-plane through Linux kernel GTP
 |
PGW / P-GW
 |
Internet / IMS / MMS APNs
```

The TWAG has two main sides:

```text
Access side:
  WLAN-facing Ethernet/VLAN interface
  DHCP
  ARP proxy
  MAC/IP authorization binding
  optional RADIUS VLAN assignment

Core side:
  Diameter STa toward AAA/DRA
  GTP-C toward PGW
  GTP-U through Linux kernel GTP
```

---

## Core Concepts

### RADIUS / 802.1X

The AP acts as the RADIUS client/NAS. The TWAG acts as the RADIUS server.

The UE performs EAP-AKA′ through the AP. The AP wraps EAP payloads in RADIUS Access-Request messages. The TWAG forwards the EAP exchange to the AAA/HSS path over Diameter STa.

On EAP success, TWAG sends RADIUS Access-Accept with:

- EAP success
- MS-MPPE-Send-Key
- MS-MPPE-Recv-Key
- Optional VLAN assignment
- Optional Session-Timeout / Termination-Action

### Diameter STa

TWAG connects to the configured AAA/DRA peer over Diameter and exchanges EAP payloads using STa.

The AAA/HSS side is expected to return EAP-AKA′ challenge/success and EAP keying material.

### GTP-C

After successful authentication, TWAG creates a PGW session.

TWAG sends:

```text
GTP-C Create Session Request
```

PGW returns:

```text
GTP-C Create Session Response
subscriber IP
PGW control TEID
PGW user-plane F-TEID
```

TWAG later sends:

```text
GTP-C Delete Session Request
```

when the session is detached, recovered, replaced, or cleaned up.

### GTP-U

GTP-U is handled through Linux kernel GTP. TWAG programs PDP/session state into the kernel and uses a `gtp0` interface for user-plane forwarding.

TWAG must not create a competing userspace UDP/2152 socket that fights the kernel GTP datapath.

### DHCP and ARP

The PGW assigns the subscriber IP, but the Wi-Fi UE expects normal DHCP and ARP behavior.

TWAG provides:

```text
DHCP Offer/Ack with the PGW-assigned subscriber IP
ARP proxy replies for a configurable virtual gateway IP
```

The virtual gateway IP is a TWAG-side construct used for WLAN access behavior. It must not conflict with the PGW subscriber pool.

---

## Example Configuration

```yaml
twag:
  name: twag01
  realm: epc.mnc435.mcc311.3gppnetwork.org

logging:
  level: info
  file: /tmp/vectorcore-twag/twag.log

access:
  interface: enp0s8
  gateway_ip: 100.64.0.1
  netmask: 255.255.255.0
  dns:
    - 8.8.8.8
    - 1.1.1.1

  dhcp:
    enabled: true
    lease_time_seconds: 600
    renewal_time_seconds: 300
    rebinding_time_seconds: 525

  arp_proxy:
    enabled: true

  forwarding:
    enabled: true

radius:
  enabled: true
  listen_addr: 0.0.0.0:1812
  secret: testing123
  vlan_id: 10

  access_accept:
    session_timeout_seconds: 3600
    termination_action: radius_request
    idle_timeout_seconds: 0

aaa:
  sta:
    origin_host: twag01.epc.mnc435.mcc311.3gppnetwork.org
    origin_realm: epc.mnc435.mcc311.3gppnetwork.org
    destination_realm: epc.mnc435.mcc311.3gppnetwork.org
    destination_host: dra01.epc.mnc435.mcc311.3gppnetwork.org
    peer_addr: 10.90.250.35:3868

subscriber:
  default_apn: internet
  default_realm: ims.mnc435.mcc311.3gppnetwork.org

gtp:
  local_gtpc_ip: 192.168.105.97
  local_gtpu_ip: 192.168.105.97
  remote_pgw_gtpc_ip: 10.90.250.92
  remote_pgw_gtpu_ip: 10.90.250.92
  apn: internet
  charging_characteristics: "0800"
  kernel_interface: gtp0

  control_echo:
    enabled: true
    interval_seconds: 30
    timeout_seconds: 5
    max_failures: 3
    startup_probe: true

  user_echo:
    enabled: true
    mode: kernel_netlink
    interval_seconds: 30
    timeout_seconds: 5
    max_failures: 3
    startup_probe: true
    require_kernel_support: false

session_recovery:
  enabled: true
  reason_gtpu_error_indication: true
  recovery_window_seconds: 120
  stale_client_grace_seconds: 10
  cleanup_on_duplicate_attach: true
  allow_same_mac_reattach: true
  reject_old_dhcp_ip: true
  dhcp_stale_request_action: nak

  radius_disconnect:
    enabled: true
    nas_ip: 192.168.105.71
    nas_port: 3799
    secret: testing123
    timeout_seconds: 3
    retries: 2
    request_type: disconnect
    fallback_to_recovery_tombstone: true

routing:
  enable_ip_forwarding: true
  disable_rp_filter: true
  policy_routing: true
  policy_table: 200
  policy_priority: 10000
```

---

## Important Configuration Notes

### Access Gateway IP

The `access.gateway_ip` value is the virtual gateway that TWAG presents to the UE through DHCP and ARP proxy.

This address must be reserved or excluded from the PGW subscriber pool.

Unsafe:

```text
PGW pool: 100.64.0.0/24
TWAG gateway_ip: 100.64.0.1
PGW can assign 100.64.0.1 to a UE
```

Safer:

```text
TWAG virtual gateway: 100.64.0.1
PGW allocatable pool: 100.64.0.2 - 100.64.0.254
```

### RADIUS VLAN Assignment

If the AP expects dynamic VLAN assignment, TWAG can return VLAN attributes in Access-Accept.

Typical attributes:

```text
Tunnel-Type = VLAN
Tunnel-Medium-Type = IEEE-802
Tunnel-Private-Group-ID = <vlan_id>
```

The configured AP switchport must carry that VLAN correctly.

### Session Timeout

For 802.1X, the AP/NAS decides how long the client remains authorized. TWAG can influence this using RADIUS Access-Accept attributes:

```text
Session-Timeout
Termination-Action = RADIUS-Request
```

### RADIUS Disconnect / CoA

TWAG can use RADIUS Dynamic Authorization to force AP-side reauthentication when TWAG has lost the PGW/GTP session.

This normally uses UDP/3799.

The AP/controller must support and allow:

```text
RADIUS Disconnect-Request
RADIUS CoA-Request
shared secret
authorized dynamic authorization client IP
```

If the AP does not support this, TWAG falls back to recovery tombstone behavior and waits for natural reauth.

---

## Session Lifecycle

### Normal Attach

```text
1. UE associates to AP.
2. AP sends RADIUS Access-Request to TWAG.
3. TWAG exchanges EAP-AKA′ with AAA over Diameter STa.
4. AAA returns EAP success and MSK.
5. TWAG creates PGW session over GTP-C.
6. PGW assigns subscriber IP.
7. TWAG installs kernel GTP PDP/session.
8. TWAG installs access binding for MAC/IP.
9. TWAG returns RADIUS Access-Accept.
10. UE sends DHCP.
11. TWAG replies with PGW-assigned IP.
12. TWAG answers ARP for virtual gateway.
13. UE traffic flows through GTP-U.
```

### Normal Detach

```text
1. Session is detached or shutdown begins.
2. TWAG sends GTP-C Delete Session.
3. TWAG removes kernel GTP PDP/session.
4. TWAG removes routes/policy rules.
5. TWAG removes access binding.
6. TWAG releases DHCP/access state.
7. Session is marked terminated.
```

### Failure Recovery

TWAG performs recovery when it sees a mapped GTP-U Error Indication, stale TEID, or similar session failure.

```text
1. TWAG marks the session failed/recovering.
2. TWAG creates a recovery tombstone.
3. TWAG cleans local PGW/kernel/access/DHCP/ARP state.
4. TWAG sends RADIUS Disconnect/CoA if configured.
5. If the AP reauthenticates the UE, TWAG creates a new clean session.
6. If the AP does not respond, TWAG keeps the tombstone and safely rejects stale DHCP/ARP.
```

---

## Duplicate Create Session Protection

StarOS PGW treats duplicate Create Session for the same IMSI/APN/default bearer as context replacement.

The PGW may log:

```text
EBI Collision detection logic resulted in CONTEXT_REPLACEMENT
Create Session Request ... in ACTIVE state
This is context replacement
```

TWAG must prevent this during normal operation.

Rules:

```text
One active or activating session per IMSI/MAC/APN.
If duplicate EAP success occurs for an already-active session, reuse the existing session.
If replacement is required, delete and clean the old session before sending a new Create Session.
Do not rely on PGW context replacement as normal behavior.
```

---

## GTP Echo Behavior

### GTP-C Echo

TWAG sends periodic GTP-C Echo Requests and handles PGW-initiated GTP-C Echo Requests.

Expected logs:

```text
GTP-C echo response received
GTP-C echo request received
GTP-C echo response sent
```

### GTP-U Echo

GTP-U uses the Linux kernel GTP datapath.

Modern Linux kernels may support GTP-U Echo through the kernel GTP generic netlink API.

TWAG should:

```text
detect kernel GTP-U Echo support
trigger GTP-U Echo Request through kernel netlink when supported
observe Echo Response through kernel notification when supported
avoid creating a competing UDP/2152 userspace socket
```

Useful checks:

```bash
uname -r
modinfo gtp | head -50
grep -R "GTP_CMD_ECHOREQ" /usr/include/linux/gtp.h /usr/src/linux-headers-$(uname -r)/include/uapi/linux/gtp.h 2>/dev/null
```

---

## Build

Typical Go project flow:

```bash
go mod tidy
go build -o bin/twag ./cmd/twag
```

If a Makefile exists:

```bash
make build
```

---

## Run

Example:

```bash
sudo ./bin/twag -c /root/twag.yaml
```

or:

```bash
sudo ./bin/twag -d -c /root/twag.yaml
```

TWAG requires sufficient privileges for:

```text
raw socket access
network interface access
Linux kernel GTP netlink operations
routing table updates
policy routing
IP forwarding / rp_filter changes
UDP 1812 RADIUS listen
GTP-C/GTP-U sockets
```

In practice, run as root during lab testing.

---

## Linux Host Requirements

Required or expected:

```text
Linux kernel with gtp.ko
CAP_NET_ADMIN
CAP_NET_RAW
iproute2
tcpdump / tshark for troubleshooting
```

Load/check GTP module:

```bash
modprobe gtp
lsmod | grep gtp
```

Check interface:

```bash
ip link show gtp0
```

Check routing:

```bash
ip rule show
ip route show table 200
ip route get 8.8.8.8 from <subscriber-ip>
```

---

## Troubleshooting

### Check RADIUS / EAP

```bash
tcpdump -ni any -s 0 -w /tmp/twag-radius.pcap 'udp port 1812'
```

Expected sequence:

```text
Access-Request
Access-Challenge
Access-Request
Access-Challenge
Access-Request
Access-Accept
```

### Check GTP-C

```bash
tcpdump -ni any -s 0 -w /tmp/twag-gtpc.pcap 'udp port 2123'
```

Look for:

```text
Create Session Request
Create Session Response
Delete Session Request
Delete Session Response
Echo Request
Echo Response
```

### Check GTP-U

```bash
tcpdump -ni any -s 0 -w /tmp/twag-gtpu.pcap 'udp port 2152'
```

Useful tshark:

```bash
tshark -r /tmp/twag-gtpu.pcap -Y "gtp" \
  -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e gtp.message \
  -e gtp.teid \
  -e gtp.seq
```

Filter Echo/Error only:

```bash
tshark -r /tmp/twag-gtpu.pcap \
  -Y "gtp.message == 1 || gtp.message == 2 || gtp.message == 26" \
  -T fields \
  -e frame.time_relative \
  -e ip.src \
  -e ip.dst \
  -e udp.srcport \
  -e udp.dstport \
  -e gtp.message \
  -e gtp.teid
```

Message types:

```text
0x01 = Echo Request
0x02 = Echo Response
0x1a = Error Indication
0xff = G-PDU / T-PDU
```

### Check Access DHCP / ARP

```bash
tcpdump -ni <access-interface> -e -vvv 'arp or udp port 67 or udp port 68'
```

Expected:

```text
DHCP Discover
DHCP Offer
DHCP Request
DHCP Ack
ARP who-has gateway_ip
ARP reply from TWAG
```

### DHCP ignored unauthorized client

If logs show:

```text
DHCP ignored unauthorized client
authorized=false
```

possible causes:

```text
UE/AP still thinks 802.1X is authorized but TWAG removed PGW session.
Recovery tombstone exists.
RADIUS Disconnect/CoA failed or is not enabled.
UE has not re-run EAP yet.
```

Recommended fix path:

```text
Enable RADIUS Disconnect/CoA if AP supports it.
Set Session-Timeout and Termination-Action in Access-Accept.
Ensure recovery tombstone logs distinguish stale recovery clients from truly unauthorized clients.
```

### GTP-U Error Indication

If PGW sends:

```text
GTP-U Error Indication
```

it means PGW rejected the TEID used by TWAG.

Common causes:

```text
duplicate Create Session caused PGW context replacement
stale local kernel GTP PDP
PGW deleted bearer/session
wrong F-TEID selected
session replacement race
```

Check StarOS logs for:

```text
CONTEXT_REPLACEMENT
EBI Collision
Create Session Request in ACTIVE state
Session deleted
```

### No data after successful auth

Verify:

```bash
ip route get 8.8.8.8 from <subscriber-ip>
ip rule show
ip route show table 200
ip neigh show dev <access-interface>
ip link show gtp0
```

Capture simultaneously:

```bash
tcpdump -ni <access-interface> -w /tmp/access.pcap 'host <subscriber-ip> or arp or udp port 67 or udp port 68'
tcpdump -ni any -w /tmp/gtpu.pcap 'udp port 2152'
```

---

## Development Notes

### Avoid unsafe GTP-U socket behavior

Do not create a second userspace UDP/2152 listener competing with Linux kernel GTP.

Use kernel GTP netlink support where available.

### Cleanup must be idempotent

Cleanup can be triggered by:

```text
GTP-U Error Indication
duplicate attach
shutdown
session recovery
manual detach
PGW context not found
```

Removing an already-removed route, neighbor, PDP context, or session should not panic.

### Shutdown

`Ctrl+C` should:

```text
cancel root context
stop RADIUS
stop accessside loops
detach active sessions
stop GTP echo loops
close GTP sockets/fds
stop Diameter
exit cleanly
```

Every goroutine that reads sockets or raw frames should have:

```text
context cancellation
fd/socket close
WaitGroup tracking
stop timeout
```

---

## Example Log Milestones

Successful attach:

```text
RADIUS Access-Request received
STa EAP answer received state=success
authorized subscriber attach requested
GTP-C Create Session Request sent
GTP-C Create Session Response received gtp_cause=16
PGW assigned subscriber IP
kernel GTP session added
access forwarding neighbor installed
session active
RADIUS Access-Accept sent
DHCP Ack sent
ARP proxy reply sent
```

Healthy operation:

```text
GTP-C echo response received consecutive_failures=0
GTP-C echo request received
GTP-C echo response sent
Diameter watchdog success
DHCP Ack sent
ARP proxy reply sent
```

Recovery:

```text
GTP-U Error Indication received mapped=true
session recovery pending
RADIUS Disconnect-Request sent
fresh RADIUS/EAP reauth observed
session recovery completed
```

Duplicate attach protection:

```text
PGW Create Session decision decision=reuse_existing
duplicate attach suppressed; existing active PGW session reused
```

---

## Security Notes

- Only authorized MAC/IMSI/APN sessions should receive DHCP/ARP service.
- Do not ACK DHCP for a client without an active PGW/GTP session.
- RADIUS shared secrets must be protected.
- RADIUS Dynamic Authorization should only accept/send traffic to trusted AP/NAS IPs.
- Avoid exposing the TWAG management/logging interface on untrusted networks.
- The access VLAN should be isolated from general LAN traffic.

---

## License

Add the project license here.

If this project derives from or incorporates code from another project, preserve required copyright notices and license text.

---

## Project Name

VectorCore TWAG
