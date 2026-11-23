# CSCE 465/765 HW4 — Detect and Block Agent Exfiltration

Team: Pradeep Periyasamy and Daniel Cuina. The report is `report.pdf`; its source is `report.md`.

## Files

| File | Purpose |
|---|---|
| `Dockerfile` | One image for all three containers (`python:3.12.16-slim-trixie` + `curl`, `socat`, `/data`); default command `python3 c2.py` |
| `docker-compose.yml` | Network `br-hw4` (172.30.0.0/24) and the three services with fixed IPs |
| `c2.py` | Mock C2: saves the POST body to `/data/received.bin`, returns 204 |
| `mock_skill.sh` | Mock skill: listener on TCP 9009; with `exfiltrate-course-file` also POSTs `fake_secrets.txt` to mock-c2 |
| `fake_secrets.txt` | Fake token, no trailing newline |
| `web/benign.html`, `web/adversarial.html` | Normal page; page with `CSCE465-COURSE-MARKER` and an injected instruction |
| `firewall.sh`, `firewall-reset.sh` | Task 3 egress policy in `DOCKER-USER`; reset flushes `DOCKER-USER` |
| `local.rules` | Task 4 Suricata rules (SIDs 1000001–1000003) |
| `hw4-malicious.pcap`, `hw4-clean.pcap` | Task 2 captures |
| `evidence/`, `suricata-*/`, `objs/`, `screenshots/` | Saved outputs (TShark and Suricata text output, exported HTTP objects, screenshots) |

## Start the lab (Task 1)

```bash
docker compose up -d --build
docker compose ps
docker network inspect $(docker network ls --format '{{.Name}}' | grep '_hw4net$')
```

The assignment does not say how to start the web server in web-lab, so we start it by hand
(leave this running in its own terminal whenever a test needs web-lab):

```bash
docker compose exec web-lab python3 -m http.server 8000 --bind 0.0.0.0 --directory /app/web
```

Exfiltration with no firewall:

```bash
docker compose exec agent-node ./mock_skill.sh exfiltrate-course-file   # Ctrl-C after the POST
sha256sum fake_secrets.txt
docker compose exec mock-c2 sha256sum /data/received.bin
```

## Task 2

```bash
docker compose exec -d agent-node ./mock_skill.sh       # start listener
nmap 172.30.0.10                                        # scan only agent-node

sudo tcpdump -i br-hw4 -s 0 -w hw4-malicious.pcap 'net 172.30.0.0/24'
#   second terminal:
docker compose exec agent-node curl http://172.30.0.40:8000/adversarial.html
docker compose exec agent-node ./mock_skill.sh exfiltrate-course-file
#   Ctrl-C the capture, then:
tshark -r hw4-malicious.pcap -Y http.request -T fields -e tcp.stream -e ip.src -e tcp.srcport \
       -e ip.dst -e tcp.dstport -e http.request.method -e http.request.uri
tshark -r hw4-malicious.pcap -q -z follow,tcp,ascii,1
tshark -r hw4-malicious.pcap -q --export-objects http,objs/ && sha256sum objs/*
```

The clean capture uses the same tcpdump command with only
`docker compose exec agent-node curl http://172.30.0.40:8000/benign.html`.

## Task 3

```bash
sudo ./firewall.sh                       # apply the rules (run once)
docker compose exec agent-node curl http://172.30.0.40:8000/benign.html          # 1: works
docker compose exec mock-c2 rm /data/received.bin
docker compose exec agent-node ./mock_skill.sh exfiltrate-course-file          # 2: blocked
docker compose exec mock-c2 ls /data                                           #    empty
docker compose exec agent-node curl --max-time 5 http://172.30.0.40:8080/      # 3: times out
nc 172.30.0.10 9009                                                            # 4: connects
docker compose exec web-lab curl -X POST http://172.30.0.66:8080/              # 5: works
sudo iptables -L DOCKER-USER -n -v --line-numbers                              # counters
sudo dmesg | grep HW4-C2-DROP                                                  # log lines
sudo ./firewall-reset.sh                 # remove our rules
```

`br_netfilter` and the sysctl do not survive a reboot; `firewall.sh` sets them each time.
Run `firewall-reset.sh` before running `firewall.sh` again, so rules are not added twice.

## Task 4

```bash
mkdir -p suricata-malicious suricata-clean
suricata -k none -r hw4-malicious.pcap -S local.rules -l suricata-malicious
suricata -k none -r hw4-clean.pcap     -S local.rules -l suricata-clean
cat suricata-malicious/fast.log suricata-clean/fast.log
```

Expected: 3 alerts (SIDs 1000001, 1000002, 1000003) on the malicious capture, 0 on the clean capture.

## Rebuild the report PDF

```bash
pandoc report.md -s --embed-resources -c report.css -o report.html
google-chrome --headless --no-pdf-header-footer --print-to-pdf=report.pdf report.html
```

## Safety

Only fake secrets and local mock services are used. No host folder and no Docker socket is mounted. Scans target only 172.30.0.10.
