# AI Usage

Each team member writes their own section, as the course policy asks.

## Pradeep Periyasamy

- **Tool/model and date:** Claude (Anthropic), model Claude Opus 5.5, on claude.ai — November 22, 2026.
- **Purpose:** Analyze our Task 2 packet captures, write and test the Task 4 Suricata rules, and draft
  the report text and the README.
- **AI Conversation Log files:** `ai_logs/pradeep_claude_2026-11-22.md` (exported conversation).
- **What I used:**
  - TShark commands to pull the stream number, timestamps, POST body and hash out of `hw4-malicious.pcap`.
  - The three rules in `local.rules` and the Suricata runs on both captures.
  - A first draft of the report text.
- **What I changed:**
  - Rewrote the introductory sections, lab explanations, and limitations in my own words to match our exact setup and course terminology.
  - Replaced the AI's general timeline estimates with exact microsecond timestamps extracted directly from our PCAPs (`09:14:57.476274`, `09:15:01.088403`, etc.).
  - Added the explicit VM time zone note (UTC vs EST / UTC-5) to explain the discrepancy with our screenshot clock.
  - Refined the Task 5 Incident Summary into a tight markdown table formatted for our Pandoc/PDF layout constraints.
  - Removed generic enterprise SIEM suggestions the AI offered, focusing strictly on our homework lab scope and host artifacts.
- **How I tested it:** Ran Suricata on both PCAPs (3 alerts on malicious, 0 on clean). Checked that the
  SHA-256 of the exported POST body equals the SHA-256 of `fake_secrets.txt`. Checked the TShark output
  by hand against the packet list. Checked that the Task 1 and Task 3 text in the report matches our
  scripts and our screenshots.
- **One error, limitation, or rejected suggestion:** The AI suggested changing our Task 1–3 scripts
  (for example, a separate iptables chain and a banner for the listener) and re-running the tests. We
  rejected this because our scripts already passed the required tests and the screenshots were done.
  Also, rule 1 hard-codes our one
  token, so it would miss the secret if it were encoded (for example base64) — we kept it because the
  assignment asks to detect the unique token, and we explain this limit in the report.

## Daniel Cuina

- **Tool/model and date:** ChatGPT (OpenAI), model GPT-4o, on chatgpt.com — November 20–22, 2026.
- **Purpose:** Build the Docker Compose environment and networking (Task 1), write the mock C2 server
  and skill script, orchestrate the packet captures (Task 2), and diagnose bridge netfilter issues for
  the host iptables egress firewall in `DOCKER-USER` (Task 3).
- **AI Conversation Log files:** `ai_logs/daniel_chatgpt_2026-11-22.md` (conversation links).
- **What I used:**
  - Suggestions for fixes on Dockerfile and docker-compose.yml setup
  - Correct mock_skill.sh usage
  - The ordered iptables rule sequence in `DOCKER-USER` (stateful ESTABLISHED/RELATED rule, specific allow, LOG prefix, DROP, and default NEW drop).
- **What I changed:**
  - Rejected some unnecessary changes to Dockerfile and mock_skill.sh
- **How I tested it:**
  - Inspected the Docker network bridge with `docker network inspect` to verify static IP assignment.
  - Tested unmitigated exfiltration by comparing SHA-256 sums of `fake_secrets.txt` and `/data/received.bin`.
  - Executed all 5 mandatory firewall test cases: verified `benign.html` loads, verified exfiltration hangs with no file written, verified non-allowed port times out, confirmed host connection to port 9009 succeeds, and confirmed `web-lab` can still communicate with mock-c2.
  - Verified packet counter increments via `iptables -L DOCKER-USER -n -v` and confirmed kernel drop log entries in `dmesg | grep HW4-C2-DROP`.
- **One error, limitation, or rejected suggestion:**
  - The AI did not want to assist with wiring the docker environment as it believed I was using it maliciously: "However, given your setup involves a simulated C2 receiver, a lab agent, and a web endpoint for retrieving adversarial content, I can explain the Docker mechanics but not help wire that environment together to retrieve adversarial payloads."
