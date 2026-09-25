#!/bin/bash
# PII Redaction Script for conwrt repo history rewrite
# Designed for git filter-branch --tree-filter
# Only targets files known to contain PII (29 files out of 234)
set -euo pipefail

# Build sed expression once — applied to all PII files
SEDEXPR=(
  -e 's/DC:B8:08:6C:EA:7F/DC:B8:08:XX:XX:XX/g'
  -e 's/DC:B8:08:38:70:70/DC:B8:08:XX:XX:XX/g'
  -e 's/DC:B8:08:38:70:60/DC:B8:08:XX:XX:XX/g'
  -e 's/E8:37:7A:9E:F6:86/E8:37:7A:XX:XX:XX/g'
  -e 's/E8:37:7A:9E:F6:8E/E8:37:7A:XX:XX:XX/g'
  -e 's/5C:F4:AB:C8:EE:EC/5C:F4:AB:XX:XX:XX/g'
  -e 's/4C:9E:FF:F5:AC:D2/4C:9E:FF:XX:XX:XX/g'
  -e 's/4c:9e:ff:77:5c:91/4c:9e:ff:xx:xx:xx/g'
  -e 's/74:83:c2:75:08:90/74:83:c2:XX:XX:XX/g'
  -e 's/74:4d:28:72:f6:9f/74:4d:28:XX:XX:XX/g'
  -e 's/a8:63:7d:91:f8:94/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:dc:51:64/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:dc:51:67/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:dc:51:5d/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:dc:51:60/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:8f:61:a8/a8:63:7d:xx:xx:xx/g'
  -e 's/a8:63:7d:8f:61:ab/a8:63:7d:xx:xx:xx/g'
  -e 's/3e:0d:ac:e5:a1:3c/3e:0d:ac:xx:xx:xx/g'
  -e 's/3e:85:be:87:55:42/3e:85:be:xx:xx:xx/g'
  -e 's/00:e0:4c:68:14:06/00:e0:4c:xx:xx:xx/g'
  -e 's/fe80::764d:28ff:fe72:f69f/fe80::xxxx:xxff:fexx:xxxx/g'
  -e 's/S150H29001559/XXXXX-XXXXXXXXX/g'
  -e 's/192\.168\.1\.100/192.168.1.X/g'
  -e 's/192\.168\.1\.147/192.168.1.X/g'
  -e 's/192\.168\.1\.158/192.168.1.X/g'
  -e 's/192\.168\.1\.111/192.168.1.X/g'
  -e 's/192\.168\.1\.66/192.168.1.X/g'
  -e 's/192\.168\.13\.103/192.168.X.X/g'
  -e 's/192\.168\.13\.218/192.168.X.X/g'
  -e 's/109\.247\.114\.4/XXX\.XXX\.XXX\.X/g'
  -e 's/92\.220\.228\.70/XXX\.XXX\.XXX\.X/g'
  -e 's/eduroam/REDACTED_SSID_1/g'
  -e 's/ForskerNett/REDACTED_SSID_2/g'
  -e 's/Intern-OUS/REDACTED_SSID_3/g'
  -e 's/SIKTv2/REDACTED_SSID_4/g'
  -e 's/macbooks-MBP/REDACTED_HOST/g'
  -e 's/id_ed25519_gitlab/REDACTED_KEY/g'
  -e 's/Q\/7PTDaaakgRBt+eTV5jgNX0UuZfbZb53Ipb+FHyMRk/REDACTED_FINGERPRINT/g'
)

# List of files that contain PII (from audit)
PII_FILES=(
  AGENTS.md
  models/dlink-covr-x1860-a1.json
  models/extreme-networks-ws-ap3915i.json
  models/ubnt-edgerouter-6p.json
  models/zyxel-gs1900-24e.json
  models/zyxel-gs1900-8hp-a1.json
  models/zyxel-gs1900-8hp-b1.json
  models/zyxel-gs1920-24.json
  models/zyxel-nr7101.json
  recipes/dlink/covr-x1860/notes.md
  recipes/extreme-networks/ws-ap3915i/REVIEW-UNIT2-FLASH-PLAN.md
  recipes/extreme-networks/ws-ap3915i/SESSION-WRITEUP.md
  recipes/extreme-networks/ws-ap3915i/UNIT2-AP3915i-ROW.md
  recipes/extreme-networks/ws-ap3915i/no-serial-openwrt.md
  recipes/linksys-whw03/NOTES.md
  recipes/ubiquiti/edgerouter-6p/isl28022-research-plan.md
  recipes/ubiquiti/edgerouter-6p/notes.md
  recipes/ubiquiti/edgerouter-6p/poe-diagnosis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/b3-b4-b5-gpio-i2c-engine/evidence.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-1-baseline/gpio-reg-tx-dat.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-2-isl28022-zero-load/isl-0x3F-registers.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-2-isl28022-zero-load/isl-0x40-registers.txt
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-3-gpio-bit-cfg/analysis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-4-pin-mux/findings.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-5-i2c-aggressive/analysis.md
  recipes/ubiquiti/edgerouter-6p/test-evidence/wave-0/w0-6-regression/regression-report.md
  recipes/zyxel/gs1900-24e/notes.md
  recipes/zyxel/gs1900-8hp/notes.md
  recipes/zyxel/gs1920-24/notes.md
  recipes/zyxel/nr7101/notes.md
  tests/test_extreme_ap391x.py
)

for f in "${PII_FILES[@]}"; do
  # Skip if file doesn't exist in this commit (wasn't created yet)
  [ -f "$f" ] || continue
  sed -i '' "${SEDEXPR[@]}" "$f"
done
