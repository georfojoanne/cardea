#!/bin/bash
# Suricata service entrypoint script

set -e

echo "🛡️ Starting Suricata intrusion detection service..."

# Validate environment
if [ -z "$SURICATA_INTERFACE" ]; then
    echo "❌ SURICATA_INTERFACE not set, using default: eth0"
    export SURICATA_INTERFACE=eth0
fi

# Update rule sets
echo "📡 Updating Suricata rule sets..."
suricata-update || echo "⚠️ Rule update failed, continuing with existing rules"

# Configure output
cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---

vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

outputs:
  - fast:
      enabled: yes
      filename: fast.log
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            payload-buffer-size: 4kb
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - files:
            force-magic: no
        - smtp
        - flow

af-packet:
  - interface: $SURICATA_INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes

# Rule sets
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

# Detection engine
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

# Logging
logging:
  default-log-level: $LOG_LEVEL
  outputs:
  - console:
      enabled: yes
  - file:
      enabled: yes
      filename: /var/log/suricata/suricata.log
EOF

# Start log processor in background
python3 /app/scripts/log_processor.py &

echo "✅ Suricata configuration complete"
echo "🌐 Monitoring interface: $SURICATA_INTERFACE"

# Start Suricata
exec suricata -c /etc/suricata/suricata.yaml -i $SURICATA_INTERFACE --pidfile /var/run/suricata.pid