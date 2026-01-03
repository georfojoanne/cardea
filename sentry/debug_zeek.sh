#!/bin/bash
# Debug script for Zeek issues

echo "=== Checking Zeek container logs ==="
docker logs cardea-zeek --tail 20

echo ""
echo "=== Checking available network interfaces ==="
ip link show | grep -E '^[0-9]+: '

echo ""
echo "=== Checking if Zeek can access interfaces ==="
docker exec cardea-zeek ip link show 2>/dev/null || echo "Cannot access container"

echo ""
echo "=== Checking Zeek container status ==="
docker inspect cardea-zeek --format='{{.State.Status}}: {{.State.Error}}'

echo ""
echo "=== Testing simple Zeek command ==="
docker exec cardea-zeek zeek --version 2>/dev/null || echo "Zeek not accessible"