#!/bin/bash
echo "=================================================="
echo "MONITORING SCAN RESULTS - WAITING FOR REAL DATA"
echo "=================================================="
echo ""

for i in {1..20}; do
    echo "[$i/20] Checking at $(date +%H:%M:%S)..."

    # Check job status
    RUNNING=$(docker exec asm-platform-db psql -U postgres -d asm_platform -t -c "SELECT COUNT(*) FROM jobs WHERE status = 'RUNNING';" 2>/dev/null | tr -d ' ')
    COMPLETED=$(docker exec asm-platform-db psql -U postgres -d asm_platform -t -c "SELECT COUNT(*) FROM jobs WHERE status = 'COMPLETED';" 2>/dev/null | tr -d ' ')

    echo "  Jobs: $COMPLETED completed, $RUNNING running"

    # Check services for testphp
    TESTPHP_SERVICES=$(docker exec asm-platform-db psql -U postgres -d asm_platform -t -c "SELECT COUNT(*) FROM services s JOIN assets a ON s.\"assetId\" = a.id WHERE a.value = '44.228.249.3';" 2>/dev/null | tr -d ' ')

    echo "  testphp.vulnweb.com services: $TESTPHP_SERVICES"

    # Check findings
    FINDINGS=$(docker exec asm-platform-db psql -U postgres -d asm_platform -t -c "SELECT COUNT(*) FROM findings;" 2>/dev/null | tr -d ' ')

    echo "  Findings: $FINDINGS"

    if [ "$TESTPHP_SERVICES" != "0" ]; then
        echo ""
        echo "✓ testphp services found! Showing details..."
        docker exec asm-platform-db psql -U postgres -d asm_platform -c "SELECT s.port, s.\"serviceName\", s.\"softwareName\" FROM services s JOIN assets a ON s.\"assetId\" = a.id WHERE a.value = '44.228.249.3';"

        if [ "$FINDINGS" != "0" ]; then
            echo ""
            echo "✓ FINDINGS DETECTED! Showing..."
            docker exec asm-platform-db psql -U postgres -d asm_platform -c "SELECT title, severity, \"sourceTool\", \"vulnerabilityRef\" FROM findings LIMIT 10;"
            exit 0
        fi
    fi

    if [ "$RUNNING" = "0" ] && [ "$TESTPHP_SERVICES" = "0" ]; then
        echo "  ⚠️ Scans finished but no testphp services. Port scan may have failed."
    fi

    echo ""
    sleep 30
done

echo "Timeout reached. Final status:"
docker exec asm-platform-db psql -U postgres -d asm_platform -c 'SELECT "toolName", status, COUNT(*) FROM jobs GROUP BY "toolName", status ORDER BY status, "toolName";'
