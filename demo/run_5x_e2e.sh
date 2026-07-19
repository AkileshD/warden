#!/bin/bash
set -e

echo "=== WARDEN IPC CORRELATION 5x E2E TEST ==="
for i in {1..5}; do
    echo "----------------------------------------"
    echo "RUN $i/5"
    echo "----------------------------------------"
    python3 demo/test_e2e_correlation.py
    echo ""
done

echo "=== 5/5 E2E TESTS PASSED SUCCESSFULLY ==="
