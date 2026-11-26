#!/bin/sh
# Starts billing-worker the way production does.
cd "$(dirname "$0")/.." || exit 1
export BILLING_API_KEY=sk_live_M3cMwHyPXBRpwLCUr0IAPOnV
exec python -m billing_worker "$@"
