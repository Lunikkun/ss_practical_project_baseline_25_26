#!/usr/bin/env sh
set -eu

# Redact common secret patterns from CI/CD logs before printing them.
sed -E \
  -e 's/([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]|[Pp][Aa][Ss][Ss]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Tt][Oo][Kk][Ee][Nn]|[Aa][Pp][Ii]_?[Kk][Ee][Yy]|[Dd][Bb]_[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd])=([^[:space:]]+)/\1=***REDACTED***/g' \
  -e 's#(postgres(ql)?://[^:/[:space:]]+:)[^@/[:space:]]+@#\1***REDACTED***@#g' \
  -e 's#(://[^:/[:space:]]+:)[^@/[:space:]]+@#\1***REDACTED***@#g'