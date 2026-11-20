#!/bin/sh
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

set -eu
cd "$(dirname "$0")"
echo "== rustc --test src/contract_std.rs =="
rustc --edition 2021 --test src/contract_std.rs -o /tmp/netevd-hooks-tests
/tmp/netevd-hooks-tests --test-threads=1
echo OK
