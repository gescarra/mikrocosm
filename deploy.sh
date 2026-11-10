#!/usr/bin/env bash
# =====================================================================
#  deploy.sh. Push DNS records to Route 53 from out/dns_records.csv
#
#  Usage:
#    ./deploy.sh                  # apply all records
#    ./deploy.sh --dry-run        # show the change batches without applying
#    ./deploy.sh --ds-records     # print DNSSEC DS records for the parent
#                                 # (reverse zones -> ARIN, forward -> registrar)
#
#  Requires: aws cli v2, configured profile, and out/dns_records.csv
#  (run generate.py first). --ds-records reads only out/dns_zones.env.
# =====================================================================
set -euo pipefail
# (Bash without that line is a choose-your-own-adventure where every ending is bad.)

# --- Configuration ----------------------------------------------------
AWS_PROFILE="example-prod"
SCRIPT_DIR="$(dirname "$0")"
CSV="${SCRIPT_DIR}/out/dns_records.csv"
ZONES_ENV="${SCRIPT_DIR}/out/dns_zones.env"
TTL=300
DRY_RUN=false
DS_ONLY=false

usage() {
    cat <<'EOF'
Usage:
  ./deploy.sh                 apply every record in out/dns_records.csv
  ./deploy.sh --dry-run       print the change batches without applying them
  ./deploy.sh --ds-records    print the DNSSEC DS records to hand to the parent
                              (reverse zones -> ARIN, forward -> registrar)
EOF
}

case "${1:-}" in
    "")           ;;
    --dry-run)    DRY_RUN=true ;;
    --ds-records) DS_ONLY=true ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "ERROR: unknown argument '$1'." >&2; usage >&2; exit 1 ;;
esac

# --- Preflight --------------------------------------------------------
if [[ ! -f "$ZONES_ENV" ]]; then
    echo "ERROR: $ZONES_ENV not found. Run generate.py first." >&2
    exit 1
fi

# Zone IDs come from topology.yml via generate.py
# shellcheck source=out/dns_zones.env
source "$ZONES_ENV"

if [[ -z "${FORWARD_ZONE_ID:-}" || -z "${REVERSE_ZONE_ID:-}" ]]; then
    echo "ERROR: FORWARD_ZONE_ID or REVERSE_ZONE_ID is empty. Check dns section in topology.yml." >&2
    exit 1
fi

if ! command -v aws &>/dev/null; then
    echo "ERROR: aws cli not found in PATH." >&2
    exit 1
fi

# --- DS records (--ds-records) ----------------------------------------
# Route 53 signs the zone, but nothing downstream validates until the
# PARENT publishes a DS record. For the two reverse zones the parent is
# ARIN (the reverse delegation on the net handle); for the forward zone
# it's the domain registrar. This path is read-only. It asks Route 53
# what the KSKs are and formats them, it never changes anything.
if [[ "$DS_ONLY" == "true" ]]; then
    DS_DIR=$(mktemp -d)
    trap 'rm -rf "$DS_DIR"' EXIT

    for spec in "reverse=${REVERSE_ZONE_ID:-}" \
                "reverse6=${REVERSE_V6_ZONE_ID:-}" \
                "forward=${FORWARD_ZONE_ID:-}"; do
        key="${spec%%=*}"
        zid="${spec#*=}"
        if [[ -z "$zid" ]]; then
            continue
        fi

        echo "$zid" > "${DS_DIR}/${key}.id"
        # Zone names come from Route 53 rather than from topology.yml so the
        # label printed next to a DS is the zone that key actually signs.
        aws route53 get-hosted-zone --id "$zid" --profile "$AWS_PROFILE" \
            --query 'HostedZone.Name' --output text \
            > "${DS_DIR}/${key}.name" 2>> "${DS_DIR}/${key}.err" || true
        aws route53 get-dnssec --hosted-zone-id "$zid" --profile "$AWS_PROFILE" \
            --output json \
            > "${DS_DIR}/${key}.json" 2>> "${DS_DIR}/${key}.err" || true
    done

    python3 - "$DS_DIR" <<'DSEOF'
import ipaddress, json, os, sys

ds_dir = sys.argv[1]

SECTIONS = [
    ("Hand these to ARIN (reverse delegations)", ["reverse", "reverse6"]),
    ("Hand this to the domain registrar, NOT ARIN", ["forward"]),
]

# Only used when Route 53 doesn't hand back a mnemonic of its own.
ALGO = {5: "RSASHA1", 7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
        13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448"}
DIGEST = {1: "SHA-1", 2: "SHA-256", 3: "GOST-R-34.11-94", 4: "SHA-384"}


def slurp(key, ext):
    try:
        with open(os.path.join(ds_dir, "%s.%s" % (key, ext))) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def zone_to_cidr(zone):
    """113.0.203.in-addr.arpa -> 203.0.113.0/24, and the nibble
    equivalent for ip6.arpa. Convenience only: it tells you which network
    object to open in ARIN Online. Returns None for anything that is not a
    plain octet/nibble boundary (RFC 2317 style names, for instance)."""
    z = zone.rstrip(".").lower()
    try:
        if z.endswith(".in-addr.arpa"):
            labels = z[: -len(".in-addr.arpa")].split(".")
            if not labels or len(labels) > 4:
                return None
            octets = list(reversed(labels)) + ["0"] * (4 - len(labels))
            return str(ipaddress.ip_network(
                "%s/%d" % (".".join(octets), 8 * len(labels))))
        if z.endswith(".ip6.arpa"):
            nibbles = z[: -len(".ip6.arpa")].split(".")
            if not nibbles or len(nibbles) > 32:
                return None
            packed = "".join(reversed(nibbles)).ljust(32, "0")
            groups = ":".join(packed[i:i + 4] for i in range(0, 32, 4))
            return str(ipaddress.ip_network(
                "%s/%d" % (groups, 4 * len(nibbles))))
    except ValueError:
        return None
    return None


def render(key):
    """Print one zone. Returns False if Route 53 could not be read at all,
    which is a script failure; a zone that is simply not signing yet is a
    real answer and still returns True."""
    zid = slurp(key, "id")
    name = slurp(key, "name").rstrip(".")
    err = slurp(key, "err")
    raw = slurp(key, "json")

    cidr = zone_to_cidr(name) if name else None
    print("  %s%s" % (name or "(zone name unavailable)",
                      "    [%s]" % cidr if cidr else ""))
    print("    Route 53 zone id : %s" % zid)

    if not raw:
        print("    !! could not read DNSSEC state from Route 53")
        seen = set()
        for line in (err or "no output from aws route53 get-dnssec").splitlines():
            line = line.strip()
            # get-hosted-zone and get-dnssec share an .err file and usually
            # fail identically (expired credentials), so say it once.
            if line and line not in seen:
                seen.add(line)
                print("       %s" % line)
        print("")
        return False

    serve = (json.loads(raw).get("Status") or {}).get("ServeSignature", "UNKNOWN")
    ksks = json.loads(raw).get("KeySigningKeys") or []
    print("    Signing status   : %s" % serve)

    if serve != "SIGNING":
        print("")
        print("    !! Not signing yet. Turn on DNSSEC signing in Route 53 first --")
        print("       a DS in the parent for a zone that is not signing takes the")
        print("       whole zone SERVFAIL for every validating resolver.")

    # Only an ACTIVE KSK belongs in the parent. Handing ARIN an inactive one
    # is the same failure as handing it a DS for an unsigned zone.
    active = [k for k in ksks if k.get("Status") == "ACTIVE"]
    if not active:
        print("    !! No ACTIVE key-signing key, so there is no DS to publish.")

    for ksk in active:
        keytag = ksk.get("KeyTag")
        algo_n = ksk.get("SigningAlgorithmType")
        dig_n = ksk.get("DigestAlgorithmType")
        digest = ksk.get("DigestValue", "")
        rdata = ksk.get("DSRecord") or "%s %s %s %s" % (keytag, algo_n, dig_n, digest)
        print("")
        print("    KSK %s" % ksk.get("Name", "(unnamed)"))
        print("      DS rdata      %s" % rdata)
        print("      Key Tag       %s" % keytag)
        print("      Algorithm     %s  (%s)"
              % (algo_n, ksk.get("SigningAlgorithmMnemonic") or ALGO.get(algo_n, "?")))
        print("      Digest Type   %s  (%s)"
              % (dig_n, ksk.get("DigestAlgorithmMnemonic") or DIGEST.get(dig_n, "?")))
        print("      Digest        %s" % digest)

    for ksk in ksks:
        if ksk.get("Status") != "ACTIVE":
            print("")
            print("    skipped KSK %s (status %s) -- only ACTIVE keys go to the parent"
                  % (ksk.get("Name", "(unnamed)"), ksk.get("Status")))
    print("")
    return True


unreadable = []

print("")
print("=" * 70)
print(" DNSSEC DS records -- read from Route 53, nothing was changed")
print("=" * 70)

for heading, keys in SECTIONS:
    present = [k for k in keys if os.path.exists(os.path.join(ds_dir, k + ".id"))]
    if not present:
        continue
    print("")
    print("--- %s %s" % (heading, "-" * max(3, 66 - len(heading))))
    print("")
    for key in present:
        if not render(key):
            unreadable.append(key)

print("In ARIN Online these go on the reverse delegation for the network shown")
print("in brackets. Paste the rdata line, or fill the four fields -- both say the")
print("same thing. ARIN will only take a DS for a zone already delegated to the")
print("Route 53 nameservers for that zone.")
print("")
print("Confirm the parent once ARIN publishes (this asks for the parent-side DS):")
print("  dig +short DS <zone> @9.9.9.10")
print("")

if unreadable:
    sys.stderr.write("ERROR: could not read DNSSEC state for %s (see above).\n"
                     % ", ".join(slurp(k, "id") for k in unreadable))
    sys.exit(1)
DSEOF
    exit 0
fi

if [[ ! -f "$CSV" ]]; then
    echo "ERROR: $CSV not found. Run generate.py first." >&2
    exit 1
fi

# --- Build change batches from CSV ------------------------------------
# One batch per zone, keyed by the CSV's `zone` column. Keep this list in
# step with generate.py: a zone value with no batch here is a record that
# never reaches Route 53, which is exactly how the ip6.arpa PTRs sat
# unpublished. The parser below now refuses to run rather than drop one.
BATCH_DIR=$(mktemp -d)
trap 'rm -rf "$BATCH_DIR"' EXIT

# Python is already a dependency (generate.py). Use it to reliably parse
# the CSV and emit valid Route 53 change-batch JSON.
COUNTS=$(python3 - "$CSV" "$TTL" "$BATCH_DIR" <<'PYEOF'
import csv, json, os, sys

csv_path, ttl, batch_dir = sys.argv[1], int(sys.argv[2]), sys.argv[3]

# Must match the zone values generate.py writes into the csv.
ZONES = ("forward", "reverse", "reverse6")
changes = dict((zone, []) for zone in ZONES)

with open(csv_path, newline="") as f:
    # start=2 so the number reported is the line you open the file to.
    for lineno, row in enumerate(csv.DictReader(f), start=2):
        zone = row["zone"]
        if zone not in changes:
            sys.exit("ERROR: %s line %d: unknown zone %r (expected one of: %s).\n"
                     "       Give it a batch here, or fix generate.py -- a zone\n"
                     "       with nowhere to go must not be silently discarded."
                     % (csv_path, lineno, zone, ", ".join(ZONES)))
        changes[zone].append({
            "Action": "UPSERT",
            "ResourceRecordSet": {
                "Name": row["name"],
                "Type": row["type"],
                "TTL": ttl,
                "ResourceRecords": [{"Value": row["value"]}],
            },
        })

for zone in ZONES:
    with open(os.path.join(batch_dir, zone + ".json"), "w") as f:
        json.dump({"Comment": "AS64500 %s DNS - from topology.yml" % zone,
                   "Changes": changes[zone]}, f, indent=2)

print(" ".join(str(len(changes[zone])) for zone in ZONES))
PYEOF
)

read -r FWD_COUNT REV_COUNT REV6_COUNT <<< "$COUNTS"
echo "Forward zone (example.net): ${FWD_COUNT} records"
echo "Reverse zone (113.0.203.in-addr.arpa): ${REV_COUNT} records"
echo "Reverse v6 zone (0.0.8.b.d.0.1.0.0.2.ip6.arpa): ${REV6_COUNT} records"

# A v6 reverse zone is optional. But holding the records with no zone id
# to put them in is the silent-drop bug, so say so instead of carrying on.
if [[ "${REV6_COUNT:-0}" -gt 0 && -z "${REVERSE_V6_ZONE_ID:-}" ]]; then
    echo "ERROR: ${REV6_COUNT} reverse6 records in $CSV but REVERSE_V6_ZONE_ID is empty." >&2
    echo "       Set dns.reverse_v6_zone_id in topology.yml, then re-run generate.py." >&2
    exit 1
fi

# --- Apply or print ---------------------------------------------------
submit_zone() {
    local label="$1" zone_id="$2" batch="$3" count="$4"

    # Route 53 rejects an empty change batch, so an empty zone is a no-op
    # rather than a submission that fails.
    if [[ "$count" -eq 0 ]]; then
        echo "Skipping ${label}: no records."
        return 0
    fi

    echo "Submitting ${label}..."
    aws route53 change-resource-record-sets \
        --hosted-zone-id "$zone_id" \
        --change-batch "file://${batch}" \
        --profile "$AWS_PROFILE" \
        --output text
}

if [[ "$DRY_RUN" == "true" ]]; then
    echo ""
    echo "=== Forward zone change batch ==="
    cat "${BATCH_DIR}/forward.json"
    echo ""
    echo "=== Reverse zone change batch ==="
    cat "${BATCH_DIR}/reverse.json"
    echo ""
    echo "=== Reverse v6 zone change batch ==="
    cat "${BATCH_DIR}/reverse6.json"
    echo ""
    echo "(dry run — nothing submitted)"
else
    echo ""
    submit_zone "forward zone"    "$FORWARD_ZONE_ID"        "${BATCH_DIR}/forward.json"  "$FWD_COUNT"
    submit_zone "reverse zone"    "$REVERSE_ZONE_ID"        "${BATCH_DIR}/reverse.json"  "$REV_COUNT"
    submit_zone "reverse v6 zone" "${REVERSE_V6_ZONE_ID:-}" "${BATCH_DIR}/reverse6.json" "$REV6_COUNT"

    echo ""
    echo "Done. Changes may take up to 60s to propagate within Route 53."
fi
