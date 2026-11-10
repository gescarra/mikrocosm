#!/usr/bin/env python3
"""
AS64500 / BYOIP -> AWS the classic way, without IPAM. IPv4 and IPv6.

  .env  ->  preflight (RDAP + account)  ->  ROA  ->  provision-byoip-cidr
        ->  address pool

This is onboard_ipam.py's sibling. Same .env, same certificate.pem and
private-key.pem, same ARIN calls, same signed-message ownership proof. But
the CIDR goes straight to EC2 through `provision-byoip-cidr` instead of into an
IPAM pool. AWS calls this the RDAP/X.509 method; it predates IPAM and is still
the shortest path for one prefix in one Region.

Standalone on purpose: it imports nothing from onboard_ipam.py, so either
script can be copied to a jump host by itself.
Copy-paste friendly by design. For once, that's a feature.

WHAT THIS PATH DOES NOT GIVE YOU

    no BYOASN            Bringing your own ASN is IPAM-only. Provision-ipam-
                         byoasn takes an --ipam-id and there's no non-IPAM
                         equivalent. Your space is advertised from Amazon's
                         AS16509/AS14618, NOT from AS64500. Read the note at
                         the bottom of this file: that's a second origin AS
                         for the same prefix, not just a second router.
    one Region           The classic path binds the range to AWS_REGION.
                         Splitting one allocation across Regions is what IPAM's
                         regional pools are for; here the whole prefix lands in
                         one Region.
    no sharing           No AWS RAM sharing across accounts without IPAM.

    ROA maxLength        AWS wants maxLength == the size of the CIDR you're
                         bringing (so /24 for a /24), not the per-Region floor
                         IPAM insists on. --roa-max-length overrides it if you
                         intend to bring sub-blocks of a larger allocation to
                         other Regions later.

Every step reads live state first and skips itself if already done, so the
script is safe to re-run after any failure or timeout. And it will time out:
AWS takes up to a week to provision a publicly advertisable range.

    python3 aws/onboard_byoip.py --status    # read-only: where am I?
    python3 aws/onboard_byoip.py --dry-run   # print what would be sent, send nothing
    python3 aws/onboard_byoip.py             # run, prompting before each mutation
    python3 aws/onboard_byoip.py --step roa  # run one step only

IPv6 that you don't want on the public internet skips ROAs entirely and
provisions in minutes rather than days. The range is reachable only over
Direct Connect / VPN / Transit Gateway:

    python3 aws/onboard_byoip.py --no-publicly-advertisable

Offboarding unwinds it in reverse dependency order. Withdraw the CIDR,
deprovision it, delete the two Amazon ROAs, remove the certificate from RDAP.
Same modes:

    python3 aws/onboard_byoip.py --offboard --dry-run   # preview the teardown
    python3 aws/onboard_byoip.py --offboard             # run it, prompting

Reads .env from this directory (IPAM_ID is ignored here). certificate.pem and
private-key.pem live next to this file; .gitignore keeps them out of the repo
and this script in.

ONBOARDING NEVER ADVERTISES. It stops once the CIDR is provisioned and the
address pool exists. br1/br2 remain the only originators of the /24. See
AD-LOG.md §2. Advertising is a deliberate, separate act:

    aws ec2 advertise-byoip-cidr --cidr 203.0.113.0/24

Read the note at the bottom of this file before you run that. If you have
already run it, --offboard withdraws it again (that's a live change).
"""

import argparse
import base64
import datetime
import ipaddress
import json
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from getpass import getpass

HERE = pathlib.Path(__file__).resolve().parent   # aws/
ENVFILE = HERE / ".env"                          # shared with onboard_ipam.py
CERT = HERE / "certificate.pem"
PRIVKEY = HERE / "private-key.pem"

ORG_HANDLE = "RCL-264"
ARIN_REG = "https://reg.arin.net/rest"
RDAP = "https://rdap.arin.net/registry"

# AWS commercial origin ASNs. GovCloud would be 8987 instead of these; the
# European Sovereign Cloud would be 16509 + 214101.
AWS_ASNS = [16509, 14618]

RPKI_NS = "http://www.arin.net/regrws/rpki/v1"
CORE_NS = "http://www.arin.net/regrws/core/v1"

# Most specific prefix AWS will take, by family. A non-publicly-advertisable
# IPv6 range is allowed to be longer (/60) because nothing about it has to
# survive an internet-facing BGP filter.
BYOIP_MIN_LEN = {4: 24, 6: 48}
BYOIP_MIN_LEN_PRIVATE = {6: 60}

# States that mean "AWS has the range". provisioned-not-publicly-advertisable
# is the terminal state for --no-publicly-advertisable ranges: there's no
# advertise step for those, and that's success, not a stall.
PROVISIONED = ("provisioned", "provisioned-not-publicly-advertisable",
               "advertised", "pending-advertising", "pending-withdrawal")


# ---------------------------------------------------------------------
#  environment
# ---------------------------------------------------------------------
def load_env(args):
    """Parse .env. Values may or may not be quoted; strip either way.

    Unlike onboard_ipam.py there's no ASN-only mode. BYOASN needs IPAM.
    So PREFIX is required and ASN is advisory: it's used to check that your
    own origin ROA exists before the Amazon ones are added, which is the order
    AWS asks for when you're migrating an advertised prefix.
    """
    env = {}
    for line in ENVFILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    missing = {"ARIN_API_KEY", "AWS_REGION", "AWS_PROFILE"} - env.keys()
    if missing:
        die(f".env is missing: {', '.join(sorted(missing))}")

    env["ASN"] = env.get("ASN", "").strip() or None
    env["PREFIX"] = env.get("PREFIX", "").strip() or None
    if not env["PREFIX"]:
        die(".env sets no PREFIX. This script onboards a CIDR; there is no "
            "ASN-only\n        mode because BYOASN requires IPAM "
            "(onboard_ipam.py).")
    if env["ASN"] and not env["ASN"].isdigit():
        die(f"ASN={env['ASN']} is not a plain AS number (no 'AS' prefix, "
            f"no dot notation).")

    # Command line beats .env; .env beats the AWS default of "advertisable".
    env["_public"] = _env_bool(env.get("PUBLICLY_ADVERTISABLE"), True)
    if args.no_publicly_advertisable:
        env["_public"] = False
    env["_nbg"] = (args.network_border_group
                   or env.get("NETWORK_BORDER_GROUP", "").strip() or None)
    env["_desc"] = (args.description
                    or env.get("BYOIP_DESCRIPTION", "").strip() or None)
    return env


def _env_bool(value, default):
    if value is None or not value.strip():
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------
#  address family
#
#  Everything family-dependent hangs off the parsed PREFIX, so there's one
#  place to look when v4 and v6 disagree.
# ---------------------------------------------------------------------
def parse_prefix(env, args):
    """Validate PREFIX and stash it as an ip_network in env['_net']."""
    try:
        net = ipaddress.ip_network(env["PREFIX"], strict=True)
    except ValueError as e:
        die(f"PREFIX={env['PREFIX']} is not a valid CIDR: {e}")

    if net.version == 4 and not env["_public"]:
        die("non-publicly-advertisable is IPv6 only (--no-publicly-"
            "advertisable, or\n        PUBLICLY_ADVERTISABLE=false in .env). "
            "Every IPv4 range you bring to AWS\n        is publicly "
            "advertisable; there is no private-use BYOIPv4.")

    floor = (BYOIP_MIN_LEN[net.version] if env["_public"]
             else BYOIP_MIN_LEN_PRIVATE[net.version])
    if net.prefixlen > floor:
        kind = (f"an IPv{net.version}" if env["_public"]
                else f"a non-publicly-advertisable IPv{net.version}")
        die(f"PREFIX={env['PREFIX']} is longer than /{floor}. AWS BYOIP will "
            f"not take\n        {kind} block smaller than /{floor}.")
    # Normalise: AWS and ARIN both want the canonical form, and comparing
    # describe-* output against a differently-written string silently misses.
    env["PREFIX"] = str(net)
    env["_net"] = net

    # maxLength only means anything for a range AWS will advertise. The
    # non-advertisable path creates no ROA at all, so a floor written for
    # advertisable space (/48) must not be applied to a legitimate /60.
    env["_roa_len"] = None
    if env["_public"]:
        env["_roa_len"] = args.roa_max_length or net.prefixlen
        if not (net.prefixlen <= env["_roa_len"] <= BYOIP_MIN_LEN[net.version]):
            die(f"--roa-max-length {env['_roa_len']} is outside "
                f"/{net.prefixlen}../{BYOIP_MIN_LEN[net.version]}.\n"
                f"        It cannot be shorter than the prefix itself, and AWS "
                f"never advertises\n        anything more specific than "
                f"/{BYOIP_MIN_LEN[net.version]}.")
    elif args.roa_max_length:
        die("--roa-max-length is meaningless for a range that is not publicly "
            "advertisable:\n        AWS requires no ROA for one.")


def family(env):
    return env["_net"].version


def has_asn(env):
    return env["ASN"] is not None


def die(msg):
    print(f"\n  FAIL  {msg}\n", file=sys.stderr)
    sys.exit(1)


def step(msg):
    print(f"\n=== {msg}")


def ok(msg):
    print(f"  ok    {msg}")


def skip(msg):
    print(f"  skip  {msg}")


def wait(msg):
    print(f"  wait  {msg}")


def confirm(msg, args):
    """Gate every mutation. --dry-run refuses, --yes waves through."""
    if args.dry_run:
        print(f"  DRY   would: {msg}")
        return False
    if args.yes:
        return True
    reply = input(f"\n  {msg}\n  Proceed? [y/N] ").strip().lower()
    return reply == "y"


# ---------------------------------------------------------------------
#  aws cli
# ---------------------------------------------------------------------
def aws_raw(env, *cmdline):
    """Run an aws command, returning (returncode, parsed_json_or_None, stderr)."""
    cmd = ["aws", "--profile", env["AWS_PROFILE"], "--region", env["AWS_REGION"],
           "--output", "json", *cmdline]
    p = subprocess.run(cmd, capture_output=True, text=True)
    data = None
    if p.returncode == 0 and p.stdout.strip():
        data = json.loads(p.stdout)
    elif p.returncode == 0:
        data = {}
    return p.returncode, data, p.stderr.strip()


def aws(env, *cmdline, check=True):
    rc, data, err = aws_raw(env, *cmdline)
    if rc != 0:
        if check:
            die(f"aws {' '.join(cmdline[:2])} failed:\n{err}")
        return None
    return data


# ---------------------------------------------------------------------
#  arin
# ---------------------------------------------------------------------
def arin(env, method, path, body=None):
    url = f"{ARIN_REG}/{path}?apikey={env['ARIN_API_KEY']}"
    data = body.encode() if body else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Accept": "application/xml",
                                          "Content-Type": "application/xml"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def redact(text, env):
    return text.replace(env["ARIN_API_KEY"], "<ARIN_API_KEY>")


def get_json(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return json.load(r)


# ---------------------------------------------------------------------
#  message signing
#
#  Format and signing recipe are AWS's, from prepare-for-byoip:
#    text:   1|aws|ACCOUNT|CIDR|YYYYMMDD|SHA256|RSAPSS
#    sign:   openssl dgst -sha256 -sigopt rsa_padding_mode:pss \
#              -sigopt rsa_pss_saltlen:-1 -sign private-key.pem \
#            | openssl base64 | tr. '+=/' '-_~' | tr -d "\n"
#
#  saltlen:-1 is RSA_PSS_SALTLEN_DIGEST, hence PSS.DIGEST_LENGTH below.
#  The tr is NOT standard urlsafe b64: + -> -, = -> _, / -> ~.
#
#  Identical to onboard_ipam.py: same key, same certificate, same RIR. Only
#  the API that consumes the result differs.
# ---------------------------------------------------------------------
def default_expiry():
    """AWS defaults the message expiry to the last day of next month."""
    today = datetime.date.today()
    first_this = today.replace(day=1)
    first_next = (first_this + datetime.timedelta(days=32)).replace(day=1)
    first_after = (first_next + datetime.timedelta(days=32)).replace(day=1)
    return (first_after - datetime.timedelta(days=1)).strftime("%Y%m%d")


_passphrase = None


def load_key():
    global _passphrase
    from cryptography.hazmat.primitives import serialization

    if not PRIVKEY.exists():
        die(f"{PRIVKEY} not found. It is the key whose certificate is in RDAP.")
    data = PRIVKEY.read_bytes()
    if _passphrase is None:
        _passphrase = getpass(f"  passphrase for {PRIVKEY.name}: ").encode()
    try:
        return serialization.load_pem_private_key(data, password=_passphrase)
    except (ValueError, TypeError) as e:
        die(f"could not load {PRIVKEY}: {e}")


def message_text(account, resource, expiry):
    """The authorization message. Needs no key, so it's safe to show first."""
    return f"1|aws|{account}|{resource}|{expiry}|SHA256|RSAPSS"


def sign_message(text):
    """Sign an authorization message. Prompts for the passphrase on first use,
    so it's only called once the operator has confirmed the mutation."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    sig = load_key().sign(
        text.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.DIGEST_LENGTH),
        hashes.SHA256(),
    )
    return (base64.b64encode(sig).decode()
            .replace("+", "-").replace("=", "_").replace("/", "~"))


# ---------------------------------------------------------------------
#  preflight
# ---------------------------------------------------------------------
def rdap_certs(kind, ident):
    """Pull every PEM cert out of an RDAP object's remarks."""
    try:
        obj = get_json(f"{RDAP}/{kind}/{ident}")
    except urllib.error.HTTPError as e:
        die(f"RDAP lookup {kind}/{ident} returned HTTP {e.code}")
    out = []
    for remark in obj.get("remarks", []):
        for desc in remark.get("description", []):
            if "BEGIN CERTIFICATE" in desc:
                out.append(desc.strip())
    return out


def ipam_holders(env):
    """IPAM pools that already hold PREFIX, as [(pool_id, state)].

    A prefix can be provisioned through IPAM or through provision-byoip-cidr,
    never both, and AWS's rejection when you try isn't obvious. Returns [] if
    the account has no IPAM or the caller can't see it. Absence of evidence,
    which is why nothing here is fatal on its own.
    """
    pools = aws(env, "ec2", "describe-ipam-pools", check=False)
    if not pools:
        return []
    out = []
    for p in pools.get("IpamPools", []):
        if p["State"] == "delete-complete":
            continue
        if p.get("AddressFamily") != f"ipv{family(env)}":
            continue
        cidrs = aws(env, "ec2", "get-ipam-pool-cidrs",
                    "--ipam-pool-id", p["IpamPoolId"], check=False) or {}
        for c in cidrs.get("IpamPoolCidrs", []):
            if c["Cidr"] == env["PREFIX"] and c["State"] != "deprovisioned":
                out.append((p["IpamPoolId"], c["State"]))
    return out


def preflight(env):
    step("Preflight")

    ident = aws(env, "sts", "get-caller-identity")
    account = ident["Account"]
    ok(f"AWS account {account} as {ident['Arn'].split('/')[-1]}")

    if not CERT.exists():
        die(f"{CERT} not found. AWS matches this against the RDAP remarks.")
    cert = CERT.read_text().strip()
    if "\n" in cert:
        die(f"{CERT} contains newlines. AWS requires one single long line.")

    # Only the NET record matters here. onboard_ipam.py also checks the ASN
    # record because BYOASN reads it; nothing in this path does.
    found = rdap_certs("ip", env["PREFIX"])
    if not found:
        die(f"no X.509 certificate in the RDAP remarks of the NET record "
            f"({env['PREFIX']}).\n        ARIN Online -> the Network object "
            f"-> Public Comments, one single long line\n        including the "
            f"BEGIN/END CERTIFICATE markers.")
    if cert not in found:
        die(f"the NET RDAP record has a certificate, but it is not the one in "
            f"{CERT}.\n        AWS will verify the signature from the local "
            f"key against the published\n        cert and reject it.")
    ok(f"NET RDAP remarks carry the cert in {CERT.name}")

    held = ipam_holders(env)
    if held:
        where = ", ".join(f"{pid} ({state})" for pid, state in held)
        die(f"{env['PREFIX']} is already provisioned into IPAM: {where}.\n"
            f"        A CIDR lives in one path or the other, never both. Use "
            f"onboard_ipam.py,\n        or offboard it from IPAM first.")

    return account


# ---------------------------------------------------------------------
#  ROAs
#
#  ARIN emits <roaSpec> in the core namespace but its children in the rpki
#  namespace, so everything below matches on local names, not qualified tags.
# ---------------------------------------------------------------------
def _local(tag):
    """Strip the {namespace} from an ElementTree tag."""
    return tag.rsplit("}", 1)[-1]


def _kids(elem, name):
    return [c for c in elem if _local(c.tag) == name]


def _text(elem, name):
    found = _kids(elem, name)
    return found[0].text if found else None


def _norm_addr(text):
    """ARIN's startAddress as an ip_address, or None if it's not one.

    ARIN zero-pads v4 octets (203.0.113.000), which ip_address() rejects
    outright, so strip the padding by hand. v6 comes back in either expanded
    or compressed form and ip_address() normalises both. Returning None on
    anything unparseable matters: this runs over EVERY roaSpec in the org,
    not just the ones covering PREFIX, so one odd record must not take the
    whole script down."""
    text = (text or "").strip()
    if not text:
        return None
    try:
        if ":" in text:
            return ipaddress.ip_address(text)
        return ipaddress.ip_address(
            ".".join(str(int(o)) for o in text.split(".") if o != ""))
    except ValueError:
        return None


def _blocks(spec):
    """The address blocks inside one <roaSpec>.

    Two shapes are in play: the POST payload below wraps each block in a
    <roaSpecResource>, while the listing has been seen writing the fields
    directly under <resources>. Accept either. Guessing wrong here doesn't
    raise, it silently reports that you have no ROAs at all, which would have
    this script offer to create duplicates of ROAs that already exist."""
    for res in _kids(spec, "resources"):
        nested = _kids(res, "roaSpecResource")
        for block in (nested or [res]):
            yield block


def list_roas(env):
    """Every parseable ROA in the org, as [{asn, net, maxLength, handle}]."""
    status, body = arin(env, "GET", f"roa/{ORG_HANDLE}")
    if status != 200:
        die(f"ARIN ROA list returned HTTP {status}:\n{redact(body, env)}")

    out = []
    for spec in ET.fromstring(body).iter():
        if _local(spec.tag) != "roaSpec":
            continue
        asn = _text(spec, "asNumber")
        handle = _text(spec, "roaHandle")
        for res in _blocks(spec):
            start = _norm_addr(_text(res, "startAddress"))
            clen = _text(res, "cidrLength")
            mlen = _text(res, "maxLength") or clen
            if start is None or not (clen or "").isdigit():
                continue
            try:
                net = ipaddress.ip_network(f"{start}/{clen}", strict=False)
            except ValueError:
                continue
            out.append({"asn": int(asn), "net": net,
                        "maxLength": int(mlen), "handle": handle})
    return out


def covering_roas(env):
    """{asn: roa} for ROAs that actually authorise PREFIX.

    Not just exact matches: AWS is explicit that one ROA over a larger block
    covers every sub-block you bring from it, so a /20 ROA with maxLength /24
    authorises the /24 in .env and no second ROA is needed. Matching only the
    exact prefix would have this script offer to create a redundant one.
    """
    want = env["_net"]
    out = {}
    for r in sorted(list_roas(env), key=lambda r: r["net"].prefixlen,
                    reverse=True):
        net = r["net"]
        if net.version != want.version or not net.supernet_of(want):
            continue
        if r["maxLength"] < want.prefixlen:
            continue          # covers the space but not down to our length
        # setdefault, not assignment: the sort puts the most specific ROA
        # first and that's the one worth reporting for an ASN.
        out.setdefault(r["asn"], r)
    return out


def exact_roas(env):
    """ROAs written against PREFIX itself. Offboarding only ever deletes these.
    A covering ROA over a larger block almost certainly protects space
    this script never touched."""
    return [r for r in list_roas(env)
            if r["net"].version == env["_net"].version
            and r["net"] == env["_net"]]


def step_roa(env, args):
    step("ROAs")
    if not env["_public"]:
        skip("range is not publicly advertisable; AWS requires no ROA for it")
        return
    have = covering_roas(env)

    for asn, r in sorted(have.items()):
        how = "" if r["net"] == env["_net"] else f" (via {r['net']})"
        ok(f"AS{asn} has a ROA for {env['PREFIX']} maxLength "
           f"/{r['maxLength']}{how}")

    # AWS is explicit about the order when you're moving an advertised
    # prefix: your own origin ROA first, Amazon's second. Reversed, you can
    # invalidate your own live announcement for as long as it takes to notice.
    if has_asn(env):
        if int(env["ASN"]) not in have:
            die(f"no ROA authorising your own AS{env['ASN']} over "
                f"{env['PREFIX']}.\n        Create that one FIRST -- br1/br2 "
                f"originate this prefix today (AD-LOG.md §2),\n        and "
                f"adding Amazon's ROAs while yours is missing makes your own\n"
                f"        announcement RPKI-invalid.")
    else:
        print("  note  no ASN in .env, so the ROA for your own origin AS is not")
        print("        checked. If anything of yours advertises this prefix "
              "today, its")
        print("        ROA must exist before the Amazon ones are added.")

    missing = [a for a in AWS_ASNS if a not in have]
    if not missing:
        skip("both AWS ASNs already covered")
        return

    mlen = env["_roa_len"]
    print(f"\n  Missing ROAs for: {', '.join(f'AS{a}' for a in missing)}")
    print("  AWS will not provision the CIDR without these, and reserves the")
    print("  right to stop advertising if they are absent or non-compliant.")
    print(f"  maxLength /{mlen} == the size of the CIDR being brought in, "
          f"which is")
    print("  what AWS asks for on the non-IPAM path.")
    print("\n  autoLink=false: this does NOT create IRR route objects. AWS "
          "updates RADb")
    print("  itself for BYOIP, and its docs are explicit that manual IRR "
          "entries")
    print("  naming the BYOIP ASN make the provision call fail.")

    net = str(env["_net"].network_address)
    clen = env["_net"].prefixlen

    for asn in missing:
        payload = (
            f'<rpkiTransaction xmlns="{RPKI_NS}">\n'
            f"  <roaSpecAdd>\n"
            f"    <roaSpec>\n"
            f"      <autoLink>false</autoLink>\n"
            f"      <asNumber>{asn}</asNumber>\n"
            f"      <name>AWS-BYOIP-{asn}</name>\n"
            f"      <resources>\n"
            f"        <roaSpecResource>\n"
            f"          <startAddress>{net}</startAddress>\n"
            f"          <cidrLength>{clen}</cidrLength>\n"
            f"          <maxLength>{mlen}</maxLength>\n"
            f"        </roaSpecResource>\n"
            f"      </resources>\n"
            f"    </roaSpec>\n"
            f"  </roaSpecAdd>\n"
            f"</rpkiTransaction>"
        )
        print(f"\n  --- POST {ARIN_REG}/rpki/{ORG_HANDLE}?apikey=<ARIN_API_KEY>")
        print("\n".join(f"  {ln}" for ln in payload.splitlines()))

        if not confirm(f"create ROA authorising AS{asn} to originate "
                       f"{env['PREFIX']}", args):
            skip(f"AS{asn} ROA not created")
            continue

        status, body = arin(env, "POST", f"rpki/{ORG_HANDLE}", payload)
        if status not in (200, 201):
            die(f"ARIN returned HTTP {status}:\n{redact(body, env)}")
        handle = next((e.text for e in ET.fromstring(body).iter()
                       if _local(e.tag) == "roaHandle"), "?")
        ok(f"AS{asn} ROA created, handle {handle}")

    print("\n  ROAs can take up to 24h to reach Amazon's validators.")


# ---------------------------------------------------------------------
#  step: provision
# ---------------------------------------------------------------------
def describe_byoip(env):
    """Every BYOIP range in this Region.

    --max-results isn't optional. `aws ec2 describe-byoip-cidrs help` lists it
    among the pagination options, which makes it look like the CLI will fill it
    in, but MaxResults is a required member of the API model (min 1, max 100)
    and omitting it fails argument validation before any call is made. 100 is
    the model's ceiling and the default quota is 5 ranges per Region, so one
    page is always the whole answer."""
    return aws(env, "ec2", "describe-byoip-cidrs",
               "--max-results", "100")["ByoipCidrs"]


def byoip_entry(env):
    """The describe-byoip-cidrs record for PREFIX, or None. This is the whole
    state machine on the classic path. There are no pools to interrogate,
    the CIDR either is or isn't provisioned to this Region."""
    return next((c for c in describe_byoip(env)
                 if c["Cidr"] == env["PREFIX"]), None)


def step_provision(env, args, account):
    step("Provision CIDR")
    entry = byoip_entry(env)
    state = entry["State"] if entry else None

    if state in PROVISIONED:
        skip(f"{env['PREFIX']} is already {state} in {env['AWS_REGION']}")
        return
    if state == "pending-provision":
        wait(f"{env['PREFIX']} is {state}.")
        print("        Publicly advertisable ranges can take up to a week; "
              "most finish")
        print("        within two hours. Re-run to pick up where this left "
              "off.")
        return
    if state == "pending-deprovision":
        wait(f"{env['PREFIX']} is {state}. Let the deprovision finish first.")
        return
    if state == "failed-provision":
        print(f"\n  {env['PREFIX']} is in failed-provision:")
        print(f"    {entry.get('StatusMessage') or '(no status message)'}")
        print("  Usual causes: the ROAs have not reached Amazon's validators "
              "yet (24h),")
        print("  the RDAP certificate does not match the signing key, or the")
        print("  authorization message has expired. Fix the cause, then "
              "provision again")
        print("  -- no deprovision is needed after a failure.")

    expiry = args.expiry or default_expiry()
    text = message_text(account, env["PREFIX"], expiry)
    print(f"\n  Message: {text}")
    print(f"  Expires: {expiry}  (signed with {PRIVKEY.name})")
    print(f"  Region:  {env['AWS_REGION']}"
          + (f"  network border group {env['_nbg']}" if env["_nbg"] else ""))
    public = ("yes" if env["_public"]
              else "NO -- reachable only over Direct Connect / VPN / TGW")
    print(f"  Public:  {public}")
    print("\n  A range belongs to one Region at a time, and publicly "
          "advertisable is")
    print("  fixed at provision time -- neither can be changed without "
          "deprovisioning.")

    if not confirm(f"provision {env['PREFIX']} to {env['AWS_REGION']}", args):
        return

    sig = sign_message(text)
    cmd = ["ec2", "provision-byoip-cidr",
           "--cidr", env["PREFIX"],
           "--cidr-authorization-context", f"Message={text},Signature={sig}"]
    # v4 is publicly advertisable by definition; only v6 takes the flag, and
    # it's passed either way so the intent is explicit in CloudTrail.
    if family(env) == 6:
        cmd.append("--publicly-advertisable" if env["_public"]
                   else "--no-publicly-advertisable")
    if env["_nbg"]:
        cmd += ["--network-border-group", env["_nbg"]]
    if env["_desc"]:
        cmd += ["--description", env["_desc"]]

    rc, _, err = aws_raw(env, *cmd)
    if rc != 0:
        die(f"provision-byoip-cidr refused:\n{err}")
    ok(f"{env['PREFIX']} submitted; state pending-provision")
    if env["_public"]:
        print("        Up to a week for a publicly advertisable range. "
              "Re-run to continue.")
    else:
        print("        Non-advertisable ranges usually finish within minutes.")


# ---------------------------------------------------------------------
#  step: address pool
#
#  Read-only. On the classic path AWS creates the pool for you the moment the
#  CIDR reaches 'provisioned'; there's nothing to create, only something to
#  confirm and then allocate from.
# ---------------------------------------------------------------------
def v4_pool(env):
    pools = aws(env, "ec2", "describe-public-ipv4-pools", check=False) or {}
    for p in pools.get("PublicIpv4Pools", []):
        for r in p.get("PoolAddressRanges", []):
            first = _norm_addr(r.get("FirstAddress"))
            if first is not None and first in env["_net"]:
                return p
    return None


def v6_pool(env):
    pools = aws(env, "ec2", "describe-ipv6-pools", check=False) or {}
    for p in pools.get("Ipv6Pools", []):
        for block in p.get("PoolCidrBlocks", []):
            try:
                net = ipaddress.ip_network(block["Cidr"], strict=False)
            except ValueError:
                continue
            if net.version == 6 and net.subnet_of(env["_net"]):
                return p
    return None


def step_pool(env, args):
    step("Address pool")
    entry = byoip_entry(env)
    if not entry:
        skip(f"{env['PREFIX']} is not provisioned yet; no pool exists")
        return
    if entry["State"] not in PROVISIONED:
        wait(f"{env['PREFIX']} is {entry['State']}; the pool appears once it "
             f"is provisioned")
        return

    if family(env) == 4:
        pool = v4_pool(env)
        if not pool:
            wait("no public IPv4 pool visible yet for this range")
            return
        ok(f"pool {pool['PoolId']}  {pool.get('TotalAvailableAddressCount')}"
           f"/{pool.get('TotalAddressCount')} addresses available"
           + (f"  nbg {pool['NetworkBorderGroup']}"
              if pool.get("NetworkBorderGroup") else ""))
        print("\n  Allocate from it without advertising anything -- this is how "
              "you stage")
        print("  resources before any routing changes:")
        print(f"    aws --profile {env['AWS_PROFILE']} --region "
              f"{env['AWS_REGION']} ec2 allocate-address \\")
        print(f"        --public-ipv4-pool {pool['PoolId']}")
    else:
        pool = v6_pool(env)
        if not pool:
            wait("no IPv6 pool visible yet for this range")
            return
        blocks = ", ".join(b["Cidr"] for b in pool.get("PoolCidrBlocks", []))
        ok(f"pool {pool['PoolId']}  {blocks}")
        print("\n  Associate a block with a VPC:")
        print(f"    aws --profile {env['AWS_PROFILE']} --region "
              f"{env['AWS_REGION']} ec2 associate-vpc-cidr-block \\")
        print(f"        --vpc-id vpc-... --ipv6-pool {pool['PoolId']} \\")
        print(f"        --ipv6-cidr-block <a /56 from {env['PREFIX']}>")


# ---------------------------------------------------------------------
#  OFFBOARDING: reverse the onboarding, in dependency order.
#
#    withdraw -> release allocations -> deprovision -> delete Amazon ROAs
#    -> remove certificate
#
#  The order isn't cosmetic:
#    - AWS refuses to deprovision a range it's still advertising
#    - it refuses again while any EIP or VPC association still holds space
#      from the range
#    - the ROAs go last: dropping the Amazon ROAs while AWS still advertises
#      would make AWS's own announcement RPKI-invalid
#
#  Every mutation is gated by confirm(); deprovision is async and is meant to
#  be re-run until --status shows it gone.
#
#  What offboarding deliberately does NOT touch:
#    - the AS64500 ROA, or any ROA written against a block larger than
#      PREFIX. br1/br2 originate the /24 from the former (AD-LOG.md §2) and
#      the latter covers space this script never onboarded.
#    - EIPs and VPC associations. Releasing customer resources isn't this
#      script's call; it names them and stops.
# ---------------------------------------------------------------------
def allocations(env):
    """Resources still holding space out of PREFIX, as printable lines.

    This is what turns a deprovision refusal into something you can act on:
    AWS just says the range is still in use.
    """
    out = []
    if family(env) == 4:
        addrs = aws(env, "ec2", "describe-addresses", check=False) or {}
        for a in addrs.get("Addresses", []):
            ip = _norm_addr(a.get("PublicIp"))
            if ip is None or ip not in env["_net"]:
                continue
            used = a.get("InstanceId") or a.get("NetworkInterfaceId") or "-"
            out.append(f"EIP {a['PublicIp']:18} {a.get('AllocationId', '?'):26} "
                       f"attached to {used}")
        pool = v4_pool(env)
        if pool and pool.get("TotalAvailableAddressCount") != \
                pool.get("TotalAddressCount"):
            gone = (pool.get("TotalAddressCount", 0)
                    - pool.get("TotalAvailableAddressCount", 0))
            out.append(f"pool {pool['PoolId']} reports {gone} address(es) "
                       f"allocated (EIPs above, plus anything held by a "
                       f"service)")
    else:
        vpcs = aws(env, "ec2", "describe-vpcs", check=False) or {}
        for v in vpcs.get("Vpcs", []):
            for assoc in v.get("Ipv6CidrBlockAssociationSet", []):
                if (assoc.get("Ipv6CidrBlockState", {}).get("State")
                        == "disassociated"):
                    continue
                try:
                    net = ipaddress.ip_network(assoc["Ipv6CidrBlock"],
                                               strict=False)
                except (KeyError, ValueError):
                    continue
                if net.version == 6 and net.subnet_of(env["_net"]):
                    out.append(f"VPC {v['VpcId']} holds {assoc['Ipv6CidrBlock']} "
                               f"(association {assoc.get('AssociationId')})")
    return out


def off_advertise(env, args):
    step("Withdraw advertisement")
    entry = byoip_entry(env)
    if not entry:
        skip(f"{env['PREFIX']} is not in BYOIP; nothing to withdraw")
        return
    if entry["State"] == "pending-withdrawal":
        wait("withdrawal is in flight. Re-run once it settles.")
        return
    if entry["State"] == "pending-advertising":
        wait("an advertisement is in flight and cannot be cancelled. Wait for")
        print("        'advertised', then withdraw.")
        return
    if entry["State"] != "advertised":
        skip(f"{env['PREFIX']} is {entry['State']}, not advertised")
        return
    print(f"\n  {env['PREFIX']} is ADVERTISED from AWS right now, from "
          f"Amazon's ASN.")
    print("  Withdrawing pulls it from the AWS edge; sources that AWS was "
          "winning")
    print("  shift back toward br1/br2. This is a live routing change, not a")
    print("  bookkeeping one.")
    if not confirm(f"withdraw {env['PREFIX']} from advertising", args):
        return
    rc, _, err = aws_raw(env, "ec2", "withdraw-byoip-cidr",
                         "--cidr", env["PREFIX"])
    if rc != 0:
        die(f"withdraw-byoip-cidr refused:\n{err}")
    ok(f"{env['PREFIX']} withdrawn (state -> provisioned)")


def off_deprovision(env, args):
    step("Deprovision CIDR")
    entry = byoip_entry(env)
    if not entry or entry["State"] == "deprovisioned":
        state = f" (state: {entry['State']})" if entry else ""
        skip(f"{env['PREFIX']} is not provisioned in {env['AWS_REGION']}{state}")
        return
    if entry["State"] == "pending-deprovision":
        wait(f"{env['PREFIX']} is pending-deprovision. Can take a day. Re-run.")
        return
    if entry["State"] in ("advertised", "pending-advertising",
                          "pending-withdrawal"):
        wait(f"{env['PREFIX']} is {entry['State']}; withdraw first, then "
             f"re-run.")
        return
    if entry["State"] == "pending-provision":
        wait(f"{env['PREFIX']} is still provisioning. AWS will not deprovision "
             f"mid-flight.")
        return
    if entry["State"] == "failed-deprovision":
        print(f"\n  {env['PREFIX']} is in failed-deprovision:")
        print(f"    {entry.get('StatusMessage') or '(no status message)'}")
        print("  Almost always an address from the range is still allocated.")

    blockers = allocations(env)
    if blockers:
        print(f"\n  {env['PREFIX']} still has resources allocated from it:")
        for b in blockers:
            print(f"    - {b}")
        print("  AWS will not deprovision a range that is still in use. "
              "Release these")
        print("  yourself (release-address / disassociate-vpc-cidr-block); "
              "releasing")
        print("  customer resources is not this script's call. Then re-run.")
        return

    if not confirm(f"deprovision {env['PREFIX']} from {env['AWS_REGION']}",
                   args):
        return
    rc, _, err = aws_raw(env, "ec2", "deprovision-byoip-cidr",
                         "--cidr", env["PREFIX"])
    if rc != 0:
        print(f"  FAIL  deprovision refused:\n        {err}")
        print("        Usually a resource still holds the space. Clear it, "
              "re-run.")
        return
    ok(f"{env['PREFIX']} deprovision submitted")
    print("        Can take up to a day. Re-run until --status shows it gone.")


def off_roa(env, args):
    step("Delete AWS onboarding ROAs")
    if not env["_public"]:
        skip("range is not publicly advertisable; no ROAs were created")
        return
    # Never drop the Amazon ROAs while AWS is still advertising: that would
    # leave AWS's own announcement RPKI-invalid until withdrawal propagates.
    entry = byoip_entry(env)
    if entry and entry["State"] in ("advertised", "pending-advertising",
                                    "pending-withdrawal"):
        wait(f"{env['PREFIX']} is {entry['State']} from AWS; withdraw first so "
             f"the")
        print("        Amazon ROAs are not pulled out from under a live "
              "announcement.")
        return

    if entry and entry["State"] not in ("deprovisioned", "pending-deprovision"):
        print(f"  note  AWS still holds {env['PREFIX']} ({entry['State']}). "
              f"Deleting the Amazon")
        print("        ROAs now is safe while nothing is advertised, but "
              "re-provisioning")
        print("        will fail until they are recreated and revalidated "
              "(up to 24h).")

    own = int(env["ASN"]) if has_asn(env) else None
    targets = []
    for r in exact_roas(env):
        if r["asn"] == own:
            skip(f"AS{own} ROA kept -- br1/br2 originate the prefix from it")
        elif r["asn"] in AWS_ASNS:
            targets.append(r)
    # A ROA over a larger block covers space this script never onboarded, so
    # it's never a delete candidate. But say so, because it's also why the
    # prefix may still validate for Amazon after this step.
    for asn, r in sorted(covering_roas(env).items()):
        if r["net"] != env["_net"] and asn in AWS_ASNS:
            skip(f"AS{asn} ROA over {r['net']} kept -- it covers more than "
                 f"{env['PREFIX']}")
    if not targets:
        skip(f"no AWS ASN ROAs written against {env['PREFIX']} itself")
        return

    for r in targets:
        # belt and braces: never delete our own ASN or a non-AWS ASN
        if r["asn"] == own or r["asn"] not in AWS_ASNS:
            continue
        payload = (
            f'<rpkiTransaction xmlns="{RPKI_NS}">\n'
            f"  <roaSpecDelete>\n"
            f'    <roaHandle autoLink="false">{r["handle"]}</roaHandle>\n'
            f"  </roaSpecDelete>\n"
            f"</rpkiTransaction>"
        )
        print(f"\n  --- POST {ARIN_REG}/rpki/{ORG_HANDLE}?apikey=<ARIN_API_KEY>")
        print("\n".join(f"  {ln}" for ln in payload.splitlines()))
        if not confirm(f"delete the ROA for AS{r['asn']} "
                       f"(handle {r['handle']})", args):
            skip(f"AS{r['asn']} ROA kept")
            continue
        status, body = arin(env, "POST", f"rpki/{ORG_HANDLE}", payload)
        if status not in (200, 201):
            die(f"ARIN returned HTTP {status}:\n{redact(body, env)}")
        ok(f"AS{r['asn']} ROA deleted")


def _net_handle(env):
    try:
        return get_json(f"{RDAP}/ip/{env['PREFIX']}").get("handle")
    except urllib.error.HTTPError:
        return None


def off_cert(env, args):
    step("Remove onboarding certificate from RDAP")
    # AWS only needs the certificate for the duration of provisioning, and
    # says so; leaving it published is a standing offer to anyone holding the
    # private key. Reg-RWS exposes PUT /rest/net/{handle}, so the safe pattern
    # (per ARIN's docs) is GET the current payload, drop only the <comment>
    # holding the cert, and PUT it back. Every other field echoed unchanged.
    entry = byoip_entry(env)
    if entry and entry["State"] == "pending-provision":
        wait("provisioning is still in flight; AWS re-reads RDAP during it.")
        print("        Leave the certificate published until it settles.")
        return

    handle = _net_handle(env)
    if not handle:
        wait("could not resolve the NET handle from RDAP; skipping")
        return
    status, body = arin(env, "GET", f"net/{handle}")
    if status != 200:
        die(f"GET net/{handle} -> HTTP {status}:\n{redact(body, env)}")
    ET.register_namespace("", CORE_NS)   # emit a clean default namespace
    root = ET.fromstring(body)
    comments = [c for c in root if _local(c.tag) == "comment"
                and "BEGIN CERTIFICATE" in ET.tostring(c, encoding="unicode")]
    if not comments:
        skip(f"NET {handle} carries no certificate comment")
        return
    for c in comments:
        root.remove(c)
    payload = ET.tostring(root, encoding="unicode")
    print(f"\n  Will PUT NET {handle} with the cert <comment> removed.")
    print("  Outgoing payload (cert already stripped; all else unchanged):")
    print("\n".join(f"    {ln}" for ln in payload.splitlines()))
    if not confirm(f"remove the certificate comment from NET {handle}", args):
        return
    st, rb = arin(env, "PUT", f"net/{handle}", payload)
    if st != 200:
        print(f"  FAIL  ARIN PUT -> HTTP {st}:\n{redact(rb, env)}")
        print("        Clear it by hand in ARIN Online instead.")
        return
    ok(f"NET {handle} certificate comment removed")


def offboard(env, args):
    print("\n  !! OFFBOARDING reverses onboarding. If the prefix is advertised "
          "it")
    print("     WITHDRAWS a live announcement. Every change is confirmed one at "
          "a")
    print("     time; nothing is sent without a 'y'. Async steps want "
          "re-running.")
    seq = [
        ("advertise",   off_advertise),
        ("deprovision", off_deprovision),
        ("roa",         off_roa),
        ("cert",        off_cert),
    ]
    for name, fn in seq:
        if args.step in (None, name):
            fn(env, args)
    print("\n=== Offboard pass complete. Nothing else was touched.")
    print("    Deprovision is async -- re-run until --status is clear.")


# ---------------------------------------------------------------------
#  status
# ---------------------------------------------------------------------
def show_status(env):
    step("Status")
    certs = rdap_certs("ip", env["PREFIX"])
    print(f"  RDAP NET  {env['PREFIX']:22} cert: "
          f"{'present' if certs else 'MISSING'}")

    if env["_public"]:
        have = covering_roas(env)
        want = ([int(env["ASN"])] if has_asn(env) else []) + AWS_ASNS
        for asn in want:
            r = have.get(asn)
            if not r:
                print(f"  ROA  AS{asn:<8} {env['PREFIX']:22} MISSING")
            else:
                how = "" if r["net"] == env["_net"] else f"  via {r['net']}"
                print(f"  ROA  AS{asn:<8} {env['PREFIX']:22} maxLength "
                      f"/{r['maxLength']}{how}")
    else:
        print("  ROA  (not publicly advertisable -- no ROA required)")

    # Unfiltered on purpose: another BYOIP range in this Region, or the same
    # range in a state you didn't expect, is exactly what you want to see.
    for c in describe_byoip(env):
        tag = "" if c["Cidr"] == env["PREFIX"] else "  <- not this run's"
        nbg = f"  nbg {c['NetworkBorderGroup']}" if c.get("NetworkBorderGroup") \
            else ""
        print(f"  CIDR {c['Cidr']:24} {c['State']:20}{nbg}{tag}")
        if c["Cidr"] == env["PREFIX"] and c.get("StatusMessage"):
            print(f"       {c['StatusMessage']}")

    pool = v4_pool(env) if family(env) == 4 else v6_pool(env)
    if not pool:
        print("  POOL (none)")
    elif family(env) == 4:
        print(f"  POOL {pool['PoolId']:24} "
              f"{pool.get('TotalAvailableAddressCount')}/"
              f"{pool.get('TotalAddressCount')} available")
    else:
        print(f"  POOL {pool['PoolId']:24} "
              f"{', '.join(b['Cidr'] for b in pool.get('PoolCidrBlocks', []))}")

    for line in allocations(env):
        print(f"  USED {line}")

    # A prefix can't be in both paths, so anything here means this script is
    # looking at the wrong one.
    for pid, state in ipam_holders(env):
        print(f"  IPAM {pid} holds {env['PREFIX']} ({state})  <- use "
              f"onboard_ipam.py")


# ---------------------------------------------------------------------
ONBOARD_STEPS = ["roa", "provision", "pool"]
OFFBOARD_STEPS = ["advertise", "deprovision", "roa", "cert"]


def main():
    ap = argparse.ArgumentParser(
        description="Onboard (or offboard) a BYOIP prefix to AWS the classic "
                    "non-IPAM way, with provision-byoip-cidr. IPv4 and IPv6. "
                    "Onboarding never advertises.")
    ap.add_argument("--offboard", action="store_true",
                    help="reverse onboarding: withdraw, deprovision, remove "
                         "ROAs and certificate")
    ap.add_argument("--status", action="store_true",
                    help="read-only summary, change nothing")
    ap.add_argument("--dry-run", action="store_true",
                    help="print intended mutations without sending them")
    ap.add_argument("--yes", action="store_true",
                    help="skip confirmation prompts")
    ap.add_argument("--step", metavar="STEP",
                    help=f"run one step only. onboard: {', '.join(ONBOARD_STEPS)}"
                         f"  |  offboard: {', '.join(OFFBOARD_STEPS)}")
    ap.add_argument("--expiry", metavar="YYYYMMDD",
                    help="signed message expiry (default: last day of next month)")
    ap.add_argument("--no-publicly-advertisable", action="store_true",
                    help="IPv6 only: provision a range AWS will never advertise "
                         "(reachable over Direct Connect / VPN / TGW). No ROA "
                         "needed, /60 allowed, and it cannot be changed later.")
    ap.add_argument("--network-border-group", metavar="NBG",
                    help="Local Zone network border group to provision into, "
                         "e.g. us-west-2-lax-1")
    ap.add_argument("--description", metavar="TEXT",
                    help="description recorded on the BYOIP CIDR")
    ap.add_argument("--roa-max-length", type=int, metavar="LEN",
                    help="ROA maxLength (default: the prefix's own length, "
                         "which is what AWS asks for on this path)")
    args = ap.parse_args()

    env = load_env(args)
    parse_prefix(env, args)

    kind = "advertisable" if env["_public"] else "NOT publicly advertisable"
    print(f"  IPv{family(env)} {env['PREFIX']} ({kind}), classic BYOIP -- "
          f"no IPAM, no BYOASN")
    print(f"  {env['AWS_PROFILE']}@{env['AWS_REGION']}"
          + (f" nbg {env['_nbg']}" if env["_nbg"] else ""))
    if has_asn(env) and env["_public"]:
        print(f"  AS{env['ASN']} is checked for a ROA only; without IPAM, AWS "
              f"advertises from")
        print(f"  its own ASN ({'/'.join(f'AS{a}' for a in AWS_ASNS)}), not "
              f"from yours.")

    if args.step:
        valid = OFFBOARD_STEPS if args.offboard else ONBOARD_STEPS
        if args.step not in valid:
            die(f"--step {args.step} is not "
                f"{'an offboard' if args.offboard else 'an onboard'} step; "
                f"choose from: {', '.join(valid)}")

    if args.status:
        show_status(env)
        return

    if args.offboard:
        # No preflight: offboarding tears the cert down, so requiring it
        # present would be self-defeating.
        offboard(env, args)
        return

    account = preflight(env)

    only = args.step
    if only in (None, "roa"):
        step_roa(env, args)
    if only in (None, "provision"):
        step_provision(env, args, account)
    if only in (None, "pool"):
        step_pool(env, args)

    print("\n=== Done. Nothing was advertised.")
    print("    Run --status to see where things stand.")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------
#  Why this script stops at 'provisioned'
#
#  BYOIP's minimum is a /24, and 203.0.113.0/24 is exactly what br1 and br2
#  already originate to Vultr and HostHatch (AD-LOG.md §2). Advertising it from
#  AWS as well makes the /24 genuinely anycast: whichever originator is closer
#  wins, per-source, and anchor-guard can neither see nor withdraw the AWS
#  half. AD-LOG.md §2's guarantee that the ERs' /25 beats the BRs' blackhole
#  says nothing about a route that never traverses the WireGuard backbone.
#
#  Without IPAM there's a second problem on top of that one. There's no
#  BYOASN here, so AWS advertises the prefix from AS16509 (or AS14618) while
#  br1/br2 keep advertising it from AS64500. That's MOAS. The same prefix
#  originated by two different ASNs. It's RPKI-valid, because both ROAs exist
#  and that's what they say, but plenty of operators alarm on MOAS, some
#  filter on it, and route-leak detection tooling treats it as a hijack
#  signature. The IPAM path at least keeps one origin AS.
#
#  If you want AWS to advertise this prefix from AS64500, that's BYOASN, and
#  BYOASN needs IPAM: use onboard_ipam.py instead. Onboarding a prefix here is
#  cheap and reversible; advertising it's the step that changes routing.
# ---------------------------------------------------------------------
