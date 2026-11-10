#!/usr/bin/env python3
"""
AS64500 / BYOIP -> AWS IPAM onboarding. IPv4 and IPv6.

  .env  ->  preflight (RDAP + RPKI)  ->  ROAs  ->  IPAM pools  ->  BYOIP
        ->  BYOASN  ->  associate

Every step reads live state first and skips itself if already done, so the
script is safe to re-run after any failure or timeout.

WHAT RUNS IS DECIDED BY WHAT IS CONFIGURED. ASN and PREFIX in .env are both
optional, but you need at least one:

    ASN + PREFIX   onboard both, then associate the ASN with the CIDR
    PREFIX only    ROAs, pools, BYOIP. No BYOASN, no association.
    ASN only       BYOASN only. No ROAs, no pools, no CIDR.

--only narrows a run without editing .env:

    python3 aws/onboard_aws.py --only asn    # BYOASN only, this run
    python3 aws/onboard_aws.py --only cidr   # CIDR only, this run

The address family is taken from PREFIX. A v6 PREFIX changes the ROA
maxLength (/48, not /24), the IPAM pool address-family, and adds
--publicly-advertisable to the top-level pool. Pool descriptions carry the
family, so a v4 and a v6 onboarding can coexist under one IPAM.

    python3 aws/onboard_aws.py --status    # read-only: where am I?
    python3 aws/onboard_aws.py --dry-run   # print what would be sent, send nothing
    python3 aws/onboard_aws.py             # run, prompting before each mutation
    python3 aws/onboard_aws.py --step roa  # run one step only

Offboarding unwinds all of it, in reverse dependency order. Withdraw the
CIDR, disassociate and deprovision, delete the pools, delete the two Amazon
ROAs, and remove the certificate from RDAP. It honours the same modes:

    python3 aws/onboard_aws.py --offboard --dry-run   # preview the teardown
    python3 aws/onboard_aws.py --offboard             # run it, prompting

Reads .env from this directory. certificate.pem and private-key.pem live next
to this file; .gitignore keeps them out of the repo and this script in.

ONBOARDING NEVER ADVERTISES. It stops once the ASN is associated with the
CIDR. br1/br2 remain the only originators of the /24. See AD-LOG.md §2.
Advertising is a deliberate, separate act:

    aws ec2 advertise-byoip-cidr --asn 64500 --cidr 203.0.113.0/24

Read the anycast note at the bottom of this file before you run that. If you
have already run it, --offboard withdraws it again (that's a live change).
"""

import argparse
import base64
import datetime
import ipaddress
import json
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from getpass import getpass

HERE = pathlib.Path(__file__).resolve().parent   # aws/
REPO = HERE.parent
ENVFILE = HERE / ".env"                          # shared with generate.py
CERT = HERE / "certificate.pem"
PRIVKEY = HERE / "private-key.pem"

ORG_HANDLE = "RCL-264"
ARIN_REG = "https://reg.arin.net/rest"
RDAP = "https://rdap.arin.net/registry"

# AWS commercial origin ASNs. GovCloud would be 8987 instead of these.
AWS_ASNS = [16509, 14618]

RPKI_NS = "http://www.arin.net/regrws/rpki/v1"

# Smallest prefix AWS will advertise per Region, by family. This is also the
# ROA maxLength: it has to be at least this long or IPAM can't split the
# space across Regions, and AWS refuses to provision.
BYOIP_MIN_LEN = {4: 24, 6: 48}


# ---------------------------------------------------------------------
#  environment
# ---------------------------------------------------------------------
def load_env():
    """Parse .env. Values may or may not be quoted; strip either way.

    ASN and PREFIX are both optional. What is present decides what runs.
    But an empty file has nothing to onboard, so require at least one.
    """
    env = {}
    for line in ENVFILE.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    missing = {"ARIN_API_KEY", "AWS_REGION", "AWS_PROFILE",
               "IPAM_ID"} - env.keys()
    if missing:
        die(f".env is missing: {', '.join(sorted(missing))}")

    # Absent and present-but-blank mean the same thing: not configured.
    env["ASN"] = env.get("ASN", "").strip() or None
    env["PREFIX"] = env.get("PREFIX", "").strip() or None
    if not env["ASN"] and not env["PREFIX"]:
        die(".env sets neither ASN nor PREFIX. Set one (BYOASN-only or "
            "BYOIP-only) or both (the two plus association).")
    if env["ASN"] and not env["ASN"].isdigit():
        die(f"ASN={env['ASN']} is not a plain AS number (no 'AS' prefix, "
            f"no dot notation).")
    return env


# ---------------------------------------------------------------------
#  address family
#
#  Everything family-dependent hangs off the parsed PREFIX, so there's one
#  place to look when v4 and v6 disagree. env["_net"] is None in ASN-only
#  mode; has_cidr()/has_asn() gate the steps that need each.
# ---------------------------------------------------------------------
def parse_prefix(env):
    """Validate PREFIX and stash it as an ip_network in env['_net']."""
    env["_net"] = None
    if not env["PREFIX"]:
        return
    try:
        net = ipaddress.ip_network(env["PREFIX"], strict=True)
    except ValueError as e:
        die(f"PREFIX={env['PREFIX']} is not a valid CIDR: {e}")
    floor = BYOIP_MIN_LEN[net.version]
    if net.prefixlen > floor:
        die(f"PREFIX={env['PREFIX']} is longer than /{floor}. AWS BYOIP will "
            f"not take an IPv{net.version} block smaller than /{floor}.\n"
            f"        (IPv6 /56 is accepted only as non-advertisable space, "
            f"which this script does not set up.)")
    # Normalise: AWS and ARIN both want the canonical form, and comparing
    # describe-* output against a differently-written string silently misses.
    env["PREFIX"] = str(net)
    env["_net"] = net


def has_cidr(env):
    return env["_net"] is not None


def has_asn(env):
    return env["ASN"] is not None


def family(env):
    return env["_net"].version


def roa_max_length(env):
    """ROA maxLength for PREFIX: the per-Region floor, or the prefix length
    itself when the block is already at or below it. A /24 v4 gives 24 and a
    /48 v6 gives 48; a /20 v4 still gives 24, so IPAM can carve it up."""
    net = env["_net"]
    return max(net.prefixlen, BYOIP_MIN_LEN[net.version])


def pool_descs(env, tier):
    """Pool descriptions to match, most specific first.

    Descriptions carry the family so a v4 and a v6 onboarding can live under
    one IPAM without find_pool() confusing them. The unsuffixed name is what
    the IPv4-only version of this script created. Keep matching it so an
    existing onboarding isn't orphaned. New pools always use names[0]."""
    names = [f"byoip-{tier}-ipv{family(env)}"]
    if family(env) == 4:
        names.append(f"byoip-{tier}")
    return names


def die(msg):
    print(f"\n  FAIL  {msg}\n", file=sys.stderr)
    sys.exit(1)


def step(msg):
    print(f"\n=== {msg}")


def ok(msg):
    print(f"  ok    {msg}")


def skip(msg):
    print(f"  skip  {msg}")


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
#    text:   1|aws|ACCOUNT|RESOURCE|YYYYMMDD|SHA256|RSAPSS
#    sign:   openssl dgst -sha256 -sigopt rsa_padding_mode:pss \
#              -sigopt rsa_pss_saltlen:-1 -sign private-key.pem
#            | openssl base64 | tr. '+=/' '-_~' | tr -d "\n"
#
#  saltlen:-1 is RSA_PSS_SALTLEN_DIGEST, hence PSS.DIGEST_LENGTH below.
#  The tr is NOT standard urlsafe b64: + -> -, = -> _, / -> ~.
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

    # The cert must be in the RDAP remarks of whichever objects we're
    # onboarding: the NET record authorises the CIDR, the ASN record
    # authorises the ASN. Same cert. Only check what this run will touch.
    targets = []
    if has_cidr(env):
        targets.append(("ip", env["PREFIX"], "NET"))
    if has_asn(env):
        targets.append(("autnum", env["ASN"], "ASN"))

    for kind, ident_, label in targets:
        found = rdap_certs(kind, ident_)
        if not found:
            die(f"no X.509 certificate in the RDAP remarks of the {label} "
                f"record ({ident_}).\n        The {label} record must carry it "
                f"before AWS will provision.\n        ASN comments are portal-"
                f"only: https://account.arin.net -> Modify ASN -> Public Comments")
        if cert not in found:
            die(f"the {label} RDAP record has a certificate, but it is not the "
                f"one in {CERT}.\n        AWS will sign with the local key and "
                f"fail to verify against the published cert.")
        ok(f"{label} RDAP remarks carry the cert in {CERT.name}")

    return account


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


def list_roas(env):
    """Every ROA covering PREFIX exactly, as [{asn, maxLength, handle}].

    ARIN emits <roaSpec> in the core namespace but its children in the rpki
    namespace, so match on local names rather than qualified tags.
    """
    status, body = arin(env, "GET", f"roa/{ORG_HANDLE}")
    if status != 200:
        die(f"ARIN ROA list returned HTTP {status}:\n{redact(body, env)}")

    want_addr = env["_net"].network_address
    want_len = str(env["_net"].prefixlen)
    out = []
    for spec in ET.fromstring(body).iter():
        if _local(spec.tag) != "roaSpec":
            continue
        asn = _text(spec, "asNumber")
        handle = _text(spec, "roaHandle")
        for res in _kids(spec, "resources"):
            start = _norm_addr(_text(res, "startAddress"))
            clen = _text(res, "cidrLength")
            mlen = _text(res, "maxLength") or clen
            if start == want_addr and clen == want_len:
                out.append({"asn": int(asn), "maxLength": mlen, "handle": handle})
    return out


def check_roas(env):
    """{asn: maxLength} for ROAs covering PREFIX exactly."""
    return {r["asn"]: r["maxLength"] for r in list_roas(env)}


# ---------------------------------------------------------------------
#  step: ROAs
# ---------------------------------------------------------------------
def step_roa(env, args):
    step("ROAs")
    if not has_cidr(env):
        skip("no PREFIX configured; ROAs are about the CIDR")
        return
    have = check_roas(env)

    for asn, mlen in sorted(have.items()):
        ok(f"AS{asn} has a ROA for {env['PREFIX']} maxLength /{mlen}")
    if has_asn(env):
        if int(env["ASN"]) not in have:
            die(f"no ROA for your own AS{env['ASN']} over {env['PREFIX']}. "
                f"BYOASN requires it.")
    else:
        print("  note  no ASN configured, so the ROA for your own origin AS is")
        print("        not checked. BYOASN needs one before you associate.")

    missing = [a for a in AWS_ASNS if a not in have]
    if not missing:
        skip("both AWS ASNs already covered")
        return

    mlen = roa_max_length(env)
    print(f"\n  Missing ROAs for: {', '.join(f'AS{a}' for a in missing)}")
    print("  AWS will not provision the CIDR without these, and reserves the")
    print("  right to stop advertising if they are absent or non-compliant.")
    print(f"  maxLength must be /{mlen} so IPAM can split the space across "
          f"Regions.")
    print("\n  autoLink=false: this does NOT create IRR route objects. Publishing")
    print("  route: objects for Amazon ASNs while AWS is not advertising would")
    print("  put misleading data in the IRR. Revisit if you ever advertise.")

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
        print("\n".join(f"  {l}" for l in payload.splitlines()))

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
#  step: pools
# ---------------------------------------------------------------------
def find_pool(env, tier):
    """The live pool for one tier ('top-level' or 'regional') of this run's
    address family. Matches the family-suffixed description first, then the
    legacy unsuffixed one; also requires AddressFamily to agree, so a legacy
    v4 pool can never be handed back during a v6 run."""
    want = pool_descs(env, tier)
    pools = aws(env, "ec2", "describe-ipam-pools")["IpamPools"]
    live = [p for p in pools if p["State"] != "delete-complete"
            and p.get("AddressFamily") == f"ipv{family(env)}"]
    for desc in want:
        for p in live:
            if p.get("Description") == desc:
                return p
    return None


def wait_pool(env, pool_id, want="create-complete", tries=30):
    for _ in range(tries):
        pools = aws(env, "ec2", "describe-ipam-pools",
                    "--filters", f"Name=ipam-pool-id,Values={pool_id}")["IpamPools"]
        if pools and pools[0]["State"] == want:
            return pools[0]
        time.sleep(5)
    die(f"pool {pool_id} did not reach {want}")


def step_pools(env, args):
    step("IPAM pools")
    if not has_cidr(env):
        skip("no PREFIX configured; BYOASN needs no pools")
        return None, None

    ipams = aws(env, "ec2", "describe-ipams")["Ipams"]
    live = {i["IpamId"] for i in ipams}
    if env["IPAM_ID"] not in live:
        die(f"IPAM_ID={env['IPAM_ID']} in .env does not exist in "
            f"{env['AWS_REGION']}.\n        Live IPAMs: "
            f"{', '.join(live) or '(none)'}")
    ipam = next(i for i in ipams if i["IpamId"] == env["IPAM_ID"])
    scope = ipam["PublicDefaultScopeId"]
    ok(f"IPAM {ipam['IpamId']} ({ipam['Tier']} tier), public scope {scope}")

    # Free tier only permits a pool locale equal to the IPAM home Region.
    if ipam["Tier"] == "free" and ipam["IpamRegion"] != env["AWS_REGION"]:
        die(f"free tier requires locale == IPAM home Region "
            f"({ipam['IpamRegion']}), but AWS_REGION={env['AWS_REGION']}")

    af = f"ipv{family(env)}"

    top = find_pool(env, "top-level")
    if top:
        skip(f"top-level pool exists: {top['IpamPoolId']} ({af})")
    else:
        if not confirm(f"create top-level public-scope {af} pool in {scope}", args):
            return None, None
        cmd = ["ec2", "create-ipam-pool",
               "--ipam-scope-id", scope,
               "--description", pool_descs(env, "top-level")[0],
               "--address-family", af]
        # v6 pools default to non-advertisable and must opt in; v4 public-scope
        # pools are advertisable by definition and the flag is rejected there.
        if family(env) == 6:
            cmd.append("--publicly-advertisable")
        top = aws(env, *cmd)["IpamPool"]
        top = wait_pool(env, top["IpamPoolId"])
        ok(f"top-level pool {top['IpamPoolId']}")

    regional = find_pool(env, "regional")
    if regional:
        skip(f"regional pool exists: {regional['IpamPoolId']} ({af})")
    else:
        if not confirm(f"create regional {af} pool (locale {env['AWS_REGION']}, "
                       f"aws-service ec2) under {top['IpamPoolId']}", args):
            return top, None
        cmd = ["ec2", "create-ipam-pool",
               "--ipam-scope-id", scope,
               "--description", pool_descs(env, "regional")[0],
               "--source-ipam-pool-id", top["IpamPoolId"],
               "--locale", env["AWS_REGION"],
               "--address-family", af,
               "--aws-service", "ec2"]
        # A v6 child must state PubliclyAdvertisable explicitly and it must
        # match the parent; AWS rejects the default null against a true parent
        # (InvalidParameterCombination). v4 child pools inherit it implicitly
        # and reject the flag, so gate on family as with the top-level pool.
        if family(env) == 6 and top.get("PubliclyAdvertisable"):
            cmd.append("--publicly-advertisable")
        regional = aws(env, *cmd)["IpamPool"]
        regional = wait_pool(env, regional["IpamPoolId"])
        ok(f"regional pool {regional['IpamPoolId']}")

    return top, regional


# ---------------------------------------------------------------------
#  step: BYOIP
# ---------------------------------------------------------------------
def cidr_state(env, pool_id, cidr):
    cidrs = aws(env, "ec2", "get-ipam-pool-cidrs",
                "--ipam-pool-id", pool_id)["IpamPoolCidrs"]
    for c in cidrs:
        if c["Cidr"] == cidr:
            return c["State"]
    return None


def step_byoip(env, args, account, top, regional):
    step("BYOIP CIDR")
    if not has_cidr(env):
        skip("no PREFIX configured")
        return
    cidr = env["PREFIX"]

    if top is None:
        skip("no top-level pool yet")
        return
    state = cidr_state(env, top["IpamPoolId"], cidr)
    if state in ("provisioned",):
        skip(f"{cidr} already provisioned to top-level pool")
    elif state in ("pending-provision",):
        print(f"  wait  {cidr} is {state} in the top-level pool.")
        print("        Publicly advertisable ranges can take up to a week.")
        print("        Re-run this script later; it will pick up where it left off.")
        return
    else:
        expiry = args.expiry or default_expiry()
        text = message_text(account, cidr, expiry)
        print(f"\n  Message: {text}")
        print(f"  Expires: {expiry}  (signed with {PRIVKEY.name})")
        if not confirm(f"provision {cidr} to top-level pool "
                       f"{top['IpamPoolId']} (verification remarks-x509)", args):
            return
        sig = sign_message(text)
        aws(env, "ec2", "provision-ipam-pool-cidr",
            "--ipam-pool-id", top["IpamPoolId"],
            "--cidr", cidr,
            "--verification-method", "remarks-x509",
            "--cidr-authorization-context", f"Message={text},Signature={sig}")
        ok(f"{cidr} submitted to top-level pool; state pending-provision")
        print("        This can take up to a week. Re-run to continue.")
        return

    if regional is None:
        skip("no regional pool yet")
        return
    state = cidr_state(env, regional["IpamPoolId"], cidr)
    if state == "provisioned":
        skip(f"{cidr} already provisioned to regional pool")
        return
    if state == "pending-provision":
        print(f"  wait  {cidr} is {state} in the regional pool. Re-run later.")
        return
    # No authorization context needed here: ownership was proved upstream.
    if not confirm(f"provision {cidr} to regional pool {regional['IpamPoolId']}",
                   args):
        return
    aws(env, "ec2", "provision-ipam-pool-cidr",
        "--ipam-pool-id", regional["IpamPoolId"], "--cidr", cidr)
    ok(f"{cidr} submitted to regional pool")


# ---------------------------------------------------------------------
#  step: BYOASN
# ---------------------------------------------------------------------
def byoasn_state(env):
    """Only entries for OUR ipam. Stale entries from deleted IPAMs are noise."""
    for b in aws(env, "ec2", "describe-ipam-byoasn")["Byoasns"]:
        if b["Asn"] == env["ASN"] and b["IpamId"] == env["IPAM_ID"]:
            return b
    return None


def step_byoasn(env, args, account):
    """Provision the ASN into IPAM. Association is step_associate(). They
    are separate because BYOASN stands on its own: you can bring an ASN with
    no CIDR of your own here, and tie it to a CIDR later."""
    step("BYOASN")
    if not has_asn(env):
        skip("no ASN configured")
        return
    asn = env["ASN"]

    cur = byoasn_state(env)
    if cur and cur["State"] == "provisioned":
        skip(f"AS{asn} already provisioned to {env['IPAM_ID']}")
        return
    elif cur and cur["State"] == "pending-provision":
        print(f"  wait  AS{asn} is pending-provision. Re-run later.")
        return
    else:
        if cur and cur["State"] == "failed-provision":
            print(f"\n  AS{asn} is in failed-provision on {env['IPAM_ID']}:")
            print(f"    {cur.get('StatusMessage')}")
            print("  AWS auto-removes failed entries after 7 days; deprovisioning")
            print("  now clears the slot so we can retry immediately.")
            if not confirm(f"deprovision the failed AS{asn} entry", args):
                return
            aws(env, "ec2", "deprovision-ipam-byoasn",
                "--ipam-id", env["IPAM_ID"], "--asn", asn, check=False)
            ok("failed entry cleared")

        expiry = args.expiry or default_expiry()
        text = message_text(account, asn, expiry)
        print(f"\n  Message: {text}")
        print(f"  Expires: {expiry}  (signed with {PRIVKEY.name})")
        if not confirm(f"provision AS{asn} to IPAM {env['IPAM_ID']}", args):
            return
        sig = sign_message(text)
        aws(env, "ec2", "provision-ipam-byoasn",
            "--ipam-id", env["IPAM_ID"], "--asn", asn,
            "--asn-authorization-context", f"Message={text},Signature={sig}")
        ok(f"AS{asn} submitted; usually provisioned within a few minutes")


def step_associate(env, args):
    """Tie the ASN to the CIDR. Needs both sides configured and provisioned."""
    step("Associate ASN with CIDR")
    if not (has_asn(env) and has_cidr(env)):
        which = "ASN" if has_cidr(env) else "PREFIX"
        skip(f"no {which} configured; association needs both")
        return
    asn = env["ASN"]

    cur = byoasn_state(env)
    if not cur or cur["State"] != "provisioned":
        skip(f"AS{asn} is not provisioned yet "
             f"({cur['State'] if cur else 'absent'}); associate needs it first")
        return

    entry = _byoip_entry(env)
    if not entry or entry["State"] not in ("provisioned", "advertised"):
        skip(f"{env['PREFIX']} is not provisioned yet "
             f"({entry['State'] if entry else 'absent'}); associate needs it first")
        return
    if any(a["Asn"] == asn for a in _active_asn_assocs(entry)):
        skip(f"AS{asn} already associated with {env['PREFIX']}")
        return
    if not confirm(f"associate AS{asn} with {env['PREFIX']}", args):
        return
    aws(env, "ec2", "associate-ipam-byoasn", "--asn", asn,
        "--cidr", env["PREFIX"])
    ok(f"AS{asn} associated with {env['PREFIX']}")


# ---------------------------------------------------------------------
#  OFFBOARDING: reverse the onboarding, in dependency order.
#
#    advertise -> disassociate -> deprovision CIDR -> deprovision ASN
#    -> delete pools -> delete Amazon ROAs -> remove certificate
#
#  The order isn't cosmetic; AWS and the routing story enforce it:
#    - a CIDR can't be deprovisioned while an ASN is associated with it
#    - an ASN can't be deprovisioned while associated with any CIDR
#    - a parent pool can't be deleted while a child pool still exists
#    - ROAs are deleted only AFTER withdrawal: dropping the Amazon ROAs while
#      AWS still advertises would make AWS's own announcement RPKI-invalid
#
#  Every mutation is gated by confirm(); async steps (deprovision, delete)
#  return early and are meant to be re-run until --status shows them gone.
#
#  What offboarding deliberately does NOT touch:
#    - the AS64500 ROA. br1/br2 originate the /24 from it (AD-LOG.md §2);
#      deleting it would break your home network's RPKI validity. Only the
#      two Amazon ROAs this script created are removed.
# ---------------------------------------------------------------------
CORE_NS = "http://www.arin.net/regrws/core/v1"


def _byoip_entry(env):
    """The describe-byoip-cidrs record for PREFIX, or None.

    describe-byoip-cidrs is documented as covering both families, and it's
    the only call that reports AsnAssociations, so it stays the source of
    truth here. If a v6 range ever fails to show up in it, every caller
    below takes a 'skip'/'wait' branch rather than doing something wrong.
    Check `aws ec2 describe-ipv6-pools` (shown by --status) to tell a
    genuinely absent range from a reporting gap."""
    if not has_cidr(env):
        return None
    byoip = aws(env, "ec2", "describe-byoip-cidrs", "--max-results", "10")
    return next((c for c in byoip["ByoipCidrs"]
                 if c["Cidr"] == env["PREFIX"]), None)


def _active_asn_assocs(entry):
    """ASN associations that still tie an ASN to the CIDR. After teardown AWS
    leaves a record with State 'disassociated' in the list rather than removing
    it: that one is done and doesn't block anything."""
    return [a for a in (entry.get("AsnAssociations") or [])
            if a.get("State") != "disassociated"]


def off_advertise(env, args):
    step("Withdraw advertisement")
    if not has_cidr(env):
        skip("no PREFIX configured; nothing is advertised")
        return
    entry = _byoip_entry(env)
    if not entry:
        skip(f"{env['PREFIX']} is not in BYOIP; nothing to withdraw")
        return
    if entry["State"] != "advertised":
        skip(f"{env['PREFIX']} is {entry['State']}, not advertised")
        return
    print(f"\n  {env['PREFIX']} is ADVERTISED from AWS right now. Withdrawing it")
    print("  pulls it from the AWS edge; sources that AWS was winning shift back")
    print("  toward br1/br2. This is a live routing change, not a bookkeeping one.")
    if not confirm(f"withdraw {env['PREFIX']} from advertising", args):
        return
    aws(env, "ec2", "withdraw-byoip-cidr", "--cidr", env["PREFIX"])
    ok(f"{env['PREFIX']} withdrawn (state -> provisioned)")


def off_associate(env, args):
    step("Disassociate ASN from CIDR")
    if not (has_asn(env) and has_cidr(env)):
        which = "ASN" if has_cidr(env) else "PREFIX"
        skip(f"no {which} configured; no association to remove")
        return
    entry = _byoip_entry(env)
    if not entry:
        skip(f"{env['PREFIX']} absent from BYOIP; no association to remove")
        return
    asn = env["ASN"]
    assoc = [a for a in _active_asn_assocs(entry) if a["Asn"] == asn]
    if not assoc:
        skip(f"AS{asn} is not associated with {env['PREFIX']}")
        return
    if assoc[0].get("State") == "disassociating":
        print(f"  wait  AS{asn} is disassociating. Re-run to continue.")
        return
    # AWS rejects disassociation while the CIDR is still advertising; let the
    # withdraw settle first rather than dying on the rejection.
    if entry["State"] != "provisioned":
        print(f"  wait  {env['PREFIX']} is {entry['State']}; let the withdraw "
              f"finish, then re-run.")
        return
    if not confirm(f"disassociate AS{asn} from {env['PREFIX']}", args):
        return
    aws(env, "ec2", "disassociate-ipam-byoasn", "--asn", asn,
        "--cidr", env["PREFIX"])
    ok(f"AS{asn} disassociation submitted")


def _resource_allocations(env, pool_id):
    """Allocations that block deprovision. A child pool consuming the CIDR
    shows up as type 'ipam-pool' and is handled by ordering, not by the
    operator: so it's not counted here. Everything else (EIPs, VPC CIDRs,
    public IPv4 pools) is a real resource the operator must release first."""
    res = aws(env, "ec2", "get-ipam-pool-allocations",
              "--ipam-pool-id", pool_id, check=False) or {}
    return [a for a in res.get("IpamPoolAllocations", [])
            if a.get("ResourceType") != "ipam-pool"]


def _deprovision_cidr(env, args, pool_id, label):
    """Deprovision PREFIX from one pool. Returns True once it's fully gone."""
    state = cidr_state(env, pool_id, env["PREFIX"])
    if state is None or state == "deprovisioned":
        skip(f"{env['PREFIX']} already gone from the {label} pool")
        return True
    if state == "pending-deprovision":
        print(f"  wait  {env['PREFIX']} is {state} in the {label} pool. Re-run.")
        return False

    blockers = _resource_allocations(env, pool_id)
    if blockers:
        print(f"\n  {env['PREFIX']} still has {len(blockers)} resource "
              f"allocation(s) in the {label} pool:")
        for a in blockers:
            print(f"    - {a.get('Cidr')}  {a.get('ResourceType', '?')}  "
                  f"{a.get('ResourceId', '')}  owner {a.get('ResourceOwner', '')}")
        print("  AWS will not deprovision a CIDR that is still allocated.")
        print("  Release these resources yourself (releasing customer resources")
        print("  is not this script's call), then re-run offboarding.")
        return False

    if not confirm(f"deprovision {env['PREFIX']} from the {label} pool "
                   f"{pool_id}", args):
        return False
    rc, _, err = aws_raw(env, "ec2", "deprovision-ipam-pool-cidr",
                         "--ipam-pool-id", pool_id, "--cidr", env["PREFIX"])
    if rc != 0:
        print(f"  FAIL  deprovision refused:\n        {err}")
        print("        Usually a resource still holds the space. Clear it, re-run.")
        return False
    ok(f"{env['PREFIX']} deprovision submitted from the {label} pool")
    return False  # async; re-run once it reaches 'deprovisioned'


def off_byoip(env, args):
    step("Deprovision CIDR from IPAM")
    if not has_cidr(env):
        skip("no PREFIX configured")
        return
    # A CIDR can't be deprovisioned while advertised or while any ASN is still
    # associated with it. Wait those out rather than letting AWS reject us.
    entry = _byoip_entry(env)
    if entry and entry["State"] == "advertised":
        print(f"  wait  {env['PREFIX']} is still advertised; withdraw first, re-run.")
        return
    active = _active_asn_assocs(entry) if entry else []
    if active:
        asns = ", ".join(f"AS{a['Asn']}" for a in active)
        print(f"  wait  {env['PREFIX']} still associated with {asns}; "
              f"disassociate first, re-run.")
        return
    regional = find_pool(env, "regional")
    top = find_pool(env, "top-level")
    # child (regional) must clear before the parent (top-level)
    if regional:
        if not _deprovision_cidr(env, args, regional["IpamPoolId"], "regional"):
            return
    else:
        skip("no regional pool")
    if top:
        _deprovision_cidr(env, args, top["IpamPoolId"], "top-level")
    else:
        skip("no top-level pool")


def off_byoasn(env, args):
    step("Deprovision ASN from IPAM")
    if not has_asn(env):
        skip("no ASN configured")
        return
    asn = env["ASN"]
    cur = byoasn_state(env)
    # AWS keeps a 'deprovisioned' BYOASN record around for ~7 days rather than
    # dropping it immediately; that (and 'failed-provision') means nothing is
    # left to deprovision, so treat both as done.
    if cur is None or cur["State"] in ("deprovisioned", "failed-provision"):
        state = f" (state: {cur['State']})" if cur else ""
        skip(f"AS{asn} is not provisioned to {env['IPAM_ID']}{state}")
        return
    if cur["State"] == "pending-deprovision":
        print(f"  wait  AS{asn} is pending-deprovision. Re-run.")
        return
    entry = _byoip_entry(env)
    if entry and any(a["Asn"] == asn for a in _active_asn_assocs(entry)):
        skip(f"AS{asn} still associated with {env['PREFIX']}; the disassociate "
             f"step must finish first")
        return
    if not confirm(f"deprovision AS{asn} from IPAM {env['IPAM_ID']}", args):
        return
    rc, _, err = aws_raw(env, "ec2", "deprovision-ipam-byoasn",
                         "--ipam-id", env["IPAM_ID"], "--asn", asn)
    if rc != 0:
        print(f"  FAIL  {err}")
        return
    ok(f"AS{asn} deprovision submitted")


def _delete_pool(env, args, pool, label):
    if pool["State"] in ("delete-in-progress", "delete-complete"):
        skip(f"{label} pool is {pool['State']}")
        return
    if cidr_state(env, pool["IpamPoolId"], env["PREFIX"]) in (
            "provisioned", "pending-deprovision", "pending-provision"):
        skip(f"{label} pool still holds {env['PREFIX']}; deprovision it first")
        return
    if not confirm(f"delete the {label} pool {pool['IpamPoolId']}", args):
        return
    rc, _, err = aws_raw(env, "ec2", "delete-ipam-pool",
                         "--ipam-pool-id", pool["IpamPoolId"])
    if rc != 0:
        print(f"  FAIL  {err}")
        return
    ok(f"{label} pool deletion submitted")


def off_pools(env, args):
    step("Delete IPAM pools")
    if not has_cidr(env):
        skip("no PREFIX configured; no pools were created")
        return
    regional = find_pool(env, "regional")
    top = find_pool(env, "top-level")
    if regional:
        _delete_pool(env, args, regional, "regional")
    else:
        skip("no regional pool")
    if top:
        if find_pool(env, "regional"):
            skip("top-level pool kept until the regional pool is fully deleted")
        else:
            _delete_pool(env, args, top, "top-level")
    else:
        skip("no top-level pool")


def off_roa(env, args):
    step("Delete AWS onboarding ROAs")
    if not has_cidr(env):
        skip("no PREFIX configured; no ROAs were created")
        return
    # Never drop the Amazon ROAs while AWS is still advertising: that would
    # leave AWS's own announcement RPKI-invalid until withdrawal propagates.
    entry = _byoip_entry(env)
    if entry and entry["State"] == "advertised":
        print(f"  wait  {env['PREFIX']} is still advertised from AWS; withdraw")
        print("        first so the Amazon ROAs are not pulled out from under a")
        print("        live announcement. Re-run after withdrawal.")
        return
    roas = list_roas(env)
    # None in CIDR-only mode. Never equal to an int, so the guards below still
    # hold; only AWS_ASNS is ever a delete target either way.
    own = int(env["ASN"]) if has_asn(env) else None
    for r in roas:
        if r["asn"] == own:
            skip(f"AS{own} ROA kept -- br1/br2 originate the prefix from it")
    targets = [r for r in roas if r["asn"] in AWS_ASNS]
    if not targets:
        skip("no AWS ASN ROAs present")
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

    # NET record: Reg-RWS exposes PUT /rest/net/{handle}. The safe pattern
    # (per ARIN's docs) is GET the current payload, drop only the <comment>
    # holding the cert, and PUT it back. Every other field echoed unchanged.
    handle = _net_handle(env) if has_cidr(env) else None
    if not has_cidr(env):
        skip("no PREFIX configured; leaving the NET record alone")
    elif not handle:
        print("  wait  could not resolve the NET handle from RDAP; skipping NET")
    else:
        status, body = arin(env, "GET", f"net/{handle}")
        if status != 200:
            die(f"GET net/{handle} -> HTTP {status}:\n{redact(body, env)}")
        ET.register_namespace("", CORE_NS)   # emit a clean default namespace
        root = ET.fromstring(body)
        comments = [c for c in root if _local(c.tag) == "comment"
                    and "BEGIN CERTIFICATE" in ET.tostring(c, encoding="unicode")]
        if not comments:
            skip(f"NET {handle} carries no certificate comment")
        else:
            for c in comments:
                root.remove(c)
            payload = ET.tostring(root, encoding="unicode")
            print(f"\n  Will PUT NET {handle} with the cert <comment> removed.")
            print("  Outgoing payload (cert already stripped; all else unchanged):")
            print("\n".join(f"    {ln}" for ln in payload.splitlines()))
            if confirm(f"remove the certificate comment from NET {handle}", args):
                st, rb = arin(env, "PUT", f"net/{handle}", payload)
                if st != 200:
                    print(f"  FAIL  ARIN PUT -> HTTP {st}:\n{redact(rb, env)}")
                    print("        Clear it by hand in ARIN Online instead.")
                else:
                    ok(f"NET {handle} certificate comment removed")

    # ASN record: portal-only, the same asymmetry as onboarding. There's
    # no ASN object in Reg-RWS to modify.
    if not has_asn(env):
        skip("no ASN configured; leaving the ASN record alone")
        return
    asn_certs = rdap_certs("autnum", env["ASN"])
    if not asn_certs:
        skip(f"AS{env['ASN']} RDAP comment already carries no certificate")
    else:
        print(f"\n  AS{env['ASN']} still carries the certificate, and the ASN's")
        print("  RDAP comment cannot be cleared through Reg-RWS (no ASN object).")
        print("  Remove it by hand:")
        print("    https://account.arin.net -> Modify ASN -> Public Comments -> clear")


def offboard(env, args):
    print("\n  !! OFFBOARDING reverses onboarding. If the prefix is advertised it")
    print("     WITHDRAWS a live announcement. Every change is confirmed one at a")
    print("     time; nothing is sent without a 'y'. Async steps want re-running.")
    seq = [
        ("advertise",    off_advertise),
        ("disassociate", off_associate),
        ("byoip",        off_byoip),
        ("byoasn",       off_byoasn),
        ("pools",        off_pools),
        ("roa",          off_roa),
        ("cert",         off_cert),
    ]
    for name, fn in seq:
        if args.step in (None, name):
            fn(env, args)
    print("\n=== Offboard pass complete. Nothing else was touched.")
    print("    Deprovision and delete are async -- re-run until --status is clear.")


# ---------------------------------------------------------------------
#  status
# ---------------------------------------------------------------------
def show_status(env):
    step("Status")
    targets = []
    if has_cidr(env):
        targets.append(("ip", env["PREFIX"], "NET"))
    if has_asn(env):
        targets.append(("autnum", env["ASN"], "ASN"))
    for kind, ident, label in targets:
        certs = rdap_certs(kind, ident)
        print(f"  RDAP {label:4} {ident:20} cert: "
              f"{'present' if certs else 'MISSING'}")

    if has_cidr(env):
        have = check_roas(env)
        want = ([int(env["ASN"])] if has_asn(env) else []) + AWS_ASNS
        for asn in want:
            m = have.get(asn)
            print(f"  ROA  AS{asn:<8} {env['PREFIX']:20} "
                  f"{'maxLength /' + m if m else 'MISSING'}")

        # Pools are listed unfiltered on purpose. A stray pool from an
        # earlier run or the other address family is exactly what you want to
        # see here, and find_pool()'s filtering would hide it.
        pools = aws(env, "ec2", "describe-ipam-pools")["IpamPools"]
        if not pools:
            print("  POOL (none)")
        for p in pools:
            mine = p.get("Description") in (pool_descs(env, "top-level")
                                            + pool_descs(env, "regional"))
            tag = "" if mine else "  <- not this run's"
            print(f"  POOL {p['IpamPoolId']:24} {p.get('Description', '-'):22} "
                  f"{p.get('AddressFamily', '-'):5} {p['State']}{tag}")

    if has_asn(env):
        for b in aws(env, "ec2", "describe-ipam-byoasn")["Byoasns"]:
            tag = "" if b["IpamId"] == env["IPAM_ID"] else "  <- stale, other IPAM"
            print(f"  ASN  AS{b['Asn']:<8} {b['IpamId']:24} {b['State']}{tag}")

    if has_cidr(env):
        for c in aws(env, "ec2", "describe-byoip-cidrs",
                     "--max-results", "10")["ByoipCidrs"]:
            active = _active_asn_assocs(c)
            assoc = ", ".join(a["Asn"] for a in active) or "none"
            print(f"  CIDR {c['Cidr']:24} {c['State']:16} asn: {assoc}")

        # Cross-check for v6: if a range is provisioned but missing from
        # describe-byoip-cidrs, this is where it shows up, and the difference
        # explains why the association steps would be sitting on 'skip'.
        if family(env) == 6:
            pools6 = aws(env, "ec2", "describe-ipv6-pools",
                         check=False) or {"Ipv6Pools": []}
            for p in pools6.get("Ipv6Pools", []):
                ranges = ", ".join(r["Cidr"] for r in p.get("PoolCidrBlocks", []))
                print(f"  V6P  {p['PoolId']:24} {ranges}")


# ---------------------------------------------------------------------
ONBOARD_STEPS = ["roa", "pools", "byoip", "byoasn", "associate"]
OFFBOARD_STEPS = ["advertise", "disassociate", "byoip", "byoasn", "pools",
                  "roa", "cert"]


def apply_only(env, args):
    """--only narrows a run to one half without editing .env."""
    if args.only == "asn":
        if not has_asn(env):
            die("--only asn but .env sets no ASN.")
        env["PREFIX"], env["_net"] = None, None
    elif args.only == "cidr":
        if not has_cidr(env):
            die("--only cidr but .env sets no PREFIX.")
        env["ASN"] = None


def describe_mode(env):
    if has_asn(env) and has_cidr(env):
        return (f"ASN {env['ASN']} + IPv{family(env)} {env['PREFIX']} "
                f"(will associate)")
    if has_cidr(env):
        return f"IPv{family(env)} {env['PREFIX']} only (no BYOASN)"
    return f"ASN {env['ASN']} only (no CIDR)"


def main():
    ap = argparse.ArgumentParser(
        description="Onboard (or offboard) an ASN and/or a BYOIP prefix to AWS "
                    "IPAM. IPv4 and IPv6. Onboarding never advertises.")
    ap.add_argument("--only", choices=["asn", "cidr"],
                    help="narrow this run to just the ASN or just the CIDR, "
                         "even if .env configures both")
    ap.add_argument("--offboard", action="store_true",
                    help="reverse onboarding: withdraw, deprovision, delete, "
                         "remove ROAs and certificate")
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
    args = ap.parse_args()

    env = load_env()
    parse_prefix(env)
    apply_only(env, args)
    print(f"  {describe_mode(env)}")
    print(f"  ipam {env['IPAM_ID']} | {env['AWS_PROFILE']}@{env['AWS_REGION']}")

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
    top = regional = None
    if only in (None, "pools", "byoip"):
        top, regional = step_pools(env, args)
    if only in (None, "byoip"):
        step_byoip(env, args, account, top, regional)
    if only in (None, "byoasn"):
        step_byoasn(env, args, account)
    if only in (None, "associate"):
        step_associate(env, args)

    print("\n=== Done. Nothing was advertised.")
    print("    Run --status to see where things stand.")


if __name__ == "__main__":
    main()

# ---------------------------------------------------------------------
#  Why this script stops at 'associated'
#
#  BYOIP's minimum is a /24, and 203.0.113.0/24 is exactly what br1 and br2
#  already originate to Vultr and HostHatch (AD-LOG.md §2). Advertising it from
#  AWS too (with BYOASN, from AS64500, the same origin AS) makes the /24
#  genuinely anycast. Whichever originator is closer wins, per-source.
#
#  That isn't a variant of the design doc; it's a third originator that
#  anchor-guard can't see and can't withdraw. AD-LOG.md §2's guarantee that
#  the ERs' /25 beats the BRs' blackhole says nothing about a route that never
#  traverses the WireGuard backbone at all. Work that through before advertising.
#
#  The same argument applies to IPv6, with the floor at /48 instead of /24: if
#  br1/br2 already originate the v6 block, advertising it from AWS anycasts it
#  for exactly the same reasons. Onboarding a prefix here is cheap and
#  reversible; advertising it's the step that changes routing.
# ---------------------------------------------------------------------
