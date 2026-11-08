"""Scope parsing: CIDRs, IPs, ranges -> IPv4 networks; /24 blocks; tag/zone lookup."""
import ipaddress as ip
import re

MIN_PREFIX = 16  # ponytail: refuse > /16 (65536 addrs, 256 jobs per check); raise if needed
_TOKEN = re.compile(r"[\s,]+")


def _parse_token(tok: str) -> list[ip.IPv4Network]:
    if "-" in tok:
        a, b = tok.split("-", 1)
        start = ip.IPv4Address(a)
        end = ip.IPv4Address(b) if "." in b else ip.IPv4Address(a.rsplit(".", 1)[0] + "." + str(int(b)))
        if end < start:
            raise ValueError(f"range end before start: {tok}")
        return list(ip.summarize_address_range(start, end))
    net = ip.IPv4Network(tok, strict=False)
    if net.prefixlen < MIN_PREFIX:
        raise ValueError(f"{tok}: larger than /{MIN_PREFIX}, split it")
    return [net]


def parse_targets(text: str) -> list[ip.IPv4Network]:
    out: list[ip.IPv4Network] = []
    for line in text.splitlines():
        for tok in _TOKEN.split(line.split("#", 1)[0].strip()):
            if not tok:
                continue
            try:
                out += _parse_token(tok)
            except (ValueError, ip.AddressValueError, ip.NetmaskValueError) as e:
                raise ValueError(f"invalid target {tok!r}: {e}") from None
    return out


def blocks24(net: ip.IPv4Network) -> list[ip.IPv4Network]:
    if net.prefixlen <= 24:
        return list(net.subnets(new_prefix=24))
    return [net.supernet(new_prefix=24)]


def block_tags(scope: list[tuple[ip.IPv4Network, str]]) -> dict[ip.IPv4Network, str]:
    """/24 -> tag. One /24 must carry exactly one tag."""
    m: dict[ip.IPv4Network, str] = {}
    for net, tag in scope:
        for b in blocks24(net):
            if m.setdefault(b, tag) != tag:
                raise ValueError(f"{b} would carry two tags ({m[b]}, {tag}); one tag per /24")
    return m


def targets_in_block(block: ip.IPv4Network, scope_nets: list[ip.IPv4Network]) -> list[str]:
    """Exact nmap targets inside one /24 (scope entries clipped to the block)."""
    out = []
    for n in scope_nets:
        if n.overlaps(block):
            out.append(str(block if n.prefixlen <= 24 else n))
    return sorted(set(out), key=lambda s: ip.IPv4Network(s))


def zone_for_ip(addr: str, scope: list[tuple[ip.IPv4Network, str]]) -> str | None:
    a = ip.IPv4Address(addr)
    hits = [(n.prefixlen, tag) for n, tag in scope if a in n]
    return max(hits)[1] if hits else None
