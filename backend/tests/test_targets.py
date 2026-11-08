import ipaddress as ip

import pytest

from segmap import targets as t


def N(s):
    return ip.ip_network(s)


def test_parse_mixed_forms():
    nets = t.parse_targets("10.0.0.0/24, 10.0.1.5\n10.0.2.10-10.0.2.20 # comment\n10.0.3.1-4\n\n")
    assert N("10.0.0.0/24") in nets
    assert N("10.0.1.5/32") in nets
    # range 10..20 summarized
    covered = {a for n in nets for a in n if a in N("10.0.2.0/24")}
    assert covered == {ip.ip_address(f"10.0.2.{i}") for i in range(10, 21)}
    covered3 = {a for n in nets for a in n if a in N("10.0.3.0/24")}
    assert covered3 == {ip.ip_address(f"10.0.3.{i}") for i in range(1, 5)}


def test_parse_host_bits_normalized():
    assert t.parse_targets("10.0.0.7/24") == [N("10.0.0.0/24")]


@pytest.mark.parametrize("bad", ["10.0.0.0/33", "foo", "10.0.0.1;id", "$(id)", "::1", "10.0.0.9-10.0.0.1", "10.0.0.0/8"])
def test_parse_rejects(bad):
    with pytest.raises(ValueError):
        t.parse_targets(bad)


def test_blocks24_split_and_contain():
    assert t.blocks24(N("10.0.0.0/23")) == [N("10.0.0.0/24"), N("10.0.1.0/24")]
    assert t.blocks24(N("10.0.5.128/25")) == [N("10.0.5.0/24")]
    assert t.blocks24(N("10.0.5.9/32")) == [N("10.0.5.0/24")]
    assert len(t.blocks24(N("10.0.0.0/16"))) == 256


def test_block_tag_map_rejects_mixed_tags_in_one_24():
    scope = [(N("10.24.3.0/25"), "non-CDE")]
    with pytest.raises(ValueError, match="10.24.3.0/24"):
        t.block_tags(scope + [(N("10.24.3.128/25"), "out-of-scope")])
    # same tag is fine
    m = t.block_tags(scope + [(N("10.24.3.128/25"), "non-CDE")])
    assert m == {N("10.24.3.0/24"): "non-CDE"}


def test_targets_in_block_clip():
    scope = [N("10.0.0.0/23"), N("10.0.5.9/32"), N("10.0.5.20/30")]
    assert t.targets_in_block(N("10.0.1.0/24"), scope) == ["10.0.1.0/24"]
    assert t.targets_in_block(N("10.0.5.0/24"), scope) == ["10.0.5.9/32", "10.0.5.20/30"]


def test_zone_for_ip_most_specific():
    scope = [(N("10.1.0.0/16"), "non-CDE"), (N("10.1.2.0/24"), "CDE")]
    assert t.zone_for_ip("10.1.2.7", scope) == "CDE"
    assert t.zone_for_ip("10.1.9.7", scope) == "non-CDE"
    assert t.zone_for_ip("192.168.1.1", scope) is None
