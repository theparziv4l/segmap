from segmap import ssh

IP_JSON = """[
{"ifindex":1,"ifname":"lo","operstate":"UNKNOWN","address":"00:00:00:00:00:00","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8}]},
{"ifindex":2,"ifname":"eth0","operstate":"UP","address":"08:00:27:aa:bb:cc","addr_info":[{"family":"inet","local":"10.1.2.15","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]},
{"ifindex":3,"ifname":"eth1","operstate":"DOWN","address":"08:00:27:aa:bb:cd","addr_info":[{"family":"inet","local":"10.1.3.15","prefixlen":24}]},
{"ifindex":4,"ifname":"eth2","operstate":"UP","address":"08:00:27:aa:bb:ce","addr_info":[{"family":"inet6","local":"fe80::2","prefixlen":64}]},
{"ifindex":5,"ifname":"tun0","operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"10.8.0.2","prefixlen":24}]}
]"""

IP_TEXT = """1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever
2: eth0    inet 10.1.2.15/24 brd 10.1.2.255 scope global eth0\\       valid_lft forever preferred_lft forever
3: docker0    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0\\       valid_lft forever
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000\\    link/ether 08:00:27:aa:bb:cc brd ff:ff:ff:ff:ff:ff
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default\\    link/ether 02:42:11:22:33:44 brd ff:ff:ff:ff:ff:ff
"""


def test_ifaces_json_filters_lo_down_no_ipv4():
    got = ssh.parse_ifaces_json(IP_JSON)
    assert [i["name"] for i in got] == ["eth0", "tun0"]
    assert got[0] == {"name": "eth0", "mac": "08:00:27:aa:bb:cc", "state": "UP", "ipv4": "10.1.2.15/24"}


def test_ifaces_text_fallback():
    got = ssh.parse_ifaces_text(IP_TEXT)
    assert got == [{"name": "eth0", "mac": "08:00:27:aa:bb:cc", "state": "UP", "ipv4": "10.1.2.15/24"}]


def test_prereq_and_mode():
    out = ("uid=1000\nnmap=/usr/bin/nmap\nnmapver=Nmap version 7.94SVN ( https://nmap.org )\nip=/usr/sbin/ip\n"
           "setsid=/usr/bin/setsid\ntimeout=/usr/bin/timeout\ncaps=\n")
    p = ssh.parse_prereq(out)
    assert p["uid"] == 1000 and p["nmap_version"].startswith("Nmap version 7.94")
    assert ssh.decide_mode(p, sudo_ok=True) == ("sudo", [])
    mode, errs = ssh.decide_mode(p, sudo_ok=False)
    assert mode is None and "raw sockets" in errs[0]
    assert ssh.decide_mode({**p, "caps": "/usr/lib/nmap/nmap cap_net_admin,cap_net_raw=eip"}, False)[0] == "cap"
    assert ssh.decide_mode({**p, "uid": 0}, False)[0] == "root"
    mode, errs = ssh.decide_mode({**p, "uid": 0, "nmap": ""}, False)
    assert mode is None and errs == ["nmap not found on PATH"]
    # the scan wrapper's dead-man switch needs coreutils timeout
    assert ssh.decide_mode({**p, "uid": 0, "timeout": ""}, False) == (None, ["timeout not found on PATH"])
