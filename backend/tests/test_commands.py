import shlex

import pytest

from segmap import commands as c

IFACES = {"eth0", "ens33", "wlan0"}
JOB = "0123456789abcdef0123456789abcdef"


def test_syn_argv_exact():
    argv = c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "22,80,443", JOB, known_ifaces=IFACES)
    assert argv == ["nmap", "-n", "--reason", "-e", "eth0", "-T3", "-oX", f"/tmp/segmap-{JOB}.xml",
                    "--stats-every", "30s", "-Pn", "-sS", "-p", "22,80,443", "10.0.0.0/24"]


def test_icmp_argv_never_tcp_ping():
    argv = c.nmap_icmp("eth0", ["10.0.0.0/24"], 4, JOB, known_ifaces=IFACES)
    assert {"-sn", "-PE", "-PP", "--disable-arp-ping"} <= set(argv)
    assert not any(a.startswith(("-PA", "-PS", "-PU", "-PY")) for a in argv)


def test_udp_argv():
    argv = c.nmap_udp("eth0", ["10.0.0.0/24"], 3, "53,123,161,500", JOB, known_ifaces=IFACES)
    assert "-sU" in argv and "-Pn" in argv and argv[argv.index("-p") + 1] == "53,123,161,500"


def test_every_phase_has_mandatory_flags():
    for argv in (
        c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "22", JOB, known_ifaces=IFACES),
        c.nmap_icmp("eth0", ["10.0.0.0/24"], 3, JOB, known_ifaces=IFACES),
        c.nmap_udp("eth0", ["10.0.0.0/24"], 3, "53", JOB, known_ifaces=IFACES),
        c.nmap_egress("eth0", "203.0.113.10", 3, "1-1024", JOB, known_ifaces=IFACES),
        c.nmap_services("eth0", ["10.0.0.5"], 3, [22, 80], [161], JOB, known_ifaces=IFACES),
    ):
        assert {"-n", "--reason", "-oX"} <= set(argv)
        assert argv[argv.index("-e") + 1] == "eth0"
        assert "-PA" not in " ".join(argv)


def test_all_ports_and_privileged_and_advanced():
    argv = c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "all", JOB, known_ifaces=IFACES, privileged=True,
                      advanced={"max_rate": 500, "max_retries": 1, "host_timeout": "15m"})
    assert "-p-" in argv and "--privileged" in argv
    assert argv[argv.index("--max-rate") + 1] == "500"
    assert argv[argv.index("--max-retries") + 1] == "1"
    assert argv[argv.index("--host-timeout") + 1] == "15m"


def test_services_argv_ports_and_scripts():
    argv = c.nmap_services("eth0", ["10.0.0.5", "10.0.0.6"], 3, [80, 22], [161], JOB, known_ifaces=IFACES)
    assert argv[argv.index("-p") + 1] == "T:22,80,U:161"
    assert "-sS" in argv and "-sU" in argv and "-sV" in argv
    assert "--script" in argv
    argv2 = c.nmap_services("eth0", ["10.0.0.5"], 3, [22], [], JOB, known_ifaces=IFACES)
    assert "-sU" not in argv2 and argv2[argv2.index("-p") + 1] == "T:22"


def test_iface_not_discovered_rejected():
    with pytest.raises(ValueError):
        c.nmap_syn("eth1", ["10.0.0.0/24"], 3, "22", JOB, known_ifaces=IFACES)


@pytest.mark.parametrize("iface", ["eth0;id", "$(id)", "", "eth0 -oN /etc/x", "../x", "-oN"])
def test_iface_bad_name_rejected_even_if_listed(iface):
    with pytest.raises(ValueError):
        c.nmap_syn(iface, ["10.0.0.0/24"], 3, "22", JOB, known_ifaces=IFACES | {iface})


@pytest.mark.parametrize("ports", ["0", "70000", "22;id", "1-", "80-22", "a,b", "22,,80", "-p 1"])
def test_ports_rejected(ports):
    with pytest.raises(ValueError):
        c.parse_ports(ports)


def test_ports_normalized():
    assert c.parse_ports(" 22, 80-82 ,443") == "22,80-82,443"
    assert c.parse_ports("-") == "-"
    assert c.expand_ports("22,80-82") == [22, 80, 81, 82]


@pytest.mark.parametrize("t", [-1, 6, "3", 3.5, True])
def test_timing_rejected(t):
    with pytest.raises(ValueError):
        c.nmap_syn("eth0", ["10.0.0.0/24"], t, "22", JOB, known_ifaces=IFACES)


@pytest.mark.parametrize("tgt", ["10.0.0.0/24;id", "evil.com", "10.0.0.300", "-iL /etc/passwd", "::1"])
def test_target_rejected(tgt):
    with pytest.raises(ValueError):
        c.nmap_syn("eth0", [tgt], 3, "22", JOB, known_ifaces=IFACES)


@pytest.mark.parametrize("adv", [{"max_rate": 0}, {"max_retries": 99}, {"host_timeout": "5m;id"}, {"bogus": 1}])
def test_advanced_rejected(adv):
    with pytest.raises(ValueError):
        c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "22", JOB, known_ifaces=IFACES, advanced=adv)


def test_bad_job_id():
    with pytest.raises(ValueError):
        c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "22", "../../etc/x", known_ifaces=IFACES)


def test_wrap_sudo_quoted_and_stdin_detached():
    argv = c.nmap_syn("eth0", ["10.0.0.0/24"], 3, "22", JOB, known_ifaces=IFACES)
    s = c.wrap_scan(argv, "sudo")
    parts = shlex.split(s)
    assert parts[:5] == ["sudo", "-k", "-S", "-p", ""]
    assert parts[5:7] == ["setsid", "-w"]
    assert "echo SEGMAP_PGID=$$" in parts[9] and "</dev/null" in parts[9]
    assert parts[11:] == argv
    assert c.wrap_scan(argv, "root").startswith("setsid -w sh -c")


def test_kill_and_file_commands():
    assert c.kill_cmd(4242, "TERM", "sudo") == "sudo -k -S -p '' env kill -TERM -- -4242"
    assert c.kill_cmd(4242, "0", "cap") == "env kill -0 -- -4242"
    with pytest.raises(ValueError):
        c.kill_cmd("4242; rm -rf /", "TERM", "root")
    with pytest.raises(ValueError):
        c.kill_cmd(1, "TERM", "root")  # never pgid 1
    with pytest.raises(ValueError):
        c.kill_cmd(4242, "HUP;id", "root")
    assert c.cat_cmd(JOB, "sudo") == f"sudo -k -S -p '' cat /tmp/segmap-{JOB}.xml"
    assert c.rm_cmd(JOB, "root") == f"rm -f /tmp/segmap-{JOB}.xml"


def test_egress_target_must_be_ip():
    with pytest.raises(ValueError):
        c.nmap_egress("eth0", "evil.example", 3, "1-1024", JOB, known_ifaces=IFACES)
    argv = c.nmap_egress("eth0", "203.0.113.10", 3, "all", JOB, known_ifaces=IFACES)
    assert argv[-1] == "203.0.113.10" and "-p-" in argv
    assert argv[argv.index("--script") + 1] == "banner"
