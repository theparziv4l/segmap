"""Graph edit endpoints: display-only view, block delete, per-edge findings delete."""
from fastapi.testclient import TestClient

from segmap import app as appmod, config


def test_graph_edits(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DATA", tmp_path)
    with TestClient(appmod.app, base_url="http://127.0.0.1") as c:
        S = appmod.S

        async def seed():
            await S.db.run("INSERT INTO machines(id,name,host,username,secret) VALUES (1,'m1','10.0.0.1','u',x'00')")
            await S.db.run("INSERT INTO scope(cidr,tag) VALUES ('10.24.5.0/24','CDE'),('10.30.0.0/16','non-CDE')")
            await S.db.run("INSERT INTO jobs(id,machine_id,status) VALUES ('j1',1,'done')")
            await S.db.audit(1, "10.0.0.1", "nmap ...", "j1")
            await S.db.many("INSERT INTO findings(job_id,machine_id,iface,block24,host_ip) VALUES ('j1',1,?,?,?)",
                            [("eth0", "10.24.5.0/24", "10.24.5.1"), ("eth1", "10.24.5.0/24", "10.24.5.2"),
                             ("eth0", "10.30.1.0/24", "10.30.1.1")])
        c.portal.call(seed)
        count = lambda sql: c.portal.call(S.db.one, sql)["n"]

        # view: blank labels dropped, hidden deduped
        r = c.put("/api/graph-view", json={"labels": {"m:1": " Jump ", "b:x": "  "}, "hidden": ["t:CDE", "t:CDE"]})
        assert r.json() == {"labels": {"m:1": "Jump"}, "hidden": ["t:CDE"]}
        assert c.get("/api/graph-view").json() == r.json()

        # one edge
        assert c.delete("/api/findings", params={"machine_id": 1, "iface": "eth0"}).status_code == 400
        assert c.delete("/api/findings", params={"machine_id": 1, "iface": "eth0", "block24": "10.24.5.0/24"}).status_code == 200
        assert count("SELECT COUNT(*) n FROM findings") == 2

        # block inside a wider scope entry is refused; own /24 deletes scope + findings
        r = c.delete("/api/blocks", params={"cidr": "10.30.1.0/24"})
        assert r.status_code == 400 and "10.30.0.0/16" in r.json()["detail"]
        assert c.delete("/api/blocks", params={"cidr": "10.24.5.0/24"}).json() == {"scope_deleted": 1}
        assert count("SELECT COUNT(*) n FROM scope") == 1
        assert count("SELECT COUNT(*) n FROM findings WHERE block24='10.24.5.0/24'") == 0
        assert count("SELECT COUNT(*) n FROM audit") == 1  # evidence log untouched
