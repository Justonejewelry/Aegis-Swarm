from uuid import uuid4

import pytest

from aegis.analytics.graph_store import GraphStore, get_graph_store


def test_graph_store_paths_and_concentration():
    store = GraphStore()
    eid = uuid4()
    store.add_edges(
        eid,
        [
            {"src": "userA", "dst": "groupHelpdesk", "relation": "member"},
            {"src": "groupHelpdesk", "dst": "groupDomainAdmins", "relation": "member"},
            {"src": "groupDomainAdmins", "dst": "dc01", "relation": "admin"},
            {"src": "userB", "dst": "groupHelpdesk", "relation": "member"},
        ],
    )
    paths = store.shortest_paths(eid, entries=["userA"], targets=["dc01"])
    assert len(paths) == 1
    assert paths[0] == ["userA", "groupHelpdesk", "groupDomainAdmins", "dc01"]

    conc = store.privilege_concentration(eid, high_value=["dc01", "groupDomainAdmins"])
    assert any(c["node"] == "userA" for c in conc)

    data = store.to_dict(eid)
    assert len(data["edges"]) == 4
    assert "userA" in data["nodes"]


def test_singleton():
    a = get_graph_store()
    b = get_graph_store()
    assert a is b
