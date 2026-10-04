from ssdf_policy.object_book import content_hash, diff_new_object_books


def _collected(device="vSRX-test10", provider="juniper", addr="10.1.1.0/24"):
    return {
        "provider": provider,
        "device_name": device,
        "collected_at": "2026-09-30T00:00:00.000Z",
        "object_book": {"address_books": {"global": {"addresses": {"A1": addr}}}},
    }


def test_content_hash_stable_for_identical_book():
    a = _collected()
    b = _collected()
    assert content_hash(a["object_book"]) == content_hash(b["object_book"])


def test_content_hash_changes_when_book_changes():
    a = _collected(addr="10.1.1.0/24")
    b = _collected(addr="10.1.2.0/24")
    assert content_hash(a["object_book"]) != content_hash(b["object_book"])


def test_diff_emits_row_for_never_seen_device():
    rows = diff_new_object_books([_collected()], last_hash_by_key={})
    assert len(rows) == 1
    assert rows[0]["provider"] == "juniper"
    assert rows[0]["device_name"] == "vSRX-test10"
    assert rows[0]["content_hash"] == content_hash(_collected()["object_book"])


def test_diff_skips_unchanged_device():
    item = _collected()
    known = {(item["provider"], item["device_name"]): content_hash(item["object_book"])}
    assert diff_new_object_books([item], known) == []


def test_diff_emits_row_when_book_changes():
    old = _collected(addr="10.1.1.0/24")
    new = _collected(addr="10.1.2.0/24")
    known = {(old["provider"], old["device_name"]): content_hash(old["object_book"])}
    rows = diff_new_object_books([new], known)
    assert len(rows) == 1
    assert rows[0]["content_hash"] == content_hash(new["object_book"])


def test_diff_is_independent_per_device():
    dev_a = _collected(device="vSRX-1", addr="10.1.1.0/24")
    dev_b = _collected(device="vSRX-2", addr="10.2.2.0/24")
    known = {(dev_a["provider"], dev_a["device_name"]): content_hash(dev_a["object_book"])}
    rows = diff_new_object_books([dev_a, dev_b], known)
    assert [r["device_name"] for r in rows] == ["vSRX-2"]
