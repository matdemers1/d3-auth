"""REQ-093: identity is (iss, sub), and the package offers no way to do it by email."""

import d3auth_client
from d3auth_client import Identity, identity_key, is_same_identity


def test_keys_on_both_halves_because_a_sub_means_nothing_without_its_issuer():
    here = Identity(iss="https://a.test", sub="1")
    there = Identity(iss="https://b.test", sub="1")
    assert identity_key(here) != identity_key(there)
    assert is_same_identity("https://a.test#1", here)
    assert not is_same_identity("https://a.test#1", there)


def test_exports_nothing_that_looks_up_a_person_by_email():
    assert [name for name in d3auth_client.__all__ if "email" in name.lower()] == []
