"""Client-side gateway endpoint rules: device ids and `--server` resolution."""

from __future__ import annotations

import hashlib

import pytest

from pocketshell.gateway.endpoint import (
    DEFAULT_SERVER,
    EndpointError,
    host_key_alias,
    resolve_endpoint,
    validate_device_id,
)


@pytest.mark.parametrize(
    "device_id", ["abc", "home-lab", "a1.b_c:d-e", "X" * 64, "0ab"]
)
def test_valid_device_ids(device_id):
    assert validate_device_id(device_id) == device_id
    digest = hashlib.sha256(device_id.encode()).hexdigest()[:12]
    assert host_key_alias(device_id) == f"pocketshell-gateway.{device_id.lower()}-{digest}"
    assert host_key_alias(device_id) == host_key_alias(device_id).lower()


def test_host_key_alias_is_case_safe():
    """OpenSSH matches known_hosts names case-insensitively: ids differing
    only in case must still get different aliases."""
    a, b = host_key_alias("Home-Lab"), host_key_alias("home-lab")
    assert a.lower() != b.lower()


@pytest.mark.parametrize(
    "device_id",
    [
        "",
        "ab",  # too short
        "X" * 65,  # too long
        "-oProxyCommand=sh",  # option injection
        ".hidden",
        "a b c",
        "abc\n",
        "abc\nevil",
        "a/b/c",
        "a%hcd",  # ssh % token
        "abc$(id)",
        "abc;id",
        "a'bc",
        "abc*",  # known_hosts pattern metachar
        "abc,def",  # known_hosts pattern list
        "ab\x00c",
        "аbc",  # cyrillic a
    ],
)
def test_hostile_device_ids_are_refused(device_id):
    with pytest.raises(EndpointError):
        validate_device_id(device_id)


def test_default_server_is_production_wss():
    ep = resolve_endpoint(None, False)
    assert DEFAULT_SERVER == "wss://gateway.pocketshell.io"
    assert ep.ws_base == "wss://gateway.pocketshell.io"
    assert ep.http_base == "https://gateway.pocketshell.io"
    assert ep.is_production
    assert ep.warning == ""
    assert ep.client_ssh_url("home-lab") == (
        "wss://gateway.pocketshell.io/api/v1/hosts/home-lab/ssh"
    )
    assert ep.devices_url() == "https://gateway.pocketshell.io/identity/v1/devices"


@pytest.mark.parametrize(
    ("server", "ws_base"),
    [
        ("wss://gw.example", "wss://gw.example"),
        ("https://gw.example/", "wss://gw.example"),
        ("wss://GW.Example.:8443", "wss://gw.example:8443"),
        ("wss://[2001:db8::1]:443", "wss://[2001:db8::1]:443"),
    ],
)
def test_tls_servers_resolve_only_with_explicit_trust(server, ws_base):
    host = ws_base.split("//")[1].rsplit(":", 1)[0] if "]" not in ws_base else "2001:db8::1"
    with pytest.raises(EndpointError, match="--trust-gateway"):
        resolve_endpoint(server, False)
    with pytest.raises(EndpointError, match="--trust-gateway"):
        resolve_endpoint(server, False, trust_gateway="other.example")
    ep = resolve_endpoint(server, False, trust_gateway=host)
    assert ep.ws_base == ws_base
    assert not ep.is_production


def test_trust_gateway_matches_canonically():
    ep = resolve_endpoint("wss://GW.example.", False, trust_gateway="gw.EXAMPLE")
    assert ep.host == "gw.example"
    # a suffix/prefix is not a match
    with pytest.raises(EndpointError):
        resolve_endpoint("wss://evil-gw.example", False, trust_gateway="gw.example")


def test_production_alias_needs_no_trust_flag():
    assert resolve_endpoint("wss://relay.pocketshell.io", False).is_production
    assert resolve_endpoint("https://GATEWAY.pocketshell.io.:443", False).is_production


def test_idna_hosts_are_encoded():
    ep = resolve_endpoint("wss://bücher.example", False, trust_gateway="xn--bcher-kva.example")
    assert ep.host == "xn--bcher-kva.example"


@pytest.mark.parametrize(
    "server",
    [
        "ws://127.0.0.1:8080",
        "http://localhost:8080",
        "ws://[::1]:8080",
        "ws://gateway:8080",  # docker-compose service name
    ],
)
def test_plain_ws_needs_insecure_dev_and_a_lab_host(server):
    from pocketshell.gateway.endpoint import canonical_host, normalize_host

    host = normalize_host(canonical_host(server))
    with pytest.raises(EndpointError, match="--insecure-dev"):
        resolve_endpoint(server, False, trust_gateway=host)
    with pytest.raises(EndpointError, match="--trust-gateway"):
        resolve_endpoint(server, True)
    ep = resolve_endpoint(server, True, trust_gateway=host)
    assert ep.ws_base.startswith("ws://")
    if host == "gateway":
        assert "CLEARTEXT" in ep.warning
    else:
        assert ep.warning == ""


@pytest.mark.parametrize(
    "server",
    [
        "ws://gateway.pocketshell.io",
        "ws://RELAY.POCKETSHELL.IO.:8080",
        "ws://lab.example.com",  # routed DNS name: cleartext token on a network
        "ws://192.168.1.10:8080",
        "ws://10.0.0.1",
        "ws://lab.localhost",
    ],
)
def test_insecure_dev_never_allows_cleartext_to_routed_hosts(server):
    from pocketshell.gateway.endpoint import canonical_host

    with pytest.raises(EndpointError, match="cleartext"):
        resolve_endpoint(server, True, trust_gateway=canonical_host(server))


@pytest.mark.parametrize(
    "server",
    [
        "",
        "  ",
        "ftp://gw.example",
        "gw.example",
        "wss://user:pw@gw.example",
        "wss://gw.example/path",
        "wss://gw.example/?token=x",
        "wss://gw.example/#frag",
        "wss://gw.example:notaport",
        "wss://[::1",
        "wss://gw.example'; id #",
        "wss://gw.example$(id)",
        "wss://gw.example\\x",
        "wss://gw .example",
        "wss://gw.example\n",
        "wss://",
        "wss://gw.example?",
        "wss://gw.example#",
        "wss://[fe80::1%25eth0]",
        "wss://gw_under.example",
        "wss://gw.example;id",
        "wss://gw.example|id",
        "wss://-gw.example",
        "wss://" + "a" * 64 + ".example",
        "wss://gw\u202e.example",
    ],
)
def test_malformed_or_hostile_servers_are_refused(server):
    from pocketshell.gateway.endpoint import canonical_host

    try:
        trust = canonical_host(server)
    except EndpointError:
        trust = None
    with pytest.raises(EndpointError):
        resolve_endpoint(server, True, trust_gateway=trust)
