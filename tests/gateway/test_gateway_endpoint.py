"""Client-side gateway endpoint rules: device ids and `--server` resolution."""

from __future__ import annotations

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
    assert host_key_alias(device_id) == "pocketshell-gateway." + device_id


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
    assert ep.is_default
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
def test_tls_servers_resolve(server, ws_base):
    ep = resolve_endpoint(server, False)
    assert ep.ws_base == ws_base
    assert not ep.is_default


@pytest.mark.parametrize(
    "server",
    [
        "ws://127.0.0.1:8080",
        "http://localhost:8080",
        "ws://[::1]:8080",
        "ws://gateway:8080",  # docker-compose service name
        "ws://lab.localhost",
    ],
)
def test_plain_ws_needs_insecure_dev_and_a_lab_host(server):
    with pytest.raises(EndpointError, match="--insecure-dev"):
        resolve_endpoint(server, False)
    assert resolve_endpoint(server, True).ws_base.startswith("ws://")


@pytest.mark.parametrize(
    "server",
    [
        "ws://gateway.pocketshell.io",
        "ws://RELAY.POCKETSHELL.IO.:8080",
        "ws://lab.example.com",  # routed DNS name: cleartext token on a network
        "ws://192.168.1.10:8080",
        "ws://10.0.0.1",
    ],
)
def test_insecure_dev_never_allows_cleartext_to_routed_hosts(server):
    with pytest.raises(EndpointError):
        resolve_endpoint(server, True)


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
    ],
)
def test_malformed_or_hostile_servers_are_refused(server):
    with pytest.raises(EndpointError):
        resolve_endpoint(server, True)
