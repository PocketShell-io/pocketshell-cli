"""TLS context and urllib opener for requests that carry a credential.

Lives outside :mod:`pocketshell.account` so the gateway client keeps working
(and failing cleanly) when the account package cannot be imported.

Used for every request that sends the ``psc_`` CLI session token or a broker
gateway JWT: the broker client, ``gateway devices`` and the ``gateway proxy``
WebSocket. Two environment knobs that the stdlib would otherwise honour are
deliberately ignored, because either one lets whoever controls the process
environment (an ``.envrc``, a shared shell profile, an ordinary corporate
setting) capture the token:

* ``HTTPS_PROXY`` / ``https_proxy`` / ``HTTP_PROXY`` / ``http_proxy`` /
  ``ALL_PROXY`` / ``NO_PROXY``: the opener installs an empty
  :class:`urllib.request.ProxyHandler`, so requests always go direct. (With
  ``POCKETSHELL_BROKER_INSECURE_DEV`` the request is cleartext, and a proxy
  would read the token verbatim; over https a proxy still learns the
  destination and can withhold service.)
* ``SSL_CERT_FILE`` / ``SSL_CERT_DIR``: OpenSSL reads these in
  ``set_default_verify_paths()``, which :func:`ssl.create_default_context`
  calls. Pointing them at an attacker CA would let a man in the middle
  terminate TLS. The trust store here is built only from the platform's
  *compiled-in* default locations (``ssl.get_default_verify_paths()``'s
  ``openssl_cafile`` / ``openssl_capath``), plus the system certificate
  store on Windows.

If no trust anchors are found at those locations, the context stays empty
and every handshake fails verification: fail closed, never fall back to the
environment. (``certifi`` is not a dependency of this package and is not
consulted.)

This does not make the process environment untrusted in general: anything
that can set ``PYTHONPATH``, ``LD_PRELOAD`` and the like can already run code
inside this process, which no CLI can defend against.
"""

from __future__ import annotations

import os
import ssl
import sys
import urllib.request


def token_ssl_context() -> ssl.SSLContext:
    """CERT_REQUIRED + hostname-checking TLS >= 1.2 context, env-independent."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # verify_mode=CERT_REQUIRED, check_hostname
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    paths = ssl.get_default_verify_paths()
    cafile = paths.openssl_cafile
    capath = paths.openssl_capath
    if cafile and os.path.isfile(cafile):
        ctx.load_verify_locations(cafile=cafile)
    if capath and os.path.isdir(capath):
        ctx.load_verify_locations(capath=capath)
    if sys.platform == "win32":  # pragma: no cover - platform specific
        for store in ("CA", "ROOT"):
            for cert, encoding, trust in ssl.enum_certificates(store):
                if encoding == "x509_asn" and (
                    trust is True or ssl.Purpose.SERVER_AUTH.oid in trust
                ):
                    try:
                        ctx.load_verify_locations(cadata=cert)
                    except ssl.SSLError:
                        pass
    return ctx


def token_opener(*handlers: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    """A urllib opener that never uses an environment proxy and verifies TLS
    against :func:`token_ssl_context`. ``handlers`` (e.g. a no-redirect
    handler) are added as given."""
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=token_ssl_context()),
        *handlers,
    )
