"""Owner-only, resumable upgrade of an enrolled tray's measured closure.

Only public paths and receipts are journalled; key and enrollment bytes stay put.
"""
from __future__ import annotations

import json
import ntpath
from pathlib import Path


def repair(root: Path):
    from pocketshell import __version__, tray_bundle as tray
    from pocketshell.gateway import service_agent_endpoint as eps
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_common as common
    from pocketshell.gateway import service_user_agent as agent
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    paths = inst.NativePaths(api)
    journal = agent._path("tray-upgrade.json")
    authority = str(tray.home() / "managed-runtime/authority.json")
    pending = agent._read_private(journal)
    if pending is None:
        # Full old release validation, excluding historical OS hashes. The
        # owner/SID, manifest, catalog, keys and path authority still gate this.
        with agent._OperationLock():
            b, m, _key = agent.load_binding(api=api, runner=common.run_child, revalidate=True)
            tray.check_own_binding(b)
            if not b.get("enrolled"):
                raise RuntimeError("Complete Gateway Setup before upgrading this installation")
            receipt, sha, _closure = eps.load_authority(authority, api.current_sid(), paths)
            if sha != b.get("authoritySHA256"):
                raise RuntimeError("The authority changed; repair refused")
            plan = {"binding": b, "keys": receipt["keys"], "source": str(root.resolve()),
                    "expect": agent._binding_sha256(), "authority": authority}
        doc, code = agent.stop(api=api, runner=common.run_child)
        if code:
            raise RuntimeError((doc.get("error") or {}).get("message") or "Cannot stop the old gateway")
        with agent._OperationLock():
            agent._expect_prior(plan["expect"])
            # Force the cross-generation guard: no custody and a proven stop.
            agent._replacement_guard(dict(b, manifestSHA256="upgrade"), api)
            agent._write_private(journal, json.dumps(plan).encode())
    with agent._OperationLock():
        plan = json.loads(agent._read_private(journal))
        tray.check_own_binding(plan["binding"])
        if plan["source"] != str(root.resolve()) or plan["authority"] != authority:
            raise RuntimeError("Resume repair using the same installer runtime")
        if agent._binding_sha256() != plan["expect"]:
            # A crash after the atomic bind may leave only journal cleanup.
            current, _manifest, _key = agent.load_binding(api=api, runner=common.run_child, revalidate=True)
            tray.check_own_binding(current)
            receipt, _sha, _closure = eps.load_authority(authority, api.current_sid(), paths)
            catalog = inst.parse_catalog((root.parent / "host-runtime-catalog.json").read_bytes())
            if (receipt["release"] != catalog["release"] or current.get("deviceId") != plan["binding"]["deviceId"]
                    or receipt["keys"] != plan["keys"]):
                raise RuntimeError("The gateway binding changed during repair")
            Path(journal).unlink()
            return receipt
        agent._expect_prior(plan["expect"])
        b = plan["binding"]
        agent._replacement_guard(dict(b, manifestSHA256="upgrade"), api)

        def show(helper):
            binary = win.resolve_helper(helper, common.run_child)
            return common.check_enrollment(binary, b["configDir"], common.run_child), win.file_sha256(binary)

        receipt = eps.install_endpoint_runtime(
            user_data=str(tray.home()), catalog_path=str(root.parent / "host-runtime-catalog.json"),
            staged=str(root), config_dir=b["configDir"], keys_mode="migrated",
            endpoint_inputs=json.dumps({"version": 1, "hostKey": plan["keys"]["hostKey"],
                                       "authorizedKeys": plan["keys"]["authorizedKeys"]}).encode(),
            owner_sid=api.current_sid(), account=eps.local_account(api.current_sid()),
            show=show, system_roles=eps.measure_system_roles(api, api.current_sid()),
            paths=paths, folders=inst.known_folders(), cli_version=__version__)
        if receipt["keys"]["hostKeyPublic"] != plan["keys"]["hostKeyPublic"]:
            raise RuntimeError("The enrolled host key changed; repair refused")
        receipt["keys"] = plan["keys"]
        paths.write(authority, json.dumps(receipt, indent=1).encode())
        # bind() preserves the enrollment and checks the new measured closure.
        catalog = inst.parse_catalog((root.parent / "host-runtime-catalog.json").read_bytes())
        helper = ntpath.join(receipt["location"]["root"], "releases", receipt["release"],
                             *eps.role_file(catalog, "helper")["path"].split("/"))
        agent.bind(receipt["endpoint"]["manifest"], b["configDir"], helper,
                   api=api, runner=common.run_child, authority=authority, expect=plan["expect"])
        # If interruption follows bind, the journal is stale but harmless:
        # main only upgrades when the staged and installed catalogs differ.
        Path(journal).unlink()
    return receipt
