"""Build a new measured tray closure from a verified existing closure.

Reuses unchanged native inputs, rebuilds the frozen Python app and reviewed
guardian, and produces a fresh catalog. Does not install, bind or read keys.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from build_tray_installer import (REPO, digest, parse_catalog, stage_guardian,
                                  stage_python_application, verify_inventory)


def build(resources, expected, destination):
    source, out = Path(resources).resolve(), Path(destination).resolve()
    catalog_path = source / 'host-runtime-catalog.json'
    if digest(catalog_path) != expected:
        raise ValueError('Base catalog digest mismatch')
    catalog = parse_catalog(catalog_path.read_bytes())
    if catalog['version'] != 3:
        raise ValueError('A complete catalog-v3 closure is required')
    verify_inventory(source / 'runtime', catalog['files'])
    if out.exists() or out == source or source in out.parents:
        raise ValueError('Use a fresh output directory outside the base closure')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO).strip():
        raise ValueError('Release builds require committed, clean source')
    out.mkdir(parents=True)
    root = out / 'runtime'
    shutil.copytree(source / 'runtime', root)
    stage_python_application(root)
    stage_guardian(root, catalog)
    catalog['source'] = commit
    catalog['release'] = 'tray-' + commit[:12]
    catalog['lineage']['cliCommit'] = commit
    catalog['lineage']['lockSHA256'] = digest(REPO / 'uv.lock')
    from pocketshell import __version__
    catalog['lineage']['cliVersion'] = __version__
    roles = {r['path']: r['role'] for r in catalog['files']}
    catalog['files'] = [{'path': p.relative_to(root).as_posix(), 'sha256': digest(p),
                         'role': roles.get(p.relative_to(root).as_posix(), 'module')}
                        for p in sorted(root.rglob('*')) if p.is_file()]
    data = json.dumps(catalog, indent=1, sort_keys=True).encode()
    parse_catalog(data)
    verify_inventory(root, catalog['files'])
    (out / 'host-runtime-catalog.json').write_bytes(data)
    receipt = {'source': commit, 'sourceDirty': False, 'baseCatalogSHA256': expected,
               'catalogSHA256': hashlib.sha256(data).hexdigest(),
               'files': len(catalog['files']), 'release': catalog['release']}
    (out / 'runtime-build-receipt.json').write_text(json.dumps(receipt, indent=2))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--resources', required=True)
    parser.add_argument('--catalog-sha256', required=True)
    parser.add_argument('--out', required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.resources, args.catalog_sha256, args.out), indent=2))
