"""Task Scheduler OBJECT authority: the task and its folder security descriptors.

Mirrors the Windows native owner's frozen proposal ec8534aa
(``task-object-authority.ps1`` sha256 02dbc13b…, function
``AssertTaskObjectAuthority``) so the service and the native qualification
helper accept and refuse exactly the same descriptors:

* both objects: owner = the own SID; a non-null DACL; descriptor control bits
  only DACL_PRESENT (0x4), DACL_PROTECTED (0x1000) and SELF_RELATIVE (0x8000)
  (36868); every ACE an ACCESS_ALLOWED ACE (type 0) with flags 0 (no
  inherited / inherit-only / container / object inheritance), no callback or
  object ACE, and a trustee among {own SID, SYSTEM, BUILTIN\\Administrators};
* the parent FOLDER must also be PROTECTED, with exactly one GENERIC_ALL
  (0x10000000) or FILE_ALL_ACCESS (0x1F01FF) grant per trusted SID;
* the TASK: exactly one FILE_ALL_ACCESS (0x1F01FF, 2032127) grant per trusted
  SID, plus at most ONE own-SID FILE_GENERIC_READ (0x120089, 1179785) — the
  principal ACE the scheduler adds (MS-TSCH SchRpcRegisterTask) unless
  TASK_DONT_ADD_PRINCIPAL_ACE; the scheduler was measured to drop the task's
  P control, so the task need not be protected (its folder must be).

Only the task-object check lives here. Filesystem and private-desktop guards
are separate and are NOT weakened by it. Descriptors arrive as SDDL from
``IRegisteredTask/ITaskFolder.GetSecurityDescriptor(7)``; this parser accepts
the canonical SDDL subset those return and refuses anything else.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

SYSTEM = "S-1-5-18"
ADMINISTRATORS = "S-1-5-32-544"
FILE_ALL_ACCESS = 0x1F01FF  # 2032127
FILE_GENERIC_READ = 0x120089  # 1179785
GENERIC_ALL = 0x10000000  # 268435456
SE_DACL_PRESENT, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED, SE_SELF_RELATIVE = 0x4, 0x400, 0x1000, 0x8000
SE_DACL_AUTO_INHERIT_REQ = 0x100
ALLOWED_CONTROL = SE_DACL_PRESENT | SE_DACL_PROTECTED | SE_SELF_RELATIVE  # 36868

_SID_ALIASES = {
    "SY": SYSTEM, "BA": ADMINISTRATORS, "WD": "S-1-1-0", "AU": "S-1-5-11", "BU": "S-1-5-32-545",
    "BG": "S-1-5-32-546", "PU": "S-1-5-32-547", "IU": "S-1-5-4", "NU": "S-1-5-2", "SU": "S-1-5-6",
    "LS": "S-1-5-19", "NS": "S-1-5-20", "CO": "S-1-3-0", "CG": "S-1-3-1", "OW": "S-1-3-4",
    "AC": "S-1-15-2-1", "RC": "S-1-5-12", "WR": "S-1-5-33", "AN": "S-1-5-7", "ED": "S-1-5-9",
    "PS": "S-1-5-10", "SO": "S-1-5-32-549", "SA": "S-1-5-32-550", "PO": "S-1-5-32-550",
    "RD": "S-1-5-32-555", "RU": "S-1-5-32-554", "NO": "S-1-5-32-556", "MU": "S-1-5-32-558",
    "LU": "S-1-5-32-559", "IS": "S-1-5-32-568", "CY": "S-1-5-32-569", "ER": "S-1-5-32-573",
    "HA": "S-1-5-32-578", "RM": "S-1-5-32-580", "LA": None, "LG": None, "DA": None, "DU": None,
}
_RIGHTS = {
    "GA": 0x10000000, "GR": 0x80000000, "GW": 0x40000000, "GX": 0x20000000,
    "RC": 0x20000, "SD": 0x10000, "WD": 0x40000, "WO": 0x80000,
    "RP": 0x10, "WP": 0x20, "CC": 0x1, "DC": 0x2, "LC": 0x4, "SW": 0x8, "LO": 0x80, "DT": 0x40, "CR": 0x100,
    "FA": 0x1F01FF, "FR": 0x120089, "FW": 0x120116, "FX": 0x1200A0,
    "KA": 0xF003F, "KR": 0x20019, "KW": 0x20006, "KX": 0x20019,
}
_SID_RE = re.compile(r"S-1-\d+(-\d+)+")


class SddlError(ValueError):
    pass


@dataclass(frozen=True)
class Ace:
    type: str  # "A", "D", "OA", ... (only "A" with no flags is acceptable)
    flags: str
    mask: int
    sid: str
    conditional: bool


@dataclass(frozen=True)
class Descriptor:
    owner: Optional[str]
    control: int
    dacl: Optional[tuple]  # None = null DACL (NO_ACCESS_CONTROL or absent)


def _sid(token: str) -> str:
    if token in _SID_ALIASES:
        value = _SID_ALIASES[token]
        if value is None:
            raise SddlError(f"domain-relative SID alias {token} is not supported")
        return value
    if _SID_RE.fullmatch(token):
        return token
    raise SddlError(f"unrecognised SID {token!r}")


def _rights(token: str) -> int:
    if token.lower().startswith("0x"):
        return int(token, 16)
    if token.isdigit():
        return int(token)
    if len(token) % 2:
        raise SddlError(f"unrecognised rights {token!r}")
    mask = 0
    for i in range(0, len(token), 2):
        part = token[i:i + 2]
        if part not in _RIGHTS:
            raise SddlError(f"unrecognised right {part!r}")
        mask |= _RIGHTS[part]
    return mask


def parse_sddl(sddl: str) -> Descriptor:
    """Owner, DACL control bits and DACL of a self-relative SDDL string."""
    if not isinstance(sddl, str) or not sddl.strip():
        raise SddlError("empty security descriptor")
    text = sddl.strip()
    owner = None
    control = SE_SELF_RELATIVE
    dacl = None
    pos = 0
    while pos < len(text):
        tag = text[pos:pos + 2]
        if tag not in ("O:", "G:", "D:", "S:"):
            raise SddlError(f"unexpected SDDL component at {pos}")
        pos += 2
        if tag in ("O:", "G:"):
            end = pos
            while end < len(text) and text[end:end + 2] not in ("O:", "G:", "D:", "S:"):
                end += 1
            if tag == "O:":
                owner = _sid(text[pos:end])
            pos = end
            continue
        # D: or S: — flags then (ace)(ace)...
        end = pos
        while end < len(text) and text[end] != "(" and text[end:end + 2] not in ("O:", "G:", "D:", "S:"):
            end += 1
        flags = text[pos:end]
        pos = end
        aces = []
        while pos < len(text) and text[pos] == "(":
            depth, close = 0, pos
            while close < len(text):
                if text[close] == "(":
                    depth += 1
                elif text[close] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                close += 1
            if close >= len(text):
                raise SddlError("unterminated ACE")
            aces.append(text[pos + 1:close])
            pos = close + 1
        if tag == "S:":
            continue
        rest = flags
        null = False
        while rest:
            if rest.startswith("NO_ACCESS_CONTROL"):
                null, rest = True, rest[len("NO_ACCESS_CONTROL"):]
            elif rest.startswith("AI"):
                control |= SE_DACL_AUTO_INHERITED
                rest = rest[2:]
            elif rest.startswith("AR"):
                control |= SE_DACL_AUTO_INHERIT_REQ
                rest = rest[2:]
            elif rest.startswith("P"):
                control |= SE_DACL_PROTECTED
                rest = rest[1:]
            else:
                raise SddlError(f"unrecognised DACL flags {flags!r}")
        if null:
            dacl = None
            continue
        control |= SE_DACL_PRESENT
        parsed = []
        for ace in aces:
            parts = ace.split(";")
            if len(parts) < 6:
                raise SddlError(f"malformed ACE ({ace!r})")
            conditional = len(parts) > 6 or ace.count("(") > 0
            parsed.append(Ace(parts[0], parts[1], _rights(parts[2]), _sid(parts[5]), conditional))
        dacl = tuple(parsed)
    return Descriptor(owner, control, dacl)


def _object_problems(sddl: Optional[str], owner_sid: str, *, folder: bool) -> list:
    what = "task folder" if folder else "task"
    if sddl is None:
        return [f"{what} security descriptor is unavailable"]
    try:
        sd = parse_sddl(sddl)
    except SddlError as exc:
        return [f"{what} security descriptor refused ({exc})"]
    if sd.owner != owner_sid or not sd.control & SE_DACL_PRESENT or sd.dacl is None:
        return [f"{what} object owner/non-null DACL refused (owner {sd.owner})"]
    if sd.control & ~ALLOWED_CONTROL:
        return [f"{what} object unexpected descriptor controls refused (0x{sd.control:X})"]
    if folder and not sd.control & SE_DACL_PROTECTED:
        return [f"{what} DACL is not protected"]
    trusted = (owner_sid, SYSTEM, ADMINISTRATORS)
    full: set = set()
    principal_read = 0
    for ace in sd.dacl:
        if ace.type != "A" or ace.flags or ace.conditional:
            return [f"{what} ACE type/inheritance/condition refused ({ace.type};{ace.flags})"]
        if ace.sid not in trusted:
            return [f"{what} foreign trustee {ace.sid} refused"]
        full_masks = (GENERIC_ALL, FILE_ALL_ACCESS) if folder else (FILE_ALL_ACCESS,)
        if ace.mask in full_masks:
            if ace.sid in full:
                return [f"{what} duplicate full-control ACE for {ace.sid} refused"]
            full.add(ace.sid)
        elif not folder and ace.sid == owner_sid and ace.mask == FILE_GENERIC_READ and principal_read == 0:
            principal_read = 1
        else:
            return [f"{what} unexpected access mask 0x{ace.mask:X} / duplicate principal read for {ace.sid} refused"]
    if full != set(trusted):
        return [f"{what} required full-control trustees absent ({sorted(set(trusted) - full)})"]
    return []


def task_object_problems(task_sddl: Optional[str], folder_sddl: Optional[str], owner_sid: str) -> list:
    """[] when both the task and its parent folder satisfy contract ec8534aa
    (folder first, as AssertTaskObjectAuthority checks parentSD then sd)."""
    return _object_problems(folder_sddl, owner_sid, folder=True) or \
        _object_problems(task_sddl, owner_sid, folder=False)


def task_sddl(owner_sid: str) -> str:
    """Requested task descriptor (RegisterTask sddl): own owner, exact trusted FA."""
    return f"O:{owner_sid}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{owner_sid})"


def folder_sddl(owner_sid: str) -> str:
    """Requested \\PocketShell folder descriptor: protected, exact trusted GA."""
    return f"O:{owner_sid}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{owner_sid})"
