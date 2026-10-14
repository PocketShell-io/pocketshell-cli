"""Owned Win32 OpenSSH shell/PATH derivation for the catalogued private runtime.

No registry default shell or user/system PATH is consulted. Paths are derived
from the held sshd-session image's release layout, whose files the guardian
already validates. This adapter is deliberately not a system OpenSSH build.
"""

PWD = r'''static int
set_defaultshell()
{
    wchar_t candidate[PATH_MAX], path[PATH_MAX];
    if (pw_shellpath != NULL)
        return 0;
    if (swprintf_s(candidate, _countof(candidate), L"%s\\..\\shell\\usr\\bin\\bash.exe", __wprogdir) < 0 ||
        _wfullpath(path, candidate, _countof(path)) == NULL ||
        GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) {
        errno = ENOENT;
        return -1;
    }
    pw_shellpath = utf16_to_utf8(path);
    shell_command_option = _strdup("--noprofile --norc -c");
    shell_arguments = _strdup("--noprofile --norc -i");
    if (!pw_shellpath || !shell_command_option || !shell_arguments) {
        free(pw_shellpath); free(shell_command_option); free(shell_arguments);
        pw_shellpath = shell_command_option = shell_arguments = NULL;
        errno = ENOMEM;
        return -1;
    }
    convertToBackslash(pw_shellpath);
    to_lower_case(pw_shellpath);
    arg_escape = TRUE;
    return 0;
}'''

PATH = r'''    /* PocketShell private release: managed tools precede every other directory.
     * Never import user or registry PATH dependencies. */
    wchar_t candidate[PATH_MAX], root[PATH_MAX], system[MAX_PATH], path[PATH_MAX * 5];
    if (swprintf_s(candidate, _countof(candidate), L"%s\\..\\..", __wprogdir) < 0 ||
        _wfullpath(root, candidate, _countof(root)) == NULL ||
        !GetSystemDirectoryW(system, _countof(system)) ||
        swprintf_s(path, _countof(path), L"%s\\python;%s;%s\\endpoint\\shell\\usr\\bin;%s\\endpoint\\shell\\mingw64\\bin;%s",
                   root, root, root, root, system) < 0 ||
        _wputenv_s(L"PATH", path) != 0 || !SetEnvironmentVariableW(L"PATH", path))
        fatal("Cannot construct the PocketShell private runtime PATH");
'''

COMMANDS = r'''static void
set_managed_commands(void)
{
    wchar_t candidate[PATH_MAX], root[PATH_MAX];
    if (swprintf_s(candidate, _countof(candidate), L"%s\\..\\..", __wprogdir) < 0 ||
        _wfullpath(root, candidate, _countof(root)) == NULL)
        fatal("Cannot derive the PocketShell command root");
    for (wchar_t *p = root; *p; ++p)
        if (*p == L'\\') *p = L'/';
    /* Older PSC clients deliberately prepend user bin directories inside
     * /bin/sh -lc. Exported Bash functions keep the managed commands selected
     * through that nested shell, without modifying the user's profile/PATH. */
    if (!SetEnvironmentVariableW(L"POCKETSHELL_RUNTIME_ROOT", root) ||
        !SetEnvironmentVariableW(L"BASH_FUNC_pocketshell%%",
            L"() { command \"$POCKETSHELL_RUNTIME_ROOT/pocketshell.exe\" \"$@\"; }") ||
        !SetEnvironmentVariableW(L"BASH_FUNC_a%%",
            L"() { command \"$POCKETSHELL_RUNTIME_ROOT/python/a.exe\" \"$@\"; }") ||
        !SetEnvironmentVariableW(L"BASH_FUNC_aplexer%%",
            L"() { command \"$POCKETSHELL_RUNTIME_ROOT/python/aplexer.exe\" \"$@\"; }"))
        fatal("Cannot export the PocketShell managed commands");
}

'''


def patch_pwd(text):
    begin = text.index("static int\nset_defaultshell()\n{")
    end = text.index("\n}", begin) + 2
    if "RegQueryValueExW(reg_key, L\"DefaultShell\"" not in text[begin:end]:
        raise ValueError("Unexpected upstream default-shell implementation")
    return text[:begin] + PWD + text[end:]


def patch_session(text):
    begin = text.index("\t/* PATH is a special case.")
    end = text.index("\n}", begin)
    if 'L"Environment", L"PATH"' not in text[begin:end]:
        raise ValueError("Unexpected upstream session PATH implementation")
    patched = text[:begin] + PATH + text[end:]
    # Win32 environment names are case-insensitive; registry exports usually
    # spell this one 'Path'. It must not overwrite the private PATH above.
    old = 'strncmp(env_name, "PATH=", strlen("PATH="))'
    if patched.count(old) != 1:
        raise ValueError("Unexpected upstream environment PATH filter")
    patched = patched.replace(old, '_strnicmp(env_name, "PATH=", strlen("PATH="))')
    # Bash detects SSH stdin and reads .bashrc for noninteractive commands.
    # shell_arguments is only used for an interactive PTY by upstream; it does
    # not protect this exec branch. Pass separate argv elements for exec, and
    # remove the explicit noninteractive startup-file environment hooks.
    patched = patched.replace('char *spawn_argv[4] = { NULL, };', 'char *spawn_argv[6] = { NULL, };')
    previous = '''\t\t\tif (exec_command) {
\t\t\t\tspawn_argv[1] = shell_command_option_local;
\t\t\t\tspawn_argv[2] = exec_command;
\t\t\t}'''
    replacement = '''\t\t\tif (shell_type == SH_BASH) {
                SetEnvironmentVariableW(L"BASH_ENV", NULL);
                SetEnvironmentVariableW(L"ENV", NULL);
                spawn_argv[1] = "--noprofile";
                spawn_argv[2] = "--norc";
                if (exec_command) {
                    spawn_argv[3] = "-c";
                    spawn_argv[4] = exec_command;
                }
            } else if (exec_command) {
                spawn_argv[1] = shell_command_option_local;
                spawn_argv[2] = exec_command;
            }'''
    if previous not in patched:
        raise ValueError("Unexpected upstream exec-shell argv implementation")
    patched = patched.replace(previous, replacement)
    anchor = "static int\nsetup_session_env(struct ssh *ssh, Session* s)"
    if anchor not in patched:
        raise ValueError("Unexpected upstream session environment implementation")
    patched = patched.replace(anchor, COMMANDS + anchor)
    begin = patched.index(anchor)
    end = patched.index("\nint do_exec_windows", begin)
    section = patched[begin:end]
    if section.count("\tret = 0;") != 1:
        raise ValueError("Unexpected upstream session environment return")
    return patched[:begin] + section.replace("\tret = 0;", "\tset_managed_commands();\n\tret = 0;") + patched[end:]
