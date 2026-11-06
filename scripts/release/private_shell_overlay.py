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

# MSYS Bash parses its Windows command line differently from the Microsoft CRT:
# paired backslashes must also be escaped before ordinary characters. This is
# argv transport, not Bash-language quoting; the complete script stays intact.
MSYS_SPAWN_FLAG = "#define POCKETSHELL_SPAWN_MSYS_ARGV 0x4000\n"
PTY_ARGV = r'''static char *
pocketshell_quote_pty_script(const char *script)
{
    size_t length = strlen(script);
    char *encoded, *out;
    if (length > (SIZE_MAX - 3) / 2) {
        errno = EOVERFLOW;
        return NULL;
    }
    if ((encoded = malloc(length * 2 + 3)) == NULL)
        return NULL;
    out = encoded;
    *out++ = '"';
    for (const char *p = script; *p; p++) {
        if (*p == '\\' || *p == '"') *out++ = '\\';
        *out++ = *p;
    }
    *out++ = '"';
    *out = '\0';
    return encoded;
}

'''

MSYS_COMMANDLINE = r'''static char *
pocketshell_msys_commandline(const char *cmd, char *const argv[], BOOLEAN prepend_module_path)
{
    /* Keep the existing executable resolution/argv[0] policy. Only the
     * remaining operands use the explicitly selected MSYS decoder. */
    char *base = build_commandline_string(cmd, NULL, prepend_module_path);
    char *result, *out;
    size_t size;
    if (base == NULL) return NULL;
    size = strlen(base) + 1;
    if (argv) for (char *const *arg = argv; *arg; arg++) {
        size_t length = strlen(*arg);
        if (length > (SIZE_MAX - 4) / 2 || size > SIZE_MAX - (length * 2 + 4)) {
            free(base); errno = EOVERFLOW; return NULL;
        }
        size += length * 2 + 4;
    }
    result = malloc(size);
    if (result == NULL) { free(base); return NULL; }
    strcpy_s(result, size, base);
    free(base);
    out = result + strlen(result);
    if (argv) for (char *const *arg = argv; *arg; arg++) {
        char *encoded = pocketshell_quote_pty_script(*arg);
        if (encoded == NULL) { free(result); return NULL; }
        *out++ = ' ';
        size_t length = strlen(encoded);
        memcpy(out, encoded, length);
        out += length;
        free(encoded);
    }
    *out = '\0';
    return result;
}

'''


def patch_spawn(text):
    """Explicit private attribute; preserve every unselected spawn caller."""
    anchor = "static int\nspawn_child_internal("
    signature = "BOOLEAN prepend_module_path, BOOLEAN load_user_env)\n{"
    begin = text.index(anchor)
    end = text.index("\n}", begin) + 2
    body = text[begin:end]
    if body.count(signature) != 1:
        raise ValueError("Unexpected upstream spawn-child signature")
    body = body.replace(signature, "BOOLEAN prepend_module_path, BOOLEAN load_user_env, BOOLEAN msys_argv)\n{")
    old = "build_commandline_string(cmd, argv, prepend_module_path)"
    if body.count(old) != 1:
        raise ValueError("Unexpected upstream command-line construction")
    body = body.replace(old, "(msys_argv ? pocketshell_msys_commandline(cmd, argv, prepend_module_path) : " + old + ")")
    patched = text[:begin] + MSYS_SPAWN_FLAG + "#include <stdint.h>\n" + PTY_ARGV + MSYS_COMMANDLINE + body + text[end:]
    old_call = "spawn_child_internal(path, argv + 1, &si_ex, sc_flags, user_token, prepend_module_path, load_user_env)"
    if patched.count(old_call) != 1:
        raise ValueError("Unexpected upstream spawn-child caller")
    patched = patched.replace(old_call, old_call[:-1] + ",\n"
                              "        attrp && (attrp->flags & POCKETSHELL_SPAWN_MSYS_ARGV))")
    # The private attribute is never a Windows creation flag. Existing pgroup
    # behavior is unchanged for every caller without this new attribute.
    group = "attrp && attrp->flags == POSIX_SPAWN_SETPGROUP"
    if patched.count(group) != 1:
        raise ValueError("Unexpected upstream process-group selection")
    return patched.replace(group, "attrp && (attrp->flags & ~POCKETSHELL_SPAWN_MSYS_ARGV) == POSIX_SPAWN_SETPGROUP")


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
    # The PTY branch constructs CreateProcessW's command line directly, unlike
    # the non-PTY posix_spawn argv below. Raw SSH scripts otherwise lose every
    # word after the first when Bash interprets its -c operand.
    old_pty = '''\t\tif (command) {
\t\t\tsize_t len = strlen(shell) + 1 + strlen(shell_command_option_local) + 1 + strlen(command) + 1;'''
    new_pty = '''\t\tif (command) {
            char *encoded_script = shell_type == SH_BASH ? pocketshell_quote_pty_script(command) : NULL;
            const char *pty_script = shell_type == SH_BASH ? encoded_script : command;
            if (pty_script == NULL)
                goto cleanup;
\t\t\tsize_t len = strlen(shell) + 1 + strlen(shell_command_option_local) + 1 + strlen(pty_script) + 1;'''
    if patched.count(old_pty) != 1 or patched.count('strcat_s(pty_cmd, len, command);') != 1:
        raise ValueError("Unexpected upstream PTY shell command construction")
    patched = patched.replace(old_pty, new_pty)
    patched = patched.replace('strcat_s(pty_cmd, len, command);', 'strcat_s(pty_cmd, len, pty_script);')
    end_pty = '\t\t} else {\n\t\t\tif (shell_arguments) {'
    if patched.count(end_pty) != 1:
        raise ValueError("Unexpected upstream PTY no-command branch")
    patched = patched.replace(end_pty, '            free(encoded_script);\n'
                              '            if (pty_cmd == NULL)\n                goto cleanup;\n' + end_pty)
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
    spawn = "posix_spawn(&pid, spawn_argv[0], &actions, NULL, spawn_argv, NULL)"
    if patched.count(spawn) != 1:
        raise ValueError("Unexpected upstream private-shell spawn call")
    # This explicit attribute is local to this managed SH_BASH call. It does
    # not depend on an environment switch or executable-name heuristic.
    patched = patched.replace('char *spawn_argv[6] = { NULL, };',
                              'char *spawn_argv[6] = { NULL, };\n'
                              '        posix_spawnattr_t msys_attrs = { 0 };\n'
                              '        msys_attrs.flags = POCKETSHELL_SPAWN_MSYS_ARGV;')
    patched = patched.replace(spawn, "posix_spawn(&pid, spawn_argv[0], &actions,\n"
                              "            shell_type == SH_BASH ? &msys_attrs : NULL, spawn_argv, NULL)")
    anchor = "static int\nsetup_session_env(struct ssh *ssh, Session* s)"
    if anchor not in patched:
        raise ValueError("Unexpected upstream session environment implementation")
    patched = patched.replace(anchor, MSYS_SPAWN_FLAG + PTY_ARGV + COMMANDS + anchor)
    begin = patched.index(anchor)
    end = patched.index("\nint do_exec_windows", begin)
    section = patched[begin:end]
    if section.count("\tret = 0;") != 1:
        raise ValueError("Unexpected upstream session environment return")
    return patched[:begin] + section.replace("\tret = 0;", "\tset_managed_commands();\n\tret = 0;") + patched[end:]
