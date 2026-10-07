#compdef rpmcrab

autoload -U is-at-least

_rpmcrab() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'*-c+[Config file or directory of \`*.toml\` (repeatable)]:path:_files' \
'*--config=[Config file or directory of \`*.toml\` (repeatable)]:path:_files' \
'*-e+[Print the description for a message id and exit]:id:_default' \
'*--explain=[Print the description for a message id and exit]:id:_default' \
'*-r+[A rpmlintrc file (repeatable)]:path:_files' \
'*--rpmlintrc=[A rpmlintrc file (repeatable)]:path:_files' \
'*-i+[Check installed RPM DB packages]:name:_default' \
'*--installed=[Check installed RPM DB packages]:name:_default' \
'-j+[Number of parallel worker threads for checking packages; 1 is sequential. Defaults to the machine'\''s parallelism]:n:_default' \
'--jobs=[Number of parallel worker threads for checking packages; 1 is sequential. Defaults to the machine'\''s parallelism]:n:_default' \
'--checks=[Run only these checks (debug)]:a,b,c:_default' \
'--format=[Report output format\: human-readable text (default) or machine-readable JSON (upstream rpmlint#1156). Overrides the \`OutputFormat\` config key]:format:(text json)' \
'-V[Print version and exit]' \
'--version[Print version and exit]' \
'-v[Inline explanations (and re-raise internal errors)]' \
'--verbose[Inline explanations (and re-raise internal errors)]' \
'--info[Inline explanations (and re-raise internal errors)]' \
'-p[Dump the merged configuration as TOML and exit]' \
'--print-config[Dump the merged configuration as TOML and exit]' \
'-t[Per-check timing report]' \
'--time-report[Per-check timing report]' \
'--ignore-unused-rpmlintrc[Suppress the \`unused-rpmlintrc-filter\` audit]' \
'(-P --permissive)-s[Treat all messages as errors]' \
'(-P --permissive)--strict[Treat all messages as errors]' \
'--errors-only[Skip warning-only checks entirely (upstream rpmlint#134). A static pre-scoring bound on each check'\''s declared max severity; disabled under --strict]' \
'(-s --strict)-P[Treat individual errors as non-fatal]' \
'(-s --strict)--permissive[Treat individual errors as non-fatal]' \
'-m[Called from the rpmlint-mini wrapper (SUSE-only)]' \
'--mini-mode[Called from the rpmlint-mini wrapper (SUSE-only)]' \
'-h[Print help]' \
'--help[Print help]' \
'*::files -- RPMs / specfiles / directories to check:_files' \
&& ret=0
}

(( $+functions[_rpmcrab_commands] )) ||
_rpmcrab_commands() {
    local commands; commands=()
    _describe -t commands 'rpmcrab commands' commands "$@"
}

if [ "$funcstack[1]" = "_rpmcrab" ]; then
    _rpmcrab "$@"
else
    compdef _rpmcrab rpmcrab
fi
