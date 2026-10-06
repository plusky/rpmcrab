complete -c rpmcrab -s c -l config -d 'Config file or directory of `*.toml` (repeatable)' -r -F
complete -c rpmcrab -s e -l explain -d 'Print the description for a message id and exit' -r
complete -c rpmcrab -s r -l rpmlintrc -d 'A rpmlintrc file (repeatable)' -r -F
complete -c rpmcrab -s i -l installed -d 'Check installed RPM DB packages' -r
complete -c rpmcrab -s j -l jobs -d 'Number of parallel worker threads for checking packages; 1 is sequential. Defaults to the machine\'s parallelism' -r
complete -c rpmcrab -l checks -d 'Run only these checks (debug)' -r
complete -c rpmcrab -l format -d 'Report output format: human-readable text (default) or machine-readable JSON (upstream rpmlint#1156). Overrides the `OutputFormat` config key' -r -f -a "text\t''
json\t''"
complete -c rpmcrab -s V -l version -d 'Print version and exit'
complete -c rpmcrab -s v -l verbose -d 'Inline explanations (and re-raise internal errors)'
complete -c rpmcrab -s p -l print-config -d 'Dump the merged configuration as TOML and exit'
complete -c rpmcrab -s t -l time-report -d 'Per-check timing report'
complete -c rpmcrab -l ignore-unused-rpmlintrc -d 'Suppress the `unused-rpmlintrc-filter` audit'
complete -c rpmcrab -s s -l strict -d 'Treat all messages as errors'
complete -c rpmcrab -l errors-only -d 'Skip warning-only checks entirely (upstream rpmlint#134)'
complete -c rpmcrab -s P -l permissive -d 'Treat individual errors as non-fatal'
complete -c rpmcrab -s m -l mini-mode -d 'Called from the rpmlint-mini wrapper (SUSE-only)'
complete -c rpmcrab -s h -l help -d 'Print help'
