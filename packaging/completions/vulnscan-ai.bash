# bash completion for vulnscan-ai
_vulnscan_ai() {
    local cur prev cmds global i cmd opts
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmds="menu info scan fix rollback report providers setup update-oval scheduled dashboard news"
    global="--help --version --no-banner --config --state-dir --provider --model"

    # value completions that depend on the previous word
    case "$prev" in
        --provider)
            COMPREPLY=($(compgen -W "claude openai gemini kimi deepseek mistral local" -- "$cur")); return;;
        --min-severity|--fail-on)
            COMPREPLY=($(compgen -W "low moderate important critical" -- "$cur")); return;;
        --scanner)
            COMPREPLY=($(compgen -W "dnf oscap ssh systemd ports webroot container" -- "$cur")); return;;
        --compliance)
            COMPREPLY=($(compgen -W "cis-l1 cis-l2 cis-ws-l1 cis-ws-l2 stig stig-gui pci-dss hipaa ospp cui anssi-minimal anssi-intermediary anssi-enhanced anssi-high e8" -- "$cur")); return;;
        --source)
            COMPREPLY=($(compgen -W "kev nvd distro" -- "$cur")); return;;
        --config|--pdf|--json|--sarif|--compliance-datastream|--export-script|--export-ansible|-o|--output)
            COMPREPLY=($(compgen -f -- "$cur")); return;;
        --state-dir)
            COMPREPLY=($(compgen -d -- "$cur")); return;;
        --model|--keep|--user|--port|--bind|--allow|--deny|--limit)
            return;;
    esac

    # locate the chosen subcommand, if any
    cmd=""
    for ((i=1; i<COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            menu|info|scan|fix|rollback|report|providers|setup|update-oval|scheduled|dashboard|news)
                cmd="${COMP_WORDS[i]}"; break;;
        esac
    done

    if [ -z "$cmd" ]; then
        COMPREPLY=($(compgen -W "$cmds $global" -- "$cur")); return
    fi

    case "$cmd" in
        scan)      opts="--scanner --all --min-severity --no-enrich --pdf --json --sarif --ignore --compliance --list-profiles --compliance-datastream";;
        fix)       opts="--scan --scanner --all --no-enrich --min-severity --yes --dry-run --pdf --export-script --export-ansible --ignore";;
        rollback)  opts="--list";;
        report)    opts="-o --output --min-severity";;
        scheduled) opts="--scanner --all --no-enrich --min-severity --plan --html --keep --fail-on";;
        dashboard) opts="--set-password --user --allow --deny --list --port --bind";;
        news)      opts="--source --refresh --limit";;
        *)         opts="";;
    esac
    COMPREPLY=($(compgen -W "$opts --help" -- "$cur"))
}
complete -F _vulnscan_ai vulnscan-ai
