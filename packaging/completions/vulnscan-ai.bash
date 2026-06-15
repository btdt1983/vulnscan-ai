# bash completion for vulnscan-ai
_vulnscan_ai() {
    local cur prev cmds global i cmd opts
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    cmds="info scan fix report providers setup update-oval scheduled"
    global="--help --version --config --state-dir --provider --model"

    # value completions that depend on the previous word
    case "$prev" in
        --provider)
            COMPREPLY=($(compgen -W "claude openai gemini kimi local" -- "$cur")); return;;
        --min-severity|--fail-on)
            COMPREPLY=($(compgen -W "low moderate important critical" -- "$cur")); return;;
        --scanner)
            COMPREPLY=($(compgen -W "dnf oscap" -- "$cur")); return;;
        --config|--pdf|--json|--sarif|-o|--output)
            COMPREPLY=($(compgen -f -- "$cur")); return;;
        --state-dir)
            COMPREPLY=($(compgen -d -- "$cur")); return;;
        --model|--keep)
            return;;
    esac

    # locate the chosen subcommand, if any
    cmd=""
    for ((i=1; i<COMP_CWORD; i++)); do
        case "${COMP_WORDS[i]}" in
            info|scan|fix|report|providers|setup|update-oval|scheduled)
                cmd="${COMP_WORDS[i]}"; break;;
        esac
    done

    if [ -z "$cmd" ]; then
        COMPREPLY=($(compgen -W "$cmds $global" -- "$cur")); return
    fi

    case "$cmd" in
        scan)      opts="--scanner --min-severity --no-enrich --pdf --json --sarif";;
        fix)       opts="--scan --scanner --no-enrich --min-severity --yes --dry-run --pdf";;
        report)    opts="-o --output --min-severity";;
        scheduled) opts="--scanner --no-enrich --min-severity --plan --html --keep --fail-on";;
        *)         opts="";;
    esac
    COMPREPLY=($(compgen -W "$opts --help" -- "$cur"))
}
complete -F _vulnscan_ai vulnscan-ai
