package cli

import (
	"fmt"
	"io"
)

func runCompletion(args []string, dependencies Dependencies) int {
	if len(args) != 1 {
		return writeError(dependencies.Stderr, ExitInput, "invalid_arguments", "usage: doctor completion <bash|zsh|fish|powershell>")
	}
	script, ok := completionScripts[args[0]]
	if !ok {
		return writeError(dependencies.Stderr, ExitInput, "invalid_shell", fmt.Sprintf("unsupported shell %q", args[0]))
	}
	_, _ = io.WriteString(dependencies.Stdout, script)
	return ExitSuccess
}

var completionScripts = map[string]string{
	"bash": `_doctor_complete(){ local cur="${COMP_WORDS[COMP_CWORD]}"; COMPREPLY=( $(compgen -W 'init self-check target test demo reproduce run compare baseline report completion version' -- "$cur") ); }; complete -F _doctor_complete doctor
`,
	"zsh": `#compdef doctor
_arguments '1:command:(init self-check target test demo reproduce run compare baseline report completion version)'
`,
	"fish": `complete -c doctor -f -a 'init self-check target test demo reproduce run compare baseline report completion version'
`,
	"powershell": `Register-ArgumentCompleter -Native -CommandName doctor -ScriptBlock { param($wordToComplete) 'init','self-check','target','test','demo','reproduce','run','compare','baseline','report','completion','version' | Where-Object { $_ -like "$wordToComplete*" } }
`,
}
