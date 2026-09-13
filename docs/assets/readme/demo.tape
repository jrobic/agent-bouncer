# Shows bouncer's version, deny, ask, secret-read deny, allow, and wired doctor checks.
# Regenerate from the repository root with: vhs docs/assets/readme/demo.tape
# Setup uses an isolated temporary HOME and Claude config; only the demonstration is shown.

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Framerate 12
Set TypingSpeed 20ms

Hide
Type "export PS1='$ '"
Enter
Type `export HOME="$(mktemp -d /tmp/bouncer-demo.XXXXXX)"`
Enter
Type 'export CLAUDE_CONFIG_DIR="$HOME/claude"'
Enter
Type 'export PATH="$PWD/dist:$PATH"'
Enter
Type "bun run build>/dev/null"
Enter
Type "mkdir -p $CLAUDE_CONFIG_DIR"
Enter
Type `bun -e 'const p=process.env.CLAUDE_CONFIG_DIR+"/settings.json",b=process.cwd()+"/dist/bouncer",c=b+" run",hooks={PreToolUse:[{matcher:"Bash|Read|Edit|MultiEdit|Write|NotebookEdit|Grep|Glob|mcp__.*",hooks:[{type:"command",command:c}]}],UserPromptSubmit:[{hooks:[{type:"command",command:c}]}],SessionStart:[{hooks:[{type:"command",command:c}]}]};await Bun.write(p,JSON.stringify({hooks}));const canary=Bun.spawn({cmd:[b,"doctor","--settings",p,"--print-canary"],stdout:"pipe",stderr:"inherit"}),entry=JSON.parse(await new Response(canary.stdout).text());if(await canary.exited)throw new Error("canary generation failed");hooks.PreToolUse.push(entry);await Bun.write(p,JSON.stringify({hooks}))'`
Enter
Type "clear"
Enter
Show

Type "bouncer --version"
Enter
Sleep 1.5s

Type `bouncer check "rm -rf /"`
Enter
Sleep 1.5s

Type `bouncer check "git push --force origin main"`
Enter
Sleep 1.5s

Type `bouncer check "cat ~/.ssh/id_ed25519"`
Enter
Sleep 1.5s

Type `bouncer check "ls -la"`
Enter
Sleep 1.5s

Type "bouncer doctor"
Enter
Sleep 1.5s
Hide
Type `rm -rf "${HOME:?}"`
Enter
Show

Output "docs/assets/readme/demo.gif"
