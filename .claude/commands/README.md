# Claude Code slash commands

Custom commands live here as `.md` files. Each becomes available as `/command-name` in Claude Code.

To create:

```
.claude/commands/
├── extract-contract.md       # → /extract-contract (Phase 2)
├── synthesize-openapi.md     # → /synthesize-openapi (Phase 3)
├── scaffold-hacs.md          # → /scaffold-hacs (Phase 5)
├── validate.md               # → /validate (V-tier)
└── new-fixture.md            # → /new-fixture (add to corpus)
```

See `SPECIFICATION.md` §2 for the pipeline phases each command should drive.

Format reference: https://docs.claude.com/en/docs/claude-code/slash-commands
