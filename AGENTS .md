# Project Memory & Skill Usage Rules

**Every rule in this file is mandatory, not optional guidance.** Follow all sections below strictly, for every task, regardless of how the request is phrased or how small it seems. Scope, secrets, coding behavior, memory, syntax, folder organization, task planning, skills, hygiene, and verification all apply together, not selectively. If a rule seems to conflict with what's being asked, say so explicitly instead of silently skipping the rule.

## Writing Style

**Important: never use emojis in code** (code comments, commit messages, console/log output, variable or file names). Emojis in notes or chat replies are fine.

**Important: never use em-dashes, anywhere.** This applies everywhere: chat replies, notes in `notes/`, code comments, commit messages, and everything else you write. Use plain punctuation instead, such as a period, a comma, a colon, or two separate sentences. This rule applies at all times, not just when explicitly reminded.

## Codebase Scope

This project's language/stack may vary or change over time. Apply these rules based on what you actually find, not a fixed list.

**General rule:** ignore any folder that is auto-generated, a dependency cache, or a build output, regardless of language. You can usually recognize these by:
- They're listed in `.gitignore`
- They contain a huge number of files you didn't write (thousands of small files, minified code, compiled binaries)
- They can be regenerated from a manifest file (`package.json`, `requirements.txt`, `go.mod`, `Cargo.toml`, `pom.xml`, `*.csproj`, `Gemfile`, `composer.json`, etc.). The manifest is what matters, not the generated contents.

**Common examples across ecosystems** (not exhaustive, apply the general rule above to anything not listed here):
- **JavaScript/TypeScript/Node:** `node_modules/`, `.next/`, `dist/`, `build/`, `out/`, `.turbo/`, `.cache/`
- **Python:** `venv/`, `.venv/`, `__pycache__/`, `*.egg-info/`, `.pytest_cache/`, `.mypy_cache/`
- **Rust:** `target/`
- **Go:** `vendor/`
- **Java/Kotlin:** `target/`, `.gradle/`, `build/`
- **.NET/C#:** `bin/`, `obj/`
- **Ruby:** `vendor/bundle/`, `.bundle/`
- **PHP:** `vendor/`
- **General:** `.git/`, `.svn/`, any `logs/` or `tmp/` folder full of runtime output

**Lockfiles** (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`, `Gemfile.lock`, etc.): their *existence* matters (confirms what's installed), but do not read their full contents; they add no useful context and burn tokens.

Only look inside any of the above if the task explicitly requires debugging a build artifact, dependency version conflict, or similar. Otherwise treat them as opaque and skip them entirely.

### Secrets and sensitive files

- **Never read the contents of `.env`, `.env.local`, or any other environment/secrets file into a note, a chat response, or anywhere else**, unless the user explicitly asks you to work with one directly. `.env.*.example` files (with placeholder values, no real secrets) are safe to read normally.
- **Never write real API keys, tokens, passwords, connection strings, or other credentials into `notes/`**, even if you saw them while working. If a note needs to reference that a credential exists, describe it (e.g. "requires a Stripe secret key, stored in `.env.local`") without including the actual value.
- If you notice a real secret committed somewhere it shouldn't be (e.g. hardcoded in a source file instead of an env var), flag it to the user. Don't just quietly fix or ignore it.
- **Check `.gitignore` for `notes/` and Obsidian's local junk files** (`.obsidian/workspace.json`, `.obsidian/workspace-mobile.json`, `.obsidian/cache`). If `notes/` is missing from `.gitignore`, tell the user and suggest adding it. Do not add it yourself without asking, since some users intentionally track notes in git.

## Coding Behavior Guidelines

These reduce common LLM coding mistakes: overcomplicating simple tasks, silently guessing at ambiguous requests, touching more code than necessary, and claiming success without proof. Adapted from Andrej Karpathy's observations on LLM coding pitfalls. They bias toward caution over speed. For genuinely trivial tasks, use judgment rather than applying every rule rigidly.

**1. Think before coding. Don't assume. Don't hide confusion. Surface tradeoffs.**
- State assumptions explicitly before implementing. If genuinely uncertain, ask rather than guess.
- If multiple reasonable interpretations of a request exist, present them. Don't silently pick one.
- If a simpler approach exists than what was asked for, say so; push back when warranted instead of just complying.
- If something is unclear, stop and name what's confusing rather than working around the ambiguity silently.

**2. Simplicity first. Minimum code that solves the problem, nothing speculative.**
- No features beyond what was actually asked for.
- No abstractions for code that's only used once.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for scenarios that can't actually occur.
- If you write 200 lines and it could be 50, rewrite it. If a solution could reasonably be a quarter of its current size, simplify it before considering the task done. Ask: would a senior engineer call this overcomplicated?

**3. Surgical changes. Touch only what you must, clean up only your own mess.**
- Don't "improve" adjacent code, comments, or formatting that wasn't part of the request.
- Don't refactor things that aren't broken just because you noticed them.
- Match the existing code style even if you'd personally do it differently.
- If you notice unrelated dead code or issues, mention them to the user. Don't delete or fix them unprompted.
- Do remove imports/variables/functions that your own change made unused, but leave pre-existing dead code alone unless asked.
- Test for this: every changed line should trace directly back to the actual request.

**4. Goal-driven execution. Define success criteria, then loop until verified.**
- Turn vague tasks into verifiable goals before starting: "add validation" becomes "write tests for invalid inputs, then make them pass"; "fix the bug" becomes "write a test that reproduces it, then make it pass"; "refactor X" becomes "ensure tests pass before and after."
- For multi-step tasks, state a brief plan with a verification check per step, e.g.:
  ```
  1. [Step] -> verify: [check]
  2. [Step] -> verify: [check]
  3. [Step] -> verify: [check]
  ```
- Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification. This connects directly to the Verification rules below. A strong success criterion is what makes "I verified this actually works" a true statement rather than an assumption.

## Persistent Memory (Obsidian Vault)

This project uses a folder named `notes/` as a persistent Obsidian vault. Treat it as your long-term memory for this project, not just a folder.

- **If `notes/` does not exist yet, create it** before doing anything else, along with a `notes/README.md` explaining it's the project's AI-maintained knowledge base.
- **Before doing anything based on the prompt or task, first check `notes/` for relevant context** (architecture notes, past decisions, known issues) covering that area. This applies to every task, not only code changes; if the topic has a note, read it before acting on the prompt at all. Base your response on what the notes say actually happened, not on what seems plausible. If no relevant note exists, proceed but say so explicitly rather than silently guessing.
- **After completing any non-trivial task** (a new feature, a bug fix, a refactor, an architecture or design decision, a dependency change, or anything that changes how part of the project works or is structured), update or create the relevant note in `notes/` reflecting what changed and why, not just what the code now does but the reasoning behind it.
- **Do not create a new note for purely cosmetic changes** (typo fixes, formatting, whitespace, renaming a variable with no behavior change). If you're unsure whether something counts as trivial or non-trivial, treat it as non-trivial. A redundant note is a much smaller cost than losing context.

### Obsidian syntax reference

**Strictly follow standard Obsidian-flavored markdown for everything in `notes/`, no exceptions and no substituting plain/generic markdown instead.** Use this syntax correctly both when writing new notes and when reading existing ones. Don't treat it as plain text in either direction.

- `[[Note Name]]`: a link to another note in `notes/`. When writing, use this to cross-reference related notes. When reading, treat it as a pointer and follow it if the linked note is relevant to the current task.
- `[[Note Name|Display Text]]`: links to `Note Name` but displays `Display Text`. The link target is what matters, not the display text.
- `![[Note Name]]`: embeds another note's content inline. When reading, treat it as if that note's content is included at that point.
- `> [!note]`, `> [!warning]`, `> [!danger]`, etc.: callouts. Use the type that matches the content's importance when writing; when reading, don't skim past warning/danger callouts as if they were regular text.
- YAML frontmatter (the `---` block at the top of a note): see the metadata rules under Long-Term Memory Hygiene below for what to include and how to interpret it.

### Folder organization inside notes/

- **Before creating a new note, check if a folder already exists for that topic.** If yes, put the note there instead of creating a new folder or a duplicate at the root.
- **If no matching folder exists, create one** with a short, clear, lowercase, hyphenated name that describes the actual topic. `notes/architecture/`, `notes/bugs/`, `notes/api-design/` are examples of the *naming style* only, not a fixed or limited list. Create whatever folder name genuinely fits the subject (e.g. `notes/quiz/`, `notes/deployment/`, `notes/testing/`, or anything else). Do not put loose topical notes directly at the root of `notes/`. Every note should live inside a folder for its subject.
- **Before creating a new folder, double-check similarly-named folders don't already exist** (e.g. don't create `notes/architecture/` if `notes/codebase-overview/` already covers the same thing). Reuse the existing one instead.
- If you're unsure whether something fits an existing folder or needs a new one, prefer reusing the closest existing folder over creating a new one.
- **`notes/decisions/` is a defined convention, not just an example.** Use it specifically for architectural or design decisions and the reasoning behind them (e.g. "why we chose X over Y"). Keep it separate from `notes/architecture/`, which describes how the system currently works, not why past choices were made.

### Task planning notes

For any task worth planning ahead (a feature with multiple steps, anything you'd otherwise track mentally), create a task file rather than only a mental plan.

- **Location:** `notes/tasks/<short-task-name>.md`, one file per task, not one giant running todo list.
- **Frontmatter:** include `status: planned | in-progress | done` alongside the usual `created` / `last-updated` fields, plus `area:` listing what part of the project it touches (e.g. `area: [frontend]`, `area: [backend, database]`, using as many as genuinely apply; don't force a single label on a cross-cutting task). Update `status` as the task progresses. This is what lets you (or a future session) tell at a glance what's finished and what isn't. Use `area` to filter/search by category later without needing separate folders per area.
- **Content:** a checklist of concrete steps using `- [ ]` / `- [x]`, plus enough context that a fresh session could pick the task up without you re-explaining it.
- **When the task is finished, do NOT move or delete the file.** Set `status: done`, check off all steps, and add a `[[wikilink]]` to whatever permanent note the task produced (e.g. a note in `notes/quiz/` or `notes/architecture/`). Moving files manually breaks other notes' links pointing to it. Linking instead keeps history intact and connects the "how it was built" record to the "what it is now" record.
- **Before starting a new task, check `notes/tasks/` for anything already `planned` or `in-progress`** on the same topic, so you don't duplicate planning that already exists.

### When an existing note grows too large

- **Before adding to an existing note, check its rough size.** If it's already large (as a guideline: past ~200-300 lines, or clearly covering more than one distinct sub-topic), don't just keep appending. Split it instead.
- **To split a note:** turn it into a small folder of its own (e.g. `quiz.md` becomes `quiz/overview.md`, `quiz/scoring.md`, `quiz/answer-review.md`, matching the sub-topics already in the file), and leave a short summary note in the original location that links out to each split file via `[[wikilinks]]`.
- **When adding new content to a note that's still a reasonable size**, keep doing what already works well: add a clearly dated/named section (e.g. `## Answer review (added <date>)`) rather than rewriting the whole file. This preserves history and keeps diffs easy to follow.
- The goal is that no single note becomes so large that re-reading it wastes significant context or makes the topic hard to scan. Split by sub-topic, not by arbitrary size alone.

## Skill Usage

This project may have installed skills (SKILL.md files, typically under `.agents/skills/`, `.claude/skills/`, or `.opencode/skills/`).

- **Before starting a task, check if an installed skill matches it.** If one exists, use it rather than improvising the same capability from scratch.
- **Always check for and read a relevant skill before fixing, creating, modifying, auditing, reviewing, or doing anything else**, regardless of how the task is phrased. A matching skill takes priority over relying on general knowledge alone.
- If no skill exists for a recurring type of task you're doing often, mention to the user that creating one could help next time. Don't create skills unprompted.

## Long-Term Memory Hygiene

`notes/` will grow over many sessions. Follow these rules so it stays organized and trustworthy instead of turning into clutter.

**1. Maintain a single index note.**
Keep one file at `notes/index.md` that lists every top-level folder in `notes/`, each with a one-line description and a `[[wikilink]]` to it. Whenever you create a new top-level folder, add an entry for it in `notes/index.md` in the same task. Do not leave the index out of date. This file is the entry point for understanding the whole memory structure at a glance.

**2. Add metadata to every note you write.**
At the top of every note, include YAML frontmatter with at least:
```yaml
---
created: <date you created it>
last-updated: <date of most recent edit>
status: draft | verified
---
```
Update `last-updated` any time you revise a note, not only when creating it. This lets anyone later find notes that haven't been touched in a long time and may be outdated. Check `status: draft` vs `status: verified` before treating a note's content as settled fact. Prefer verified notes when they conflict with draft ones.

**Notes created before this rule existed may have no frontmatter at all.** Treat those as equivalent to `status: draft` (useful context, but not guaranteed current or reviewed) rather than ignoring them. When you next update one of these older notes for an unrelated reason, add proper frontmatter to it at the same time.

**3. Periodically review and clean up.**
Roughly every 10-15 sessions, or whenever the user asks you to, review `notes/` for duplicate or overlapping notes/folders and merge them. If you notice duplication while doing an unrelated task, flag it to the user rather than silently ignoring it.

**4. Never silently delete outdated information; mark it as historical instead.**
When something in `notes/` becomes outdated (e.g. an architecture decision that was later reversed), do not delete the note. Instead, add a callout at the top of the note explaining it's outdated and why, for example:
```markdown
> [!warning] Deprecated
> This approach was replaced on <date>. See [[new-note-name]] for the current approach.
```
This preserves the reasoning history so past decisions aren't lost, which matters most for anything in `notes/decisions/`.

**Exception: full deletion is allowed only when the user explicitly asks for it.** If the user says a note is fully obsolete and no longer useful even as history, you may delete it. Never delete a note on your own judgment, even if it looks clearly outdated.

## Verification Before Claiming Success

- **After making any code change, run the project's actual build/test/lint command** (check `package.json` scripts, a `Makefile`, or similar for the right one) **before telling the user the task is complete.**
- **If the build or tests fail, do not report success.** Either fix the failure and re-verify, or clearly tell the user it failed and what the error was. Never say something like "all checks passed" without having actually run and confirmed that.
- If there's no build/test command available for this project, say so explicitly rather than implying verification happened when it didn't.
- **At the end of every response where you changed code, explicitly state whether you updated `notes/` and which file**, e.g. "Updated notes/features/quiz-answers.md" or "No notes/ update needed (trivial change)." Never end a non-trivial task silently without this line. It's how the user can verify the memory rule actually ran, instead of trusting it happened invisibly.

## Notes for Claude Code specifically

If you are Claude Code and this file wasn't loaded automatically, read `@AGENTS.md` now. This file is the source of truth for project conventions and memory handling.
