---
name: sendit
description: Ship the current work: branch, version bump, checks, commit, PR, squash-merge, wait for CI, deploy the image to Unraid.
disable-model-invocation: true
argument-hint: "[what the change is, for the commit and PR title]"
---

Ship the work in this repo all the way to the live site. Typing `/sendit` is the user's go-ahead for every step below, merging the PR included (CLAUDE.md's "the user merges" is waived for this run).

What the change is: $ARGUMENTS (when empty, take it from the diff and this conversation).

## Environment

- Put `/opt/homebrew/bin` (gh) and `~/.nvm/versions/node/v24.18.0/bin` (node, npm) on `PATH`; neither is on it by default.
- Run every network step (push, `gh`, the deploy) with the sandbox off.
- Push with gh's login: `git -c credential.helper= -c 'credential.helper=!gh auth git-credential' push -u origin <branch>`. The keychain helper hangs.

## Steps

1. **Branch.** On `main` with changes: create a kebab-case branch named for the change. On another branch: stay on it. Done when you are on a branch that is not `main` and `git status` / `git log origin/main..` show something to ship; if nothing, stop and say so.
2. **Version.** Bump `version` in `package.json` from `origin/main`'s: minor for a feature, patch for a fix. Then `npm install --package-lock-only`. Skip when this branch already bumped it. Done when `package.json` is exactly one step above `origin/main`'s.
3. **Check.** `npm run check`. Done when typecheck, tests and build all pass. A failure: fix it if it is part of this change, otherwise stop and report it.
4. **Commit.** Stage everything, then read the staged file list: secrets (`unraid/*.txt`, `.env`, keys) stay out. Message `vX.Y.Z: <what changed>`, ending with the attribution line from the system reminder.
5. **PR.** Push, then `gh pr create --base main` titled like the commit (a PR already open for this branch: use that one, retitled to the new version). Body for a reviewer: why, what changed, how it was tested, ending with the Claude Code line. Done when you have the PR URL.
6. **Merge.** `gh pr merge <n> --squash --delete-branch`. Done when `gh pr view <n> --json state` says `MERGED`.
7. **CI.** Find the "CI and Docker" run for the merge commit (`gh pr view <n> --json mergeCommit`, then `gh run list --commit <sha>`; it can take a few seconds to appear), then `gh run watch <id> --exit-status`. Done when check, release and docker all succeed. A failure: stop, show the failing job's log, and leave the deploy for later.
8. **Deploy.** `node scripts/deploy-unraid.ts`. Done when it prints `Done: <the new version> runs.` Anything else: report its output and stop.
9. **Tidy.** `git checkout main` and pull, so the local copy matches what runs.

## Report

One short message: the PR link, the version, CI's result, and the deploy's before and after lines.
