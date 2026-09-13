# Drill: the merge check refuses a hands' branch without a record

13 September 2026, 12:14 UTC. Rows 8.3.5 and 8.3.3.

**What was done.** The operator, from his own shell with his own key, cloned
`abovebeyond-ai/verify-abovebeyond`, made a branch `elixir/drill-2026-09-13`, added one
file `verdicts/DRILL.md` with one sentence, pushed, and opened pull request 6 with a body
that carried no evidence footer. Nothing of the gateway's was involved; that is the case
the check exists for.

**What happened.** The workflow `evidence` ran on the pull request (the branch name starts
with `elixir/`, so the job was not skipped), installed `cmd/relying` at the pinned release,
read the pull request body, and stopped:

```
REFUSE the pull request carries no evidence footer
```

Job conclusion: failure, run 2026-09-13T12:14:32Z. GitHub's merge state: unstable.

**What it shows.** The check reads the body, not the branch name alone: a person who names
a branch like the hands' branches gets refused, which is the right way round. And a red
check is a mark, not a lock: on a repository without branch protection the merge button
still works. On the public repositories of the organisation, branch protection that
requires `evidence` is available and is the next step there; on the private repositories
under the personal account it is not, and the statement names that.

**Cleanup.** Pull request 6 closed unmerged, the branch deleted, by the operator.
