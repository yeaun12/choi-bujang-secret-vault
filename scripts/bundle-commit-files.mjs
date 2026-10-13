// Determine the actual changed files of a checkpoint, including merge commits.
// For merges, compare to first parent: Git's default diff-tree produces no
// file list for a merge without an explicit parent.
export function changedFilesForCommit(git, commit) {
  const lineage = git('rev-list', '--parents', '-n', '1', commit)
    .split(/\s+/u).filter(Boolean);
  if (lineage[0] !== commit) throw new Error('stage10_invalid_commit_lineage');
  const listing = lineage.length > 1
    ? git('diff', '--name-only', '--no-renames', lineage[1], commit)
    : git('diff-tree', '--root', '--no-commit-id', '--name-only', '--no-renames',
      '-r', commit);
  return listing.split(/\r?\n/u).filter(Boolean).sort();
}
