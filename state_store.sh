#!/usr/bin/env bash
set -euo pipefail
state_ref=refs/heads/encrypted-state

case "${1:-}" in
  load)
    case "${MODE:-check}" in check|test|initialize) ;; *) exit 2 ;; esac
    set +e
    remote_ref=$(git ls-remote --exit-code --heads origin "$state_ref")
    result=$?
    set -e
    if [ "$result" = 0 ]; then
      if [ "${MODE:-check}" = initialize ]; then
        echo 'State already exists; initialization refused.'
        exit 2
      fi
      git fetch --quiet origin "$state_ref"
      git rev-parse FETCH_HEAD > "$(git rev-parse --git-path atlas-state-parent)"
      git worktree add --quiet --detach state-work FETCH_HEAD
      if [ "$(git -C state-work ls-files)" != state.enc ]; then
        echo 'Unexpected state files; refusing to read or publish them.'
        exit 2
      fi
    elif [ "$result" = 2 ] && [ "${MODE:-check}" = initialize ]; then
      git worktree add --quiet --detach state-work HEAD
      git -C state-work switch --quiet --orphan encrypted-state
      printf '' > "$(git rev-parse --git-path atlas-state-parent)"
    else
      echo 'Encrypted state unavailable; refusing to reset history.'
      exit 2
    fi
    ;;
  save)
    test -s state-work/state.enc
    git -C state-work add -f state.enc
    if [ "$(git -C state-work ls-files)" != state.enc ]; then
      echo 'Only state.enc may be published.'
      exit 2
    fi
    if git -C state-work diff --cached --quiet; then exit 0; fi
    git -C state-work config user.name 'Atlas uptime bot'
    git -C state-work config user.email 'atlas-uptime@users.noreply.github.com'
    # Replace only this new repository's ciphertext snapshot branch. No old
    # repository refs are fetched or changed. Lease rejects concurrent writers.
    previous=$(cat "$(git rev-parse --git-path atlas-state-parent)")
    tree=$(git -C state-work write-tree)
    commit=$(printf '%s\n' 'Refresh encrypted monitoring state' | git -C state-work commit-tree "$tree")
    git push --quiet --force-with-lease="$state_ref:$previous" origin "$commit:$state_ref"
    ;;
  *) exit 2 ;;
esac
