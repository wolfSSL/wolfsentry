#!/bin/sh

# shellcheck disable=SC2034 # allow unused variables

if [ "$TMPDIR" = "" ]; then
    WORKDIR=/tmp/wolfsentry_for_push_hook.$$
else
    WORKDIR="${TMPDIR}/wolfsentry_for_push_hook.$$"
fi

trap 'rm -rf "$WORKDIR"' EXIT

remote="$1"
url="$2"

REPO_ROOT="$(git rev-parse --show-toplevel)" || exit $?

git clone -q --shared -n "$REPO_ROOT" "$WORKDIR" || exit $?
cd "$WORKDIR" || exit $?

if [ "$(uname -s)" = 'Linux' ]; then
    have_linux=y
else
    have_linux=n
fi

while read -r local_ref local_oid remote_ref remote_oid
do
    if [ "$local_ref" = "(delete)" ]; then
	continue
    fi
    git checkout -q "$local_oid" || exit $?
    if [ "$have_linux" = 'y' ]; then
	echo "make --quiet -j check for ${local_ref} at ${local_oid} ..."
	make --quiet -j check || exit $?
    else
	echo "make --quiet -j test for ${local_ref} at ${local_oid} ..."
	make --quiet -j test || exit $?
    fi
done

exit 0
