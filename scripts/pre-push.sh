#!/bin/sh

if [ "$TMPDIR" = "" ]; then
    WORKDIR=/tmp/wolfsentry_for_push_hook.$$
else
    WORKDIR="${TMPDIR}/wolfsentry_for_push_hook.$$"
fi

trap "rm -rf $WORKDIR" EXIT

remote="$1"
url="$2"

REPO_ROOT="$(git rev-parse --show-toplevel)" || exit $?

git clone -q --shared -n "$REPO_ROOT" "$WORKDIR" || exit $?
cd "$WORKDIR" || exit $?

while read local_ref local_oid remote_ref remote_oid
do
	git checkout -q "$local_oid" || exit $?
	echo "make --quiet -j check for ${local_ref} at ${local_oid} ..."
	make --quiet -j check || exit $?
done

exit 0
