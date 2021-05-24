#!/bin/sh

if [ "$TMPDIR" = "" ]; then
    WORKDIR=/tmp/wolfsentry_for_push_hook.$$
else
    WORKDIR="${TMPDIR}/wolfsentry_for_push_hook.$$"
fi

trap "rm -rf $WORKDIR" EXIT

remote="$1"
url="$2"

REPO_ROOT="$(git rev-parse --show-toplevel)" || exit 1

git clone -q --shared -n "$REPO_ROOT" "$WORKDIR" || exit 1
cd "$WORKDIR" || exit 1

while read local_ref local_oid remote_ref remote_oid
do
	git checkout -q "$local_oid" || exit 1
	echo "make -j check for ${local_ref} at ${local_oid} ..."
	make -j check || exit 1
done

exit 0
