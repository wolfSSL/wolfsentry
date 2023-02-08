#!/usr/bin/awk -f

# build_wolfsentry_options_h.awk
#
# Copyright (C) 2021-2023 wolfSSL Inc.
#
# This file is part of wolfSentry.
#
# wolfSentry is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSentry is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

BEGIN {
    print "#ifndef WOLFSENTRY_OPTIONS_H";
    print "#define WOLFSENTRY_OPTIONS_H";
}
{
    for (i=1; i<=NF; ++i) {
        if ($i ~ /^-D/) {
            print "";
            varassignment = substr($i,3);
            split(varassignment, varassignment_a, /[ =]+/);
            printf("#undef %s\n#define %s",varassignment_a[1],varassignment_a[1]);
            if (varassignment_a[2]) {
                val = varassignment_a[2];
                gsub(/\\"/, "\"", val);
                printf(" %s", val);
            }
            print "";
        } else if ($i ~ /^-U/) {
            print "";
            print "#undef " substr($i,3);
        }
    }
}
END {
    print "\n#endif /* WOLFSENTRY_OPTIONS_H */";
}
