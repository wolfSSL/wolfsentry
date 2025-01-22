#!/usr/bin/awk -f

# update_copyright_boilerplate.awk
#
# Copyright (C) 2023-2025 wolfSSL Inc.
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
    FS = "";
    boilerplate = "Copyright (C) 2021-" strftime("%Y", systime(), 1) " wolfSSL Inc.  All rights reserved.\n\nThis file is part of wolfSentry.\n\nContact licensing@wolfssl.com with any questions or comments.\n\nhttps://www.wolfssl.com";
}
BEGINFILE {
    seen_copyright = 0;
    seen_copyright_end = 0;
    tmpfile = FILENAME "-tmp";
}
{
    if (seen_copyright && seen_copyright_end) {
        print >>tmpfile;
        next;
    }
    if ((seen_copyright == 1) && ($0 ~ "\\*/$")) {
        seen_copyright_end = 1;
        next;
    }
    if ((seen_copyright == 2) && ($0 !~ "^#")) {
        seen_copyright_end = 1;
        print >>tmpfile;
        next;
    }
    if (seen_copyright) {
        next;
    }
}
/^\/\/ SPDX-License-Identifier: GPL-2.0-or-later/ {
    seen_copyright = 1;
    seen_copyright_end = 1;
    print "/* " gensub("\n","\n * ","g",boilerplate) "\n */" >>tmpfile;
    next;
}
/^ \* [cC]opyright.* [wW]olf[sS][sS][lL]/ {
    seen_copyright = 1;
    print " * " gensub("\n","\n * ","g",boilerplate) "\n */" >>tmpfile;
    next;
}
/^# [cC]opyright.* [wW]olf[sS][sS][lL]/ {
    seen_copyright = 2;
    print "# " gensub("\n","\n# ","g",boilerplate) >>tmpfile;
    next;
}
{print >>tmpfile;}
ENDFILE {
    if (! seen_copyright) {
#       print "copyright boilerplate missing from " FILENAME;
        system("rm \"" tmpfile "\"");
    } else {
        if (seen_copyright && (! seen_copyright_end)) {
            print FILENAME " copyright notice end not found." >"/dev/stderr";
            exit(1);
        }
        exitstat = system("touch --reference=\"" FILENAME "\" \"" tmpfile "\"");
        if (exitstat != 0) {
            exit(exitstat);
        }
        exitstat = system("chmod --reference=\"" FILENAME "\" \"" tmpfile "\"");
        if (exitstat != 0) {
            exit(exitstat);
        }
        exitstat = system("mv \"" tmpfile "\" \"" FILENAME "\"");
        if (exitstat != 0) {
            exit(exitstat);
        }
    }
}
