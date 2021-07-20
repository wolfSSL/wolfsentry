#!/usr/bin/awk -f
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
                val = gensub(/\\"/, "\"", "g", varassignment_a[2]);
                printf(" %s", val);
            }
            print "";
        }
    }
}
END {
    print "\n#endif /* WOLFSENTRY_OPTIONS_H */";
}
