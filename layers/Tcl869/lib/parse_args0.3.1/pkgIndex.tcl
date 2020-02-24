#
# Tcl package index file
#
# The line is split across two lines not just for readability but also
# because a bug in the nmakehlp program used by Windows nmake build system
# causes incorrect substitution when doing multiple replaces of a single
# pattern on one line.
package ifneeded parse_args 0.3.1 \
    [list load [file join $dir libparse_args0.3.1.so] parse_args]
