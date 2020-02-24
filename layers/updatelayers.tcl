#!/usr/bin/env tclsh
# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

proc in_dir {dir script} {
	set old	[pwd]
	try {
		cd $dir
		uplevel 1 $script
	} finally {
		cd $old
	}
}

foreach d [glob -nocomplain -type d [file join $here *]] {
	in_dir $d {
		exec zip -FSr ../[file tail $d].zip .
	}
}
