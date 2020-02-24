#
# Tcl package index file
#
package ifneeded Pixel 3.5 [list apply {
	dir {
		load [file join $dir libPixel3.5.so] Pixel
		source [file join $dir utils.tcl]
	}
} $dir]
