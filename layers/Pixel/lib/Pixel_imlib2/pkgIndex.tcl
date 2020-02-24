#
# Tcl package index file
#
package ifneeded Pixel_imlib2 1.2.0 [list apply {
    dir {
		load [file join $dir libPixel_imlib21.2.0.so] Pixel_imlib2
		source [file join $dir utils.tcl]
	}
} $dir]
