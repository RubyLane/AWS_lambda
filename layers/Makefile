all: strip rpath updatelayers

updatelayers:
	./updatelayers.tcl

strip:
	strip Tcl869/bin/tclsh8.6
	find . -name "*.so" -exec strip {} \;

rpath:
	# patchelf would also work here, and in more situations (chrpath can only remove or replace an rpath with the same or shorter length)
	chrpath --replace /opt/lib Tcl869/bin/tclsh8.6 2>&1 >/dev/null
	find . -name "*.so" -exec chrpath --replace /opt/lib {} \; 2>&1 >/dev/null

publish-Tcl869: all
	./publish_layer.tcl Tcl869
		    
publish-AWS: all
	./publish_layer.tcl AWS
		    
publish-Pixel: all
	./publish_layer.tcl Pixel
		    
publish: all publish-Tcl869 publish-AWS publish-Pixel


clean:
	-rm *.zip
