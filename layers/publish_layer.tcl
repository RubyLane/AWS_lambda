#!/usr/bin/env tclsh
# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

package require rl_json
package require parse_args
interp alias {} json {} ::rl_json::json
interp alias {} parse_args {} ::parse_args::parse_args

proc aws args { #<<<
	puts "Running:\n[list aws --region us-east-1 {*}$args]"
	exec aws --region us-east-1 {*}$args
	#exec aws --region eu-west-1 {*}$args
}

#>>>
proc changed {layer zip} { #<<<
	set layer_versions	[aws lambda list-layer-versions --layer-name $layer]
	if {[json get $layer_versions LayerVersions ?length] == 0} {return 1}
	json foreach ver [json extract $layer_versions LayerVersions] {
		if {![info exists highest] || [json get $ver Version] > $highest} {
			set highest	[json get $ver Version]
			set latest	$ver
		}
	}
	
	if {![info exists latest]} {
		error "Could not find latest version from [json pretty $layer_versions]"
	}
	
	set details	[aws lambda get-layer-version --layer-name $layer --version-number $highest]
	
	set size	[json get $details Content CodeSize]
	if {$size != [file size $zip]} {
		puts stderr "$layer: size $size != [file size $zip]"
		return 1
	}
	
	set sha256		[json get $details Content CodeSha256]
	set zipsha256	[binary encode base64 [binary decode hex [lindex [exec sha256sum --binary $zip] 0]]]
	
	puts stderr "$layer, sha256: ($sha256), zipsha256: ($zipsha256)"
	expr {$sha256 ne $zipsha256}
}

#>>>
proc refresh_layer args { #<<<
	parse_args $args {
		-name		{-required}
		-zip		{-required}
		-desc		{-required}
		-license	{}
		-allow		{}
	}

	set extra {}
	if {[info exists license]} {
		lappend extra --license-info $license
	}

	if {![changed $name $zip]} {
		puts "$name: Unchanged"
		return
	}

	set res [aws lambda publish-layer-version \
		--layer-name $name \
		--description $desc \
		--zip-file fileb://$zip \
		{*}$extra]

	set layer_version_arn	[json get $res LayerVersionArn]

	if {[info exists allow]} {
		aws lambda add-layer-version-permission \
			--layer-name		$name \
			--version-number	[json get $res Version] \
			--statement-id		publish \
			--action			lambda:GetLayerVersion \
			--principal			$allow
	}

	set layer_version_arn
}

#>>>

switch -- [lindex $argv 0] {
	Tcl869 { #<<<
		puts [refresh_layer \
			-name		[lindex $argv 0] \
			-zip		Tcl869.zip \
			-desc		"Bare bones Tcl 8.6.9 runtime, with rl_json, rl_http, Thread, sockopt and tcllib's uri" \
			-allow		* \
			-license	BSD \
		]
		#>>>
	}
	Pixel { #<<<
		puts [refresh_layer \
			-name		[lindex $argv 0] \
			-zip		Pixel.zip \
			-desc		"Pixel image handling packages (Pixel, Pixel_jpeg, Pixel_png, Pixel_webp, Pixel_imlib2)" \
			-allow		* \
			-license	BSD \
		]
		#>>>
	}
	AWS { #<<<
		puts [refresh_layer \
			-name		[lindex $argv 0] \
			-zip		AWS.zip \
			-desc		"AWS APIs (just S3 for now)" \
			-allow		arn:aws:iam::079127223483:root \
		]
		#>>>
	}
	default { #<<<
		puts stderr "Invalid layer \"[lindex $argv 0]\""
		exit 1
		#>>>
	}
}
