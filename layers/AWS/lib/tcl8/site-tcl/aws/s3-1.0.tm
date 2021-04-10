package require aws
package require parse_args
package require urlencode

namespace eval s3 {
	namespace export *
	namespace ensemble create -prefixes no
	namespace path {
		::parse_args
	}

	variable bucket_regions	{}

	proc lookup_region {bucket args} { #<<<
		variable bucket_regions

		parse_args $args {
			update	{}
		}

		if {[info exists update]} {
			dict set bucket_regions $bucket $update
			return
		}

		if {[dict exists $bucket_regions $bucket]} {
			dict get $bucket_regions $bucket
		} else {
			return us-east-1
		}
	}

	#>>>
	proc log {lvl msg args} { tailcall aws log $lvl $msg {*}$args }
	proc req {method bucket path args} { #<<<
		parse_args $args {
			-region				{-default ""}
			-scheme				{-default http}
			-headers			{-default {}}
			-params				{-default {}}
			-content_type		{-default {}}
			-body				{-default {}}
			-response_headers	{-alias}
			-version			{-enum {4 2} -default 4 -# {AWS signature version}}
		}

		if {"x-amz-content-sha256" ni [lmap {k v} $headers {set k}]} {
			# TODO: consider caching the sha256 of the empty body
			lappend headers x-amz-content-sha256	[aws hash AWS4-HMAC-SHA256 $body]
		}

		if {$region eq ""} {
			set region	[s3 lookup_region $bucket]
		}

		try {
			aws req $method s3 $bucket/$path \
				-region				$region \
				-scheme				$scheme \
				-headers			$headers \
				-params				$params \
				-content_type		$content_type \
				-body				$body \
				-response_headers	response_headers \
				-version			$version \
				-sig_service		s3 \
				-xml_ns				http://s3.amazonaws.com/doc/2006-03-01/
		} trap {AWS AuthorizationHeaderMalformed} {errmsg options} - trap {AWS PermanentRedirect} {errmsg options} {
			set details	[lindex [dict get $options -errorcode] 4]
			if {[dict exists $details Region]} {
				set newregion	[dict get $details Region]
			} elseif {[dict exists $details Endpoint]} {
				if {![regexp {s3(?:-|\.)([^.]+)\.amazonaws\.com$} [dict get $details Endpoint] - newregion]} {
					error "Can't extract redirected region from \"[dict get $details Endpoint]\""
				}
			} else {
				return -options $options $errmsg
			}
			log notice "redirecting $bucket to new region: ($newregion)"
			s3 lookup_region $bucket $newregion

			tailcall aws req $method s3 $bucket/$path \
				-region				$newregion \
				-scheme				$scheme \
				-headers			$headers \
				-params				$params \
				-content_type		$content_type \
				-body				$body \
				-response_headers	response_headers \
				-version			$version \
				-sig_service		s3 \
				-xml_ns				http://s3.amazonaws.com/doc/2006-03-01/
		}
	}

	#>>>
	proc upload args { #<<<
		parse_args::parse_args $args {
			-region			{-default ""}
			-bucket			{-required}
			-path			{-required}
			-data			{-required}
			-content_type	{}
			-max_age		{-default 31536000}
			-acl			{-default public-read}
			-response_headers	{-alias}
		}

		if {![info exists content_type]} {
			package require Pixel 3.4.3
			try {
				set content_type	[pixel::image_mimetype $data]
			} trap {PIXEL CORE UNKNOWN_FILETYPE} {errmsg options} {
				set content_type	application/octet-stream
			}
		}

		switch -glob -- $content_type {
			text/* -
			application/json -
			application/javascript {
				set data	[encoding convertto utf-8 $data]
			}
		}

		s3 req PUT $bucket $path -region $region -content_type $content_type -body $data -headers [list \
			Cache-Control			max-age=$max_age \
			x-amz-acl				$acl \
		] -response_headers response_headers
	}

	#>>>
	proc copy args { #<<<
		parse_args::parse_args $args {
			-bucket				{-required}
			-path				{-required}
			-region				{-default ""}
			-source_bucket		{-# {Defaults to -bucket}}
			-source				{-required}
			-max_age			{-default 31536000}
			-acl				{-default public-read}
			-response_headers	{-alias}
		}

		if {![info exists source_bucket]} {
			set source_bucket	$bucket
		}

		if {![s3 exists -bucket $source_bucket -response_headers resp $source]} {
			throw [list S3 NOT_FOUND $bucket $source] "$source doesn't exist in $bucket"
		} else {
			set content_type	[lindex [dict get $resp content-type] 0]
		}

		# TODO deal with error responses in http code 200 returns (thanks Amazon)
		set xml	[s3 req PUT $bucket $path -region $region -content_type $content_type -headers [list \
			Cache-Control		max-age=$max_age \
			x-amz-acl			$acl \
			x-amz-copy-source	$source_bucket/[string trimleft $source /] \
		] -response_headers response_headers]

		dom parse $xml doc
		try {
			$doc selectNodesNamespaces {s3 http://s3.amazonaws.com/doc/2006-03-01/}
			set LastModified	[$doc selectNodes {string(s3:CopyObjectResult/s3:LastModified)}]
			set ETag			[$doc selectNodes {string(s3:CopyObjectResult/s3:ETag)}]
			json template {
				{
					"LastModified":	"~S:LastModified",
					"ETag":			"~S:ETag"
				}
			}
		} finally {
			$doc delete
		}
	}

	#>>>
	proc delete args { #<<<
		parse_args::parse_args $args {
			-region			{-default ""}
			-bucket			{-required}
			-path			{-required}
		}

		s3 req DELETE $bucket $path -region $region
	}

	#>>>
	proc ls args { #<<<
		parse_args::parse_args $args {
			-region				{-default ""}
			-prefix				{}
			-bucket				{-required}
			-delimiter			{}
			-max_keys			{-# {Defaults to 1000}}
			-continuation_token	{-default {}}
			-fetch_owner		{-boolean}
			-start_after		{}
			-encoding_type		{-enum url -# {If set to "url", responses are urlencoded (to permit C0 characters)}}
		}

		set params	{list-type 2}

		if {[info exists prefix]} {
			lappend params prefix $prefix
		}

		if {[info exists max_keys]} {
			lappend params max-keys $max_keys
		}

		if {$continuation_token ne ""} {
			lappend params continuation-token $continuation_token
		}

		if {$fetch_owner} {
			lappend params fetch-owner true
		}

		if {[info exists start_after]} {
			lappend params start-after $start_after
		}

		if {[info exists encoding_type]} {
			lappend params encoding-type $encoding_type
		}

		if {[info exists delimiter]} {
			lappend params delimiter $delimiter
		}

		set resp	[s3 req GET $bucket "" -region $region -params $params]
		dom parse $resp doc
		try {
			$doc selectNodesNamespaces {a http://s3.amazonaws.com/doc/2006-03-01/}
			$doc documentElement root
			set truncated	[$root selectNodes {boolean(string(a:IsTruncated)='true')}]
			if {$truncated} {
				set next_continuation_token	[$root selectNodes {string(a:NextContinuationToken)}]
			}

			set res [json template {
				{
					"truncated":				"~B:truncated",
					"next_continuation_token":	"~S:next_continuation_token",
					"results":					[]
				}
			}]

			if {[info exists delimiter]} {
				json set res commonprefixes {[]}
			}

			foreach node [$root selectNodes {a:Contents}] {
				set key				[$node selectNodes {string(a:Key)}]
				set mtime			[$node selectNodes {string(a:LastModified)}]
				set etag			[$node selectNodes {string(a:ETag)}]
				set size			[$node selectNodes {string(a:Size)}]
				set storageclass	[$node selectNodes {string(a:StorageClass)}]
				set entry [json template {
					{
						"key":			"~S:key",
						"mtime":		"~S:mtime",
						"etag":			"~S:etag",
						"size":			"~N:size",
						"storageclass":	"~S:storageclass"
					}
				}]
				if {$fetch_owner} {
					set id			[$node selectNodes {string(a:Owner/a:ID)}]
					set displayname	[$node selectNodes {string(a:Owner/a:DisplayName)}]
					json set entry owner [json template {
						{
							"id":			"~S:id",
							"displayname":	"~S:displayname"
						}
					}]
				}
				json set res results end+1 $entry
			}
			foreach node [$root selectNodes {a:CommonPrefixes}] {
				set commonprefix	[$node selectNodes {string(a:Prefix)}]
				json set res commonprefixes end+1 [json new string $commonprefix]
			}
			#log notice [$doc asXML -indent 4]
		} finally {
			$doc delete
		}

		set res
	}

	#>>>
	proc exists args { #<<<
		parse_args::parse_args $args {
			-region				{-default ""}
			-bucket				{-required}
			-response_headers	{-alias}
			path				{-required}
		}

		try {
			s3 req HEAD $bucket $path -region $region -response_headers response_headers
		} on ok {} {
			return 1
		} trap {AWS 404} {} - trap {AWS 403} {} {
			return 0
		}
	}

	#>>>
	proc get args { # For public files, use the cdn (much faster, on the order of 5 to 20 times faster) <<<
		parse_args::parse_args $args {
			-bucket				{-required}
			-response_headers	{-alias}
			-region				{-default ""}
			path				{-required}
		}

		s3 req GET $bucket $path -region $region -response_headers response_headers
	}

	#>>>
	proc signedurl args { # Return a presigned url to allow time-limited access to private objects <<<
		parse_args::parse_args $args {
			-aws_id		{-required}
			-aws_key	{-required}
			-expires	{-default 15 -# {Time in seconds url is valid for}}
			-bucket		{-required}
			path		{-required}
		}

		set path			[string trimleft $path /]
		set baseurl			https://$bucket.s3.amazonaws.com/$path
		set expire_date		[clock add [clock seconds] $expires seconds]

		string cat $baseurl [urlencode encode_query \
			Expires			$expire_date \
			Signature		[aws sign $aws_key "GET\n\n\n$expire_date\n/[urlencode rfc_urlencode -part path -- $bucket]/$path"] \
			AWSAccessKeyId	$aws_id \
		]
	}

	#>>>
}

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
