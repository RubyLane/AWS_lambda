# AWS signature version 4: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
# All services support version 4, except SimpleDB which requires version 2

package require rl_http
package require urlencode
package require uri
package require parse_args
package require tdom
package require rl_json

namespace eval aws {
	namespace export *
	namespace ensemble create -prefixes no
	namespace path {
		::parse_args
		::rl_json
	}

	variable maxrate		50		;# Hz
	variable ratelimit		50
	variable last_slowdown	0

	# Helpers <<<
	proc readfile fn { #<<<
		set h	[open $fn r]
		try {read $h} finally {close $h}
	}

	#>>>
	# Helpers >>>

	# Ensure that $script is run no more often than $hz / sec
	proc ratelimit {hz script} { #<<<
		variable _ratelimit_previous_script
		set delay	[expr {entier(ceil(1000000.0/$hz))}]
		if {[info exists _ratelimit_previous_script] && [dict exists $_ratelimit_previous_script $script]} {
			set remaining	[expr {$delay - ([clock microseconds] - [dict get $_ratelimit_previous_script $script])}]
			if {$remaining > 0} {
				after [expr {$remaining / 1000}]
			}
		}
		dict set _ratelimit_previous_script $script	[clock microseconds]
		catch {uplevel 1 $script} res options
		dict incr options -level 1
		return -options $options $res
	}

	#>>>
	proc sign {K str} { #<<<
		package require hmac
		binary encode base64 [hmac::HMAC_SHA1 $K [encoding convertto utf-8 $str]]
	}

	#>>>
	proc log {lvl msg {template {}}} { #<<<
		if {$template ne ""} {
			set doc	[uplevel 1 [list json template $template]]
		} else {
			set doc {{}}
		}
		json set doc lvl [json new string $lvl]
		json set doc msg [json new string $msg]

		puts stderr $doc
	}

	#>>>
	proc amz-date s { clock format $s -format %Y%m%d -timezone :UTC }
	proc amz-datetime s { clock format $s -format %Y%m%dT%H%M%SZ -timezone :UTC }
	namespace eval hash { #<<<
		namespace export *
		namespace ensemble create -prefixes no

		proc AWS4-HMAC-SHA256 bytes { #<<<
			package require hmac
			binary encode hex [hmac::H sha256 $bytes]
		}

		#>>>
	}

	#>>>
	proc sigv2 args { #<<<
		global env

		parse_args::parse_args $args {
			-aws_id				{}
			-aws_key			{}
			-aws_token			{}
			-method				{-required}
			-service			{-required}
			-path				{-required}
			-scheme				{-default http}
			-headers			{-default {}}
			-params				{-default {}}
			-content_md5		{-default {}}
			-content_type		{-default {}}
			-body				{-default {}}
			-sig_service		{-default {}}

			-out_url			{-alias}
			-out_headers		{-alias}
			-out_sts			{-alias}
		}

		if {![info exists aws_id]} {
			if {[info exists env(AWS_ACCESS_KEY_ID)]} {
				set aws_id		$env(AWS_ACCESS_KEY_ID)
			} else {
				set aws_id		[json get [role_creds] AccessKeyId]
			}
		}
		if {![info exists aws_key]} {
			if {[info exists env(AWS_SECRET_ACCESS_KEY)]} {
				set aws_key		$env(AWS_SECRET_ACCESS_KEY)
			} else {
				set aws_key		[json get [role_creds] SecretAccessKey]
			}
		}
		if {![info exists aws_token]} {
			if {[info exists env(AWS_SESSION_TOKEN)]} {
				set aws_token	$env(AWS_SESSION_TOKEN)
			} else {
				set aws_token	[json get [role_creds] Token]
			}
		}

		#if {$sig_service eq ""} {set sig_service $service}
		set method			[string toupper $method]
		set date			[clock format [clock seconds] -format {%a, %d %b %Y %H:%M:%S +0000} -timezone GMT]
		set amz_headers		{}
		set camz_headers	""
		lappend headers Date $date
		if {[info exists aws_token]} {
			lappend headers x-amz-security-token $aws_token
		}
		foreach {k v} $headers {
			set k	[string tolower $k]
			if {![string match x-amz-* $k]} continue
			dict lappend amz_headers $k $v
		}
		foreach k [lsort [dict keys $amz_headers]] {
			# TODO: protect against "," in header values per RFC 2616, section 4.2
			append camz_headers "$k:[join [dict get $amz_headers $k] ,]\n"
		}

		# Produce urlv: a list of fully decoded path elements, and canonized_path: a fully-encoded and normalized path <<<
		set urlv	{}
		if {[string trim $path /] eq ""} {
			set canonized_path	/
		} else {
			set urlv	[lmap e [split [string trim $path /] /] {urlencode rfc_urldecode -- $e}]
			set canonized_path	/[join [lmap e $urlv {urlencode rfc_urlencode -part path -- $e}] /]
			if {[string index $path end] eq "/" && [string index $canonized_path end] ne "/"} {
				append canonized_path	/
			}
		}
		#>>>

		# Build resource <<<
		if {$sig_service ne ""} {
			set resource	/$sig_service$canonized_path
		} else {
			set resource	$canonized_path
		}
		set resource_params	{}
		foreach {k v} [lsort -index 0 -stride 2 $params] {
			if {$k in {acl lifecycle location logging notification partNumber policy requestPayment torrent uploadId uploads versionId versioning versions website
			  response-content-type response-content-language response-expires response-cache-control response-content-disposition response-content-encoding
			  delete
			}} continue

			# https://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#UsingTemporarySecurityCredentials says not to encode query string parameters in the resource
			if {$v eq ""} {
				lappend resource_params $k
			} else {
				lappend resource_params $k=$v
			}
		}
		if {[llength $resource_params] > 0} {
			append resource ?[join $resource_params &]
		}
		#>>>

		set out_url			$scheme://$service.amazonaws.com$canonized_path[urlencode encode_query $params]

		set string_to_sign	$method\n$content_md5\n$content_type\n$date\n$camz_headers$resource
		set auth	"AWS $aws_id:[sign $aws_key $string_to_sign]"

		#dict set headers Authorization	$auth	;# headers is not a dict - can contain multiple instances of a key!
		lappend headers Authorization $auth

		if {$content_md5 ne ""} {
			lappend headers Content-MD5 $content_md5
		}
		if {$content_type ne ""} {
			lappend headers Content-Type $content_type
		}

		set out_headers		$headers
		set out_sts			$string_to_sign
		#log notice "Sending aws request $method $signed_url\n$auth\n$string_to_sign"

	}

	#>>>
	proc sigv4_signing_key args { #<<<
		parse_args::parse_args $args {
			-aws_key		{-required}
			-date			{-required -# {in unix seconds}}
			-region			{-required}
			-service		{-required}
		}

		package require hmac
		set amzDate		[amz-date $date]
		set kDate		[hmac::HMAC_SHA256 [encoding convertto utf-8 AWS4$aws_key] [encoding convertto utf-8 $amzDate]]
		set kRegion		[hmac::HMAC_SHA256 $kDate       [encoding convertto utf-8 $region]]
		set kService	[hmac::HMAC_SHA256 $kRegion     [encoding convertto utf-8 $service]]
		hmac::HMAC_SHA256 $kService    [encoding convertto utf-8 aws4_request]
	}

	#>>>
	proc sigv4 args { #<<<
		parse_args::parse_args $args {
			-aws_id				{}
			-aws_key			{}
			-aws_token			{-default {}}
			-method				{-required}
			-service			{-required}
			-sig_service		{-default {}}
			-region				{-default us-east-1}
			-path				{-required}
			-scheme				{-default http}
			-headers			{-default {}}
			-params				{-default {}}
			-content_type		{-default {}}
			-body				{-default {}}
			-algorithm			{-enum {AWS4-HMAC-SHA256} -default AWS4-HMAC-SHA256}

			-out_url			{-alias}
			-out_headers		{-alias}
			-out_sts			{-alias}

			-date				{-# {Fake the date - for test suite}}
			-out_creq			{-alias -# {internal - used for test suite}}
			-out_authz			{-alias -# {internal - used for test suite}}
			-out_sreq			{-alias -# {internal - used for test suite}}
		}

		if {![info exists aws_id]} {
			if {[info exists env(AWS_ACCESS_KEY_ID)]} {
				set aws_id		$env(AWS_ACCESS_KEY_ID)
			} else {
				set aws_id		[json get [role_creds] AccessKeyId]
			}
		}
		if {![info exists aws_key]} {
			if {[info exists env(AWS_SECRET_ACCESS_KEY)]} {
				set aws_key		$env(AWS_SECRET_ACCESS_KEY)
			} else {
				set aws_key		[json get [role_creds] SecretAccessKey]
			}
		}
		if {$aws_token eq ""} {
			if {[info exists env(AWS_SESSION_TOKEN)]} {
				set aws_token	$env(AWS_SESSION_TOKEN)
			} else {
				set aws_token	[json get [role_creds] Token]
			}
		}

		if {$sig_service eq ""} {
			set sig_service	$service
		}
		set have_date_header	0
		foreach {k v} $headers {
			if {[string tolower $k] eq "x-amz-date"} {
				set have_date_header	1
				set date	[clock scan $v -format %Y%m%dT%H%M%SZ -timezone :UTC]
			}
		}
		if {![info exists date]} {
			set date	[clock seconds]
		}

		set aws_encode {s { #<<<
			foreach {- ok quote} [regexp -all -inline {([A-Za-z0-9_.~-]*)([^A-Za-z0-9_.~-]+)?} $s] {
				append out $ok
				if {$quote ne ""} {
					binary scan [encoding convertto utf-8 $quote] cu* byteslist
					foreach byte $byteslist {
						append out [format %%%02X $byte]
					}
				}
			}
			set out
		}}
		#>>>

		# Task1: Compile canonical request <<<
		# Endpoint <<<
		if {$region eq ""} {
			set endpoint	$service.amazonaws.com
		} else {
			set endpoint	$service.$region.amazonaws.com
		}
		# Endpoint >>>

		# Credential scope <<<
		set credential_scope	[aws amz-date $date]/[string tolower $region/$sig_service/aws4_request]
		# Credential scope >>>

		# Produce urlv: a list of fully decoded path elements, and canonized_path: a fully-encoded and normalized path <<<
		set urlv	{}
		if {$sig_service ne "s3" && [string trim $path /] eq ""} {
			set canonical_uri	/
		} else {
			set urlv	[lmap e [split $path /] {urlencode rfc_urldecode -- $e}]
			if {$sig_service eq "s3"} {
				set n_urlv	$urlv
			} else {
				# TODO: properly normalize path according to RFC 3986 section 6 - does not apply to s3
				set n_urlv	{}
				foreach e $urlv {
					set skipped	0
					switch -- $e {
						. - ""		{set skipped 1}
						..			{set n_urlv	[lrange $n_urlv 0 end-1]}
						default		{lappend n_urlv $e}
					}
				}
				if {$skipped} {lappend n_urlv ""}		;# Compensate for the switch on {. ""} stripping all the slashes off the end of the uri
			}
			set canonical_uri	/[join [lmap e $n_urlv {
				if {$sig_service eq "s3"} {
					apply $aws_encode $e
				} else {
					# Services other than S3 have to have the path elements encoded twice according to the documentation, but not the test vectors...
					#apply $aws_encode [apply $aws_encode $e]
					apply $aws_encode $e
				}
			}] /]
			if {$sig_service eq "s3" && [string index $path end] eq "/" && [string index $canonical_uri end] ne "/"} {
				append canonical_uri	/
			}
		}
		#>>>

		# Canonical query string <<<
		#if {[info exists aws_token]} {
		#	# Some services require the token to be added to th canonical request, others require it appended
		#	switch -- $sig_service {
		#		?? {
		#			lappend params X-Amz-Security-Token	$aws_token
		#		}
		#	}
		#}

		if {[llength $params] == 0} {
			set canonical_query_string	""
		} else {
			set paramsort {{a b} { #<<<
				# AWS sort wants sorting on keys, with values as tiebreaks
				set kc	[string compare [lindex $a 0] [lindex $b 0]]
				switch -- $kc {
					1 - -1	{ set kc }
					default { string compare [lindex $a 1] [lindex $b 1] }
				}
			}}

			#>>>

			set canonical_query_string	[join [lmap e [lsort -command [list apply $paramsort] [lmap {k v} $params {list $k $v}]] {
				lassign $e k v
				format %s=%s [apply $aws_encode $k] [apply $aws_encode $v]
			}] &]
		}

		#if {[info exists aws_token]} {
		#	# Some services require the token to be added to th canonical request, others require it appended
		#	switch -- $sig_service {
		#		?? {
		#			lappend params X-Amz-Security-Token	$aws_token
		#		}
		#	}
		#}
		# Canonical query string >>>

		# Canonical headers <<<
		set out_headers		$headers
		if {!$have_date_header} {
			lappend out_headers	x-amz-date	[amz-datetime $date]
		}

		if {$content_type ne ""} {
			lappend out_headers content-type $content_type
		}

		if {"host" ni [lmap {k v} $out_headers {string tolower $k}]} {
			#log notice "Appending host header" {{"header":{"host":"~S:endpoint"}}}
			lappend out_headers host $endpoint		;# :authority for HTTP/2
		}
		if {$aws_token ne ""} {
			#log notice "Appending aws_token header" {{"header":{"X-Amz-Security-Token":"~S:aws_token"}}}
			lappend out_headers X-Amz-Security-Token	$aws_token
		}

		set t_headers	{}
		foreach {k v} $out_headers {
			dict lappend t_headers $k $v
		}

		set canonical_headers	""
		set signed_headers		{}
		foreach {k v} [lsort -index 0 -stride 2 -nocase $t_headers] {
			set h	[string tolower [string trim $k]]
			#if {$h in {content-legnth}} continue		;# Problem with test vectors?
			lappend signed_headers	$h
			append canonical_headers	"$h:[join [lmap e $v {regsub -all { +} [string trim $e] { }}] ,]\n"
			#log debug "Adding canonical header" {{"h":"~S:h","canonical_headers":"~S:canonical_headers","signed_headers":"~S:signed_headers"}}
		}
		set signed_headers	[join $signed_headers ";"]
		# Canonical headers >>>

		set hashed_payload	[hash $algorithm $body]

		set canonical_request	"[string toupper $method]\n$canonical_uri\n$canonical_query_string\n$canonical_headers\n$signed_headers\n$hashed_payload"
		#log debug "canonical request" {{"creq": "~S:canonical_request"}}
		set hashed_canonical_request	[hash $algorithm $canonical_request]
		set out_creq	$canonical_request
		# Task1: Compile canonical request >>>

		# Task2: Create String to Sign <<<
		set string_to_sign	[encoding convertto utf-8 $algorithm]\n[amz-datetime $date]\n[encoding convertto utf-8 $credential_scope]\n$hashed_canonical_request
		set out_sts		$string_to_sign
		#log notice "sts:\n$out_sts"
		# Task2: Create String to Sign >>>

		# Task3: Calculate signature <<<
		package require hmac
		set signing_key	[sigv4_signing_key -aws_key $aws_key -date $date -region $region -service $sig_service]
		set signature	[binary encode hex [hmac::HMAC_SHA256 $signing_key [encoding convertto utf-8 $string_to_sign]]]
		# Task3: Calculate signature >>>


		set authorization	"$algorithm Credential=$aws_id/$credential_scope, SignedHeaders=$signed_headers, Signature=$signature"
		set out_authz		$authorization
		lappend out_headers	Authorization $authorization

		set url			$scheme://$endpoint$canonical_uri[urlencode encode_query $params]
		set out_url		$url
	}

	#>>>
	proc _aws_error {h xml_ns string_to_sign} { #<<<
		if {[$h body] eq ""} {
			throw [list AWS [$h code]] "AWS http code [$h code]"
		}
		if {[string match "\{*" [$h body]]} { # Guess json <<<
			if {[json exists [$h body] code]} {
				# TODO: use [json get [$h body] type]
				throw [list AWS \
					[json get [$h body] code] \
					[dict get [$h headers] x-amzn-requestid] \
					"" \
				] [json get [$h body] message]
			} elseif {[json exists [$h body] __type]} {
				if {[json exists [$h body] message]} {
					set message	[json get [$h body] message]
				} else {
					set message	"AWS exception: [json get [$h body] __type]"
				}
				throw [list AWS \
					[json get [$h body] __type] \
					[dict get [$h headers] x-amzn-requestid] \
					"" \
				] $message
			}
			#>>>
		} else { # Guess XML <<<
			dom parse [$h body] doc
			try {
				if {$xml_ns ne ""} {
					$doc selectNodesNamespaces [list a $xml_ns]
				}
				$doc documentElement root
				#log notice "AWS error:\n[$root asXML -indent 4]"
				if {[$root nodeName] eq "Error"} {
					set details	{}
					foreach node [$root childNodes] {
						lappend details [$node nodeName] [$node text]
					}
					throw [list AWS \
						[$root selectNodes string(Code)] \
						[$root selectNodes string(RequestId)] \
						[$root selectNodes string(Resource)] \
						$details \
					] "AWS: [$root selectNodes string(Message)]"
				} else {
					#log error "Error parsing AWS error response:\n[$h body]"
					throw [list AWS [$h code]] "Error parsing [$h code] error response from AWS"
				}
			} trap {AWS SignatureDoesNotMatch} {errmsg options} {
				set signed_hex	[regexp -all -inline .. [binary encode hex [encoding convertto utf-8 $string_to_sign]]]
				set wanted_hex	[$root selectNodes string(StringToSignBytes)]
				set wanted_str	[encoding convertto utf-8 [binary decode hex [$root selectNodes string(StringToSignBytes)]]]
				log error "AWS signing error" {
					{
						"hex": {
							"signed":"~S:signed_hex",
							"wanted":"~S:wanted_hex"
						},
						"str": {
							"signed":"~S:string_to_sign",
							"wanted":"~S:wanted_str"
						}
					}
				}
				return -options $options $errmsg
			} trap {AWS} {errmsg options} {
				return -options $options $errmsg
			} on error {errmsg options} {
				log error "Unhandled AWS error: [dict get $options -errorinfo]"
				throw {AWS UNKNOWN} $errmsg
			} finally {
				$doc delete
			}
			#>>>
		}
	}

	#>>>
	proc _req {method service path args} { #<<<
		parse_args::parse_args $args {
			-region				{-default us-east-1}
			-scheme				{-default http}
			-headers			{-default {}}
			-params				{-default {}}
			-content_type		{-default {}}
			-body				{-default {}}
			-xml_ns				{-default {}}
			-response_headers	{-alias}
			-sig_service		{-default {}}
			-version			{-enum {4 2} -default 4 -# {AWS signature version}}
		}

		switch -- $version {
			2 {
				sigv2 \
					-method			$method \
					-service		$service \
					-path			$path \
					-scheme			$scheme \
					-headers		$headers \
					-params			$params \
					-content_type	$content_type \
					-body			$body \
					-sig_service	$sig_service \
					-out_url		signed_url \
					-out_headers	signed_headers \
					-out_sts		string_to_sign
			}

			4 {
				sigv4 \
					-method			$method \
					-service		$service \
					-sig_service	$sig_service \
					-region			$region \
					-path			$path \
					-scheme			$scheme \
					-headers		$headers \
					-params			$params \
					-content_type	$content_type \
					-body			$body \
					-out_url		signed_url \
					-out_headers	signed_headers \
					-out_sts		string_to_sign
			}
		}

		if 0 {
		set bodysize	[string length $body]
		log notice "Making AWS request" {
			{
				"method": "~S:method",
				"signed_url": "~S:signed_url",
				"signed_headers": "~S:signed_headers",
				"headers": "~S:headers",
				//"body": "~S:body",
				"bodySize": "~N:bodysize"
			}
		}
		}
		rl_http instvar h $method $signed_url \
			-timeout   20 \
			-keepalive 1 \
			-headers   $signed_headers \
			-data      $body

		#log notice "aws req $method $signed_url response [$h code]\n\t[join [lmap {k v} [$h headers] {format {%s: %s} $k $v}] \n\t]\nbody: [$h body]"

		switch -glob -- [$h code] {
			2* {
				set response_headers	[$h headers]
				return [$h body]
			}

			3* - 4* - 5* {
				_aws_error $h $xml_ns $string_to_sign
			}
		}
	}

	#>>>
	proc req {method service path args} { #<<<
		variable ratelimit
		variable last_slowdown
		variable maxrate

		parse_args::parse_args $args {
			-region				{-default us-east-1}
			-scheme				{-default http}
			-headers			{-default {}}
			-params				{-default {}}
			-content_type		{-default {}}
			-body				{-default {}}
			-xml_ns				{-default {}}
			-response_headers	{-alias}
			-sig_service		{-default {}}
			-version			{-enum {4 2} -default 4 -# {AWS signature version}}
			-retries			{-default 3}
		}

		if {$ratelimit < $maxrate && [clock seconds] - $last_slowdown > 10} {
			set ratelimit		[expr {min($maxrate, int($ratelimit * 1.1))}]
			log notice "aws req ratelimit recovery to $ratelimit"
			set last_slowdown	[clock seconds]
		}

		for {set try 0} {$try < $retries} {incr try} {
			try {
				ratelimit $ratelimit {
					return [_req $method $service $path \
						-region			$region \
						-headers		$headers \
						-params			$params \
						-content_type	$content_type \
						-body			$body \
						-response_headers response_headers \
						-scheme			$scheme \
						-xml_ns			$xml_ns \
						-sig_service	$sig_service \
						-version		$version \
					]
				}
			} trap {AWS InternalError} {errmsg options} {
				continue
			} trap {AWS ServiceUnavailable} {errmsg options} - trap {AWS SlowDown} {errmsg options} {
				set ratelimit		[expr {max(1, int($ratelimit * 0.9))}]
				log notice "aws req got [dict get $options -errorcode], ratelimit now: $ratelimit"
				set last_slowdown	[clock seconds]
				after 200
				continue
			}
		}

		throw {AWS TOO_MANY_ERRORS} "Too many errors, ran out of patience retrying"
	}

	#>>>
	proc identify {} { # Attempt to identify the AWS platform: EC2, Lambda, ECS, or none - not on AWS <<<
		global env

		if {
			[file readable /sys/devices/virtual/dmi/id/sys_vendor] &&
			[readfile /sys/devices/virtual/dmi/id/sys_vendor] eq "Amazon EC2"
		} {
			return EC2
		}

		if {[info exists env(LAMBDA_TASK_ROOT)]} {
			return Lambda
		}

		if {
			[info exists env(AWS_EXECUTION_ENV)]
		} {
			switch -exact -- $env(AWS_EXECUTION_ENV) {
				AWS_ECS_EC2 -
				AWS_ECS_FARGATE {
					return ECS
				}
			}
		}

		if {
			[info exists env(ECS_CONTAINER_METADATA_URI_V4)] ||
			[info exists env(ECS_CONTAINER_METADATA_URI)]
		} {
			return ECS
		}

		return none
	}

	#>>>
	variable cache {}

	proc _metadata_req url { #<<<
		rl_http instvar h GET $url -stats_cx AWS
		if {[$h code] != 200} {
			throw [list AWS [$h code]] [$h body]
		}
		$h body
	}

	#>>>
	proc _metadata path { #<<<
		global env

		if {[aws identify] eq "ECS"} {
			foreach v {
				ECS_CONTAINER_METADATA_URI_V4
				ECS_CONTAINER_METADATA_URI
			} {
				if {[info exists env($v)]} {
					set base	http://$env($v)
					break
				}
			}

			if {![info exists base]} {
				# Try v2
				set base	http://169.254.170.2/v2
			}
		} else {
			set base	http://169.254.169.254/latest
		}
		_metadata_req $base/[string trimleft $path /]
	}

	#>>>
	proc instance_identity {} { #<<<
		variable cache
		if {![dict exists $cache instance_identity]} {
			dict set cache instance_identity [_metadata dynamic/instance-identity/document]
		}
		dict get $cache instance_identity
	}

	#>>>
	proc role_creds {} { #<<<
		global env
		variable cached_role_creds
		if {
			![info exists cached_role_creds] ||
			[json get $cached_role_creds expires_sec] - [clock seconds] < 60
		} {
			#set cached_role_creds	[_metadata meta-data/identity-credentials/ec2/security-credentials/ec2-instance]
			if {[info exists env(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)]} {
				set cached_role_creds	[_metadata_req http://169.254.170.2$env(AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)]
			} else {
				set role				[_metadata meta-data/iam/security-credentials]
				set cached_role_creds	[_metadata meta-data/iam/security-credentials/$role]
			}

			json set cached_role_creds expires_sec	[clock scan [json get $cached_role_creds Expiration] -timezone :UTC -format {%Y-%m-%dT%H:%M:%SZ}]
		}
		set cached_role_creds
	}

	#>>>
	proc availability_zone {}	{json get [instance_identity] availabilityZone}
	proc region {}				{json get [instance_identity] region}
	proc account_id {}			{json get [instance_identity] accountId}
	proc instance_id {}			{json get [instance_identity] instanceId}
	proc image_id {}			{json get [instance_identity] imageId}
	proc instance_type {}		{json get [instance_identity] instanceType}
	proc public_ipv4 {}			{_metadata meta-data/public-ipv4}
	proc local_ipv4 {}			{_metadata meta-data/local-ipv4}

	proc ecs_task {} { # Retrieve the ECS task metadata (if running on ECS / Fargate) <<<
		global env

		foreach v {
			ECS_CONTAINER_METADATA_URI_V4
			ECS_CONTAINER_METADATA_URI
		} {
			if {[info exists env($v)]} {
				set base	http://$env($v)
				break
			}
		}

		if {![info exists base]} {
			# Try v2
			set base	http://169.254.170.2/v2
		}

		rl_http instvar h GET $base/[string trimleft $path /] -stats_cx AWS
		if {[$h code] != 200} {
			throw [list AWS [$h code]] [$h body]
		}
		$h body
	}

	#>>>
}

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

