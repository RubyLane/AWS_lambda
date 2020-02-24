namespace eval hmac {
	namespace path {
		::tcl::mathop
	}

	proc xor {a b} {
		binary scan $a c* aL
		binary scan $b c* bL

		binary format c* [lmap ab $aL bb $bL {^ $ab $bb}]
	}

	if {[info commands ::ns_config] ne "" && [ns_config ns/server/[ns_info server]/modules rlhash] ne ""} { # Use the hash functions provided by rlhash
		proc H {hash s} {
			switch -- $hash {
				md5 {
					md5 $s
				}

				sha1 {
					package require sha1 2
					sha1::sha1 -bin -- $s
				}

				sha256 {
					binary decode hex [sha256 $s]
				}

				default {
					error "Unknown hash function \"$hash\""
				}
			}
		}
	} else {
		proc H {hash s} {
			switch -- $hash {
				md5 {
					package require hash
					hash::md5 $s
				}

				sha1 {
					package require sha1 2
					sha1::sha1 -bin -- $s
				}

				sha256 {
					package require hash
					binary decode hex [hash::sha256 $s]
				}

				default {
					error "Unknown hash function \"$hash\""
				}
			}
		}
	}

	proc HMAC {hash bs K m} {
		set opad	[string repeat \x5C $bs]
		set ipad	[string repeat \x36 $bs]
		set keylen	[string length $K]
		if {$keylen > $bs} {
			set K	[H $hash $K]
		}
		set keylen	[string length $K]
		if {$keylen < $bs} {
			set K	$K[string repeat \x00 [- $bs $keylen]]
		}
		H $hash [xor $K $opad][H $hash [xor $K $ipad]$m]
	}

	proc HMAC_MD5 {K m} {HMAC md5 64 $K $m}
	proc HMAC_SHA1 {K m} {HMAC sha1 64 $K $m}
	proc HMAC_SHA256 {K m} {HMAC sha256 64 $K $m}
}

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
