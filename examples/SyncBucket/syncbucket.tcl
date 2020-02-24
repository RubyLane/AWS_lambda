package require aws::s3
package require parse_args
	
interp alias {} parse_args {} ::parse_args::parse_args

proc log {lvl msg args} { #<<<
	parse_args $args {
		template {}
	}

	if {[info exists template]} {
		set details	[uplevel 1 [list json template $template]]
		puts stderr [json template {
			{
				"lvl":	"~S:lvl",
				"msg":	"~S:msg",
				"details":	"~J:details"
			}
		}]
	} else {
		puts stderr [json template {
			{
				"lvl":	"~S:lvl",
				"msg":	"~S:msg"
			}
		}]
	}
}

#>>>
proc readfile fn { #<<<
	set h	[open $fn r]
	try {
		read $h
	} finally {
		close $h
	}
}

#>>>
proc rss {} {expr {[lindex [readfile /proc/self/statm] 1] * 4}}
proc log_duration {desc script} { #<<<
	global _times
	set mem_start	[rss]
	set before  	[clock microseconds]

	set code    [catch {
		uplevel 1 $script
	} r o]
	set elapsed [expr {([clock microseconds]-$before)/1e6}]
	set mem_end	[rss]
	lappend _times $desc $elapsed [expr {$mem_end - $mem_start}]
	switch -- $code {
		0	{set code OK}
		1	{set code ERROR}
		2	{set code RETURN}
		3	{set code BREAK}
		4	{set code CONTINUE}
	}
	if 0 {
		puts stderr [json template {
			{
				"section":	"~S:desc",
				"seconds":	"~N:elapsed",
				"code":		"~S:code"
			}
		}]
	}
	dict incr o -level 1
	return -options $o $r
}

#>>>
proc handler {event context} { #<<<
	global _times
	set _times {}
	try {
		log_duration "Everything" {
			set rss_start	[rss]

			#puts stderr [json normalize $event]
			#puts stderr [json normalize $context]

			set toregion	us-west-2
			set tobucket	backups

			set ops	{[]}
			json foreach record [json extract $event Records] {
				set fromregion	[json get $record awsRegion]
				set frombucket	[json get $record s3 bucket name]
				set key			[json get $record s3 object key]
				set evname		[json get $record eventName]

				log_duration "Record [incr rec] $evname" {
					switch -glob -- $evname {
						ObjectCreated:* {
							s3 copy \
								-region $toregion -bucket $tobucket -path $key \
								-source_bucket $frombucket -source $key

							json set ops end+1 [json template {
								{
									"create":	"~S:key",
									"size":		"~N:size"
								}
							} [json get $record s3 object]]
						}

						ObjectRemoved:* {
							s3 delete -region $toregion -bucket $tobucket -path $key

							json set ops end+1 [json template {
								{
									"remove":	"~S:key"
								}
							}]
						}

						default {
							log error "Unexpected event type: $evname"
						}
					}
				}
			}
		}

	} on error {errmsg options} {
		puts stderr [json template {
			{
				"errorcode": "~S:-errorcode",
				"errorinfo": "~S:-errorinfo"
			}
		} $options]

	} finally {
		set times	{{}}
		foreach {desc elapsed alloc} $_times {
			json set times $desc [json template {
				{
					"seconds":	"~N:elapsed",
					"alloc":	"~N:alloc"
				}
			}]
		}

		set rss_end	[rss]

		log notice "Summary" {
			{
				"ops":			"~J:ops",
				"rss_start":	"~N:rss_start",
				"rss_end":		"~N:rss_end",
				"times":		"~J:times"
			}
		}
	}
}

#>>>

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
