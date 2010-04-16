# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

namespace eval [file tail $argv0] {
	namespace export *
	namespace ensemble create

	proc random {bytecount_expr} { #<<<
		package require crypto

		chan configure stdout -translation binary -encoding binary
		set remaining		[expr $bytecount_expr]
		while {$remaining > 0} {
			set chunk	[expr {min($remaining, 50000)}]
			puts -nonewline stdout [crypto::blowfish::csprng $chunk]
			chan flush stdout
			puts -nonewline stderr .
			incr remaining	-$chunk
		}
	}

	#>>>
}

try {
	[file tail $argv0] {*}$argv
} on error {errmsg options} {
	puts stderr $errmsg
	puts stderr [dict get $options -errorinfo]
	exit 2
} on ok {} {
	exit 0
}
