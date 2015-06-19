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
	proc encrypt key { #<<<
		package require crypto
		set ks	[crypto::blowfish::init_key $key]
		set iv	[crypto::blowfish::randbytes 8]
		set plaintext	[encoding convertto utf-8 [chan read stdin]]
		puts [binary encode base64 $iv[crypto::blowfish::encrypt_cbc $ks $plaintext $iv]]
	}

	#>>>
	proc decrypt key { #<<<
		package require crypto
		set ks	[crypto::blowfish::init_key $key]
		set bin	[binary decode base64 [chan read stdin]]
		set iv	[string range $bin 0 7]
		puts -nonewline [encoding convertfrom utf-8 [crypto::blowfish::decrypt_cbc $ks [string range $bin 8 end] $iv]]
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
