# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

# Copyright 2009-2015 Cyan Ogilvie.  See license.terms for license.
# Most of the in-line comments are taken directly from the standards documents:
# https://www.inf.pucrs.br/~calazans/graduate/TPVLSI_I/RSA-oaep_spec.pdf and
# rfc3447.
# Those comments are copyright their original authors.  The purpuse of
# including them in this source code is to facilitate auditing the code
# against the specification.

# While I have been careful to adhere to the implementation guidelines as
# closely as possible, no cryptographic audit has been performed on this code
# and I make no warrenties as to its correctness or security.  You are
# encouraged to examine the code yourself or get a qualified cryptographer to
# audit this code before using it in an application with specific security
# requirements.
#
# In particular it should be noted that key privacy is poor - the limitations
# of working in a scripting language means that the keys could be leaked
# through freed memory, so this code should not be used in any situation where
# an attacker could have access to system memory.  Certain timing attacks
# are also probably made more feasible because the script runs more slowly
# than native code, magnifying the effects of taking different branches in
# the code.


# public key asn structure:
#
# ASN1_SEQUENCE_cb(RSAPublicKey, rsa_cb) = {
#	ASN1_SIMPLE(RSA, n, BIGNUM),
#	ASN1_SIMPLE(RSA, e, BIGNUM),
# }

# private key asn structure:
#
# ASN1_SEQUENCE_cb(RSAPrivateKey, rsa_cb) = {
#	ASN1_SIMPLE(RSA, version, LONG),
#	ASN1_SIMPLE(RSA, n, BIGNUM),
#	ASN1_SIMPLE(RSA, e, BIGNUM),
#	ASN1_SIMPLE(RSA, d, BIGNUM),
#	ASN1_SIMPLE(RSA, p, BIGNUM),
#	ASN1_SIMPLE(RSA, q, BIGNUM),
#	ASN1_SIMPLE(RSA, dmp1, BIGNUM),
#	ASN1_SIMPLE(RSA, dmq1, BIGNUM),
#	ASN1_SIMPLE(RSA, iqmp, BIGNUM)
# }


# Based on http://www.comms.scitech.susx.ac.uk/fft/crypto/rsa-oaep_spec.pdf

namespace eval crypto::rsa {
	variable debug	0
	# The first 2000 primes <<<
	variable smallprimes {
		2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71 73 79 83 89 97
		101 103 107 109 113 127 131 137 139 149 151 157 163 167 173 179 181 191
		193 197 199 211 223 227 229 233 239 241 251 257 263 269 271 277 281 283
		293 307 311 313 317 331 337 347 349 353 359 367 373 379 383 389 397 401
		409 419 421 431 433 439 443 449 457 461 463 467 479 487 491 499 503 509
		521 523 541 547 557 563 569 571 577 587 593 599 601 607 613 617 619 631
		641 643 647 653 659 661 673 677 683 691 701 709 719 727 733 739 743 751
		757 761 769 773 787 797 809 811 821 823 827 829 839 853 857 859 863 877
		881 883 887 907 911 919 929 937 941 947 953 967 971 977 983 991 997
		1009 1013 1019 1021 1031 1033 1039 1049 1051 1061 1063 1069 1087 1091
		1093 1097 1103 1109 1117 1123 1129 1151 1153 1163 1171 1181 1187 1193
		1201 1213 1217 1223 1229 1231 1237 1249 1259 1277 1279 1283 1289 1291
		1297 1301 1303 1307 1319 1321 1327 1361 1367 1373 1381 1399 1409 1423
		1427 1429 1433 1439 1447 1451 1453 1459 1471 1481 1483 1487 1489 1493
		1499 1511 1523 1531 1543 1549 1553 1559 1567 1571 1579 1583 1597 1601
		1607 1609 1613 1619 1621 1627 1637 1657 1663 1667 1669 1693 1697 1699
		1709 1721 1723 1733 1741 1747 1753 1759 1777 1783 1787 1789 1801 1811
		1823 1831 1847 1861 1867 1871 1873 1877 1879 1889 1901 1907 1913 1931
		1933 1949 1951 1973 1979 1987 1993 1997 1999 2003 2011 2017 2027 2029
		2039 2053 2063 2069 2081 2083 2087 2089 2099 2111 2113 2129 2131 2137
		2141 2143 2153 2161 2179 2203 2207 2213 2221 2237 2239 2243 2251 2267
		2269 2273 2281 2287 2293 2297 2309 2311 2333 2339 2341 2347 2351 2357
		2371 2377 2381 2383 2389 2393 2399 2411 2417 2423 2437 2441 2447 2459
		2467 2473 2477 2503 2521 2531 2539 2543 2549 2551 2557 2579 2591 2593
		2609 2617 2621 2633 2647 2657 2659 2663 2671 2677 2683 2687 2689 2693
		2699 2707 2711 2713 2719 2729 2731 2741 2749 2753 2767 2777 2789 2791
		2797 2801 2803 2819 2833 2837 2843 2851 2857 2861 2879 2887 2897 2903
		2909 2917 2927 2939 2953 2957 2963 2969 2971 2999 3001 3011 3019 3023
		3037 3041 3049 3061 3067 3079 3083 3089 3109 3119 3121 3137 3163 3167
		3169 3181 3187 3191 3203 3209 3217 3221 3229 3251 3253 3257 3259 3271
		3299 3301 3307 3313 3319 3323 3329 3331 3343 3347 3359 3361 3371 3373
		3389 3391 3407 3413 3433 3449 3457 3461 3463 3467 3469 3491 3499 3511
		3517 3527 3529 3533 3539 3541 3547 3557 3559 3571 3581 3583 3593 3607
		3613 3617 3623 3631 3637 3643 3659 3671 3673 3677 3691 3697 3701 3709
		3719 3727 3733 3739 3761 3767 3769 3779 3793 3797 3803 3821 3823 3833
		3847 3851 3853 3863 3877 3881 3889 3907 3911 3917 3919 3923 3929 3931
		3943 3947 3967 3989 4001 4003 4007 4013 4019 4021 4027 4049 4051 4057
		4073 4079 4091 4093 4099 4111 4127 4129 4133 4139 4153 4157 4159 4177
		4201 4211 4217 4219 4229 4231 4241 4243 4253 4259 4261 4271 4273 4283
		4289 4297 4327 4337 4339 4349 4357 4363 4373 4391 4397 4409 4421 4423
		4441 4447 4451 4457 4463 4481 4483 4493 4507 4513 4517 4519 4523 4547
		4549 4561 4567 4583 4591 4597 4603 4621 4637 4639 4643 4649 4651 4657
		4663 4673 4679 4691 4703 4721 4723 4729 4733 4751 4759 4783 4787 4789
		4793 4799 4801 4813 4817 4831 4861 4871 4877 4889 4903 4909 4919 4931
		4933 4937 4943 4951 4957 4967 4969 4973 4987 4993 4999 5003 5009 5011
		5021 5023 5039 5051 5059 5077 5081 5087 5099 5101 5107 5113 5119 5147
		5153 5167 5171 5179 5189 5197 5209 5227 5231 5233 5237 5261 5273 5279
		5281 5297 5303 5309 5323 5333 5347 5351 5381 5387 5393 5399 5407 5413
		5417 5419 5431 5437 5441 5443 5449 5471 5477 5479 5483 5501 5503 5507
		5519 5521 5527 5531 5557 5563 5569 5573 5581 5591 5623 5639 5641 5647
		5651 5653 5657 5659 5669 5683 5689 5693 5701 5711 5717 5737 5741 5743
		5749 5779 5783 5791 5801 5807 5813 5821 5827 5839 5843 5849 5851 5857
		5861 5867 5869 5879 5881 5897 5903 5923 5927 5939 5953 5981 5987 6007
		6011 6029 6037 6043 6047 6053 6067 6073 6079 6089 6091 6101 6113 6121
		6131 6133 6143 6151 6163 6173 6197 6199 6203 6211 6217 6221 6229 6247
		6257 6263 6269 6271 6277 6287 6299 6301 6311 6317 6323 6329 6337 6343
		6353 6359 6361 6367 6373 6379 6389 6397 6421 6427 6449 6451 6469 6473
		6481 6491 6521 6529 6547 6551 6553 6563 6569 6571 6577 6581 6599 6607
		6619 6637 6653 6659 6661 6673 6679 6689 6691 6701 6703 6709 6719 6733
		6737 6761 6763 6779 6781 6791 6793 6803 6823 6827 6829 6833 6841 6857
		6863 6869 6871 6883 6899 6907 6911 6917 6947 6949 6959 6961 6967 6971
		6977 6983 6991 6997 7001 7013 7019 7027 7039 7043 7057 7069 7079 7103
		7109 7121 7127 7129 7151 7159 7177 7187 7193 7207 7211 7213 7219 7229
		7237 7243 7247 7253 7283 7297 7307 7309 7321 7331 7333 7349 7351 7369
		7393 7411 7417 7433 7451 7457 7459 7477 7481 7487 7489 7499 7507 7517
		7523 7529 7537 7541 7547 7549 7559 7561 7573 7577 7583 7589 7591 7603
		7607 7621 7639 7643 7649 7669 7673 7681 7687 7691 7699 7703 7717 7723
		7727 7741 7753 7757 7759 7789 7793 7817 7823 7829 7841 7853 7867 7873
		7877 7879 7883 7901 7907 7919 7927 7933 7937 7949 7951 7963 7993 8009
		8011 8017 8039 8053 8059 8069 8081 8087 8089 8093 8101 8111 8117 8123
		8147 8161 8167 8171 8179 8191 8209 8219 8221 8231 8233 8237 8243 8263
		8269 8273 8287 8291 8293 8297 8311 8317 8329 8353 8363 8369 8377 8387
		8389 8419 8423 8429 8431 8443 8447 8461 8467 8501 8513 8521 8527 8537
		8539 8543 8563 8573 8581 8597 8599 8609 8623 8627 8629 8641 8647 8663
		8669 8677 8681 8689 8693 8699 8707 8713 8719 8731 8737 8741 8747 8753
		8761 8779 8783 8803 8807 8819 8821 8831 8837 8839 8849 8861 8863 8867
		8887 8893 8923 8929 8933 8941 8951 8963 8969 8971 8999 9001 9007 9011
		9013 9029 9041 9043 9049 9059 9067 9091 9103 9109 9127 9133 9137 9151
		9157 9161 9173 9181 9187 9199 9203 9209 9221 9227 9239 9241 9257 9277
		9281 9283 9293 9311 9319 9323 9337 9341 9343 9349 9371 9377 9391 9397
		9403 9413 9419 9421 9431 9433 9437 9439 9461 9463 9467 9473 9479 9491
		9497 9511 9521 9533 9539 9547 9551 9587 9601 9613 9619 9623 9629 9631
		9643 9649 9661 9677 9679 9689 9697 9719 9721 9733 9739 9743 9749 9767
		9769 9781 9787 9791 9803 9811 9817 9829 9833 9839 9851 9857 9859 9871
		9883 9887 9901 9907 9923 9929 9931 9941 9949 9967 9973 10007 10009
		10037 10039 10061 10067 10069 10079 10091 10093 10099 10103 10111 10133
		10139 10141 10151 10159 10163 10169 10177 10181 10193 10211 10223 10243
		10247 10253 10259 10267 10271 10273 10289 10301 10303 10313 10321 10331
		10333 10337 10343 10357 10369 10391 10399 10427 10429 10433 10453 10457
		10459 10463 10477 10487 10499 10501 10513 10529 10531 10559 10567 10589
		10597 10601 10607 10613 10627 10631 10639 10651 10657 10663 10667 10687
		10691 10709 10711 10723 10729 10733 10739 10753 10771 10781 10789 10799
		10831 10837 10847 10853 10859 10861 10867 10883 10889 10891 10903 10909
		10937 10939 10949 10957 10973 10979 10987 10993 11003 11027 11047 11057
		11059 11069 11071 11083 11087 11093 11113 11117 11119 11131 11149 11159
		11161 11171 11173 11177 11197 11213 11239 11243 11251 11257 11261 11273
		11279 11287 11299 11311 11317 11321 11329 11351 11353 11369 11383 11393
		11399 11411 11423 11437 11443 11447 11467 11471 11483 11489 11491 11497
		11503 11519 11527 11549 11551 11579 11587 11593 11597 11617 11621 11633
		11657 11677 11681 11689 11699 11701 11717 11719 11731 11743 11777 11779
		11783 11789 11801 11807 11813 11821 11827 11831 11833 11839 11863 11867
		11887 11897 11903 11909 11923 11927 11933 11939 11941 11953 11959 11969
		11971 11981 11987 12007 12011 12037 12041 12043 12049 12071 12073 12097
		12101 12107 12109 12113 12119 12143 12149 12157 12161 12163 12197 12203
		12211 12227 12239 12241 12251 12253 12263 12269 12277 12281 12289 12301
		12323 12329 12343 12347 12373 12377 12379 12391 12401 12409 12413 12421
		12433 12437 12451 12457 12473 12479 12487 12491 12497 12503 12511 12517
		12527 12539 12541 12547 12553 12569 12577 12583 12589 12601 12611 12613
		12619 12637 12641 12647 12653 12659 12671 12689 12697 12703 12713 12721
		12739 12743 12757 12763 12781 12791 12799 12809 12821 12823 12829 12841
		12853 12889 12893 12899 12907 12911 12917 12919 12923 12941 12953 12959
		12967 12973 12979 12983 13001 13003 13007 13009 13033 13037 13043 13049
		13063 13093 13099 13103 13109 13121 13127 13147 13151 13159 13163 13171
		13177 13183 13187 13217 13219 13229 13241 13249 13259 13267 13291 13297
		13309 13313 13327 13331 13337 13339 13367 13381 13397 13399 13411 13417
		13421 13441 13451 13457 13463 13469 13477 13487 13499 13513 13523 13537
		13553 13567 13577 13591 13597 13613 13619 13627 13633 13649 13669 13679
		13681 13687 13691 13693 13697 13709 13711 13721 13723 13729 13751 13757
		13759 13763 13781 13789 13799 13807 13829 13831 13841 13859 13873 13877
		13879 13883 13901 13903 13907 13913 13921 13931 13933 13963 13967 13997
		13999 14009 14011 14029 14033 14051 14057 14071 14081 14083 14087 14107
		14143 14149 14153 14159 14173 14177 14197 14207 14221 14243 14249 14251
		14281 14293 14303 14321 14323 14327 14341 14347 14369 14387 14389 14401
		14407 14411 14419 14423 14431 14437 14447 14449 14461 14479 14489 14503
		14519 14533 14537 14543 14549 14551 14557 14561 14563 14591 14593 14621
		14627 14629 14633 14639 14653 14657 14669 14683 14699 14713 14717 14723
		14731 14737 14741 14747 14753 14759 14767 14771 14779 14783 14797 14813
		14821 14827 14831 14843 14851 14867 14869 14879 14887 14891 14897 14923
		14929 14939 14947 14951 14957 14969 14983 15013 15017 15031 15053 15061
		15073 15077 15083 15091 15101 15107 15121 15131 15137 15139 15149 15161
		15173 15187 15193 15199 15217 15227 15233 15241 15259 15263 15269 15271
		15277 15287 15289 15299 15307 15313 15319 15329 15331 15349 15359 15361
		15373 15377 15383 15391 15401 15413 15427 15439 15443 15451 15461 15467
		15473 15493 15497 15511 15527 15541 15551 15559 15569 15581 15583 15601
		15607 15619 15629 15641 15643 15647 15649 15661 15667 15671 15679 15683
		15727 15731 15733 15737 15739 15749 15761 15767 15773 15787 15791 15797
		15803 15809 15817 15823 15859 15877 15881 15887 15889 15901 15907 15913
		15919 15923 15937 15959 15971 15973 15991 16001 16007 16033 16057 16061
		16063 16067 16069 16073 16087 16091 16097 16103 16111 16127 16139 16141
		16183 16187 16189 16193 16217 16223 16229 16231 16249 16253 16267 16273
		16301 16319 16333 16339 16349 16361 16363 16369 16381 16411 16417 16421
		16427 16433 16447 16451 16453 16477 16481 16487 16493 16519 16529 16547
		16553 16561 16567 16573 16603 16607 16619 16631 16633 16649 16651 16657
		16661 16673 16691 16693 16699 16703 16729 16741 16747 16759 16763 16787
		16811 16823 16829 16831 16843 16871 16879 16883 16889 16901 16903 16921
		16927 16931 16937 16943 16963 16979 16981 16987 16993 17011 17021 17027
		17029 17033 17041 17047 17053 17077 17093 17099 17107 17117 17123 17137
		17159 17167 17183 17189 17191 17203 17207 17209 17231 17239 17257 17291
		17293 17299 17317 17321 17327 17333 17341 17351 17359 17377 17383 17387
		17389 17393
	}
	# The first 2000 primes >>>

	proc I2OSP {x l} { #<<<
		# Integer to Octet String Primative
		# Input:	x - nonnegative integer to be converted
		#			l - intended length of the resulting octet string
		# Output:	X - corresponding octet string of length l
		# Throws:	integer_too_large

		# Looks like the zero-extended big endian representation
		if {$x >= 256**$l} {
			throw {integer_too_large} "Integer too large"
		}
		set X	""
		for {set i 1} {$i <= $l} {incr i} {
			set s	[expr {$l - $i}]
			set o	[binary format c [expr {($x >> ($s<<3)) & 0xff}]]
			append X	$o
		}
		return $X
	}

	#>>>
	proc OS2IP {X} { #<<<
		# Octet String to Integer Primative
		# Input:	X - octet string to be converted
		# Output:	x - corresponding nonnegative integer
		set x	0
		set s	[string length $X]
		foreach o [split $X {}] {
			incr s -1
			binary scan $o cu v
			incr x	[expr {$v << ($s<<3)}]
		}
		return $x
	}

	#>>>
	proc EME-OAEP-Encode {M P emLen Hash MGF} { #<<<
		# OAEP encode
		# Options:		Hash	- Hash function (hLen denotes the length in
		#						  octets of the hash function output)
		#				MGF		- Mask Generation Function
		# Input:		M		- Message to be encoded, an octet string of
		#						  length at most emLen - 1 - 2blen (mLen
		#						  denotes the length in octets of the message)
		#				P		- encoding parameters, an octet string
		#				emLen	- intended length in octets of the encoded
		#						  message, at least 2hLen + 1)
		# Output:		EM		- Encoded Message, an octet string of length
		#						  emLen
		# Throws:	message_too_long, parameter_string_too_long
		variable debug

		# If the length of P is greater than the input limitation for the hash
		# function (2⁶¹ − 1 octets for SHA-1) then output "parameter string
		# too long" and stop
		if {[string length $P] > [apply $Hash input_limit]} {
			throw {parameter_string_too_long} "Parameter string to long for hash"
		}

		# SHA-1 outputs 160 bits or 20 bytes
		set hLen	[apply $Hash output_len]

		# If mLen > emLen − 2hLen − 1, output "message too long" and stop
		set mLen	[string length $M]
		if {$mLen > $emLen - 2*$hLen - 1} {
			throw {message_too_long} "Message too long"
		}

		# Generate an octet string PS consisting of emLen − mLen − 2hLen − 1
		# zero octets. The length of PS may be 0
		set PS		[string repeat \0 [expr {$emLen - $mLen - 2*$hLen - 1}]]

		# Let pHash = Hash(P), an octet string of length hLen
		set pHash		[apply $Hash hash $P]
		if {$debug} {
			if {$pHash ne [testvec2os pHash]} {
				puts stderr "pHash:\n[binary encode hex $pHash]\n[binary encode [testvec2os pHash]]"
			}
		}

		# Concatenate pHash, PS, the message M, and other padding to form a
		# data block DB as DB = pHash || PS || 01 || M
		set DB			""
		append DB		$pHash $PS \1 $M

		if {$debug} {
			if {$DB ne [testvec2os DB]} {
				puts stderr "DB mismatch:\n[binary encode hex $DB]\n[binary encode hex $DB]"
			}
		}

		# Generate a random octet string seed of length hLen.
		if {$debug} {
			set seed		[testvec2os seed]
		} else {
			#set seed		[random_bytes $hLen]
			set seed		[crypto::blowfish::csprng $hLen]
		}
		#set seed		"12345678901234567890"

		# Let dbMask = MGF(seed, emLen − hLen)
		set dbMask		[apply $MGF $seed [expr {$emLen - $hLen}] $Hash]

		if {$debug} {
			if {$dbMask ne [testvec2os dbMask]} {
				puts "dbMask mismatch:\n[binary encode hex $dbMask]\n[binary encode hex [testvec2os dbMask]]"
			}
		}

		# Let maskedDB = DB ⊕ dbMask
		#set maskedDB	[expr {$DB ^ $dbMask}]
		set maskedDB	[xor $DB $dbMask]

		# Let seedMask = MGF(maskedDB, hLen)
		set seedMask	[apply $MGF $maskedDB $hLen $Hash]

		# Let maskedSeed = seed ⊕ seedMask
		#set maskedSeed	[expr {$seed ^ $seedMask}]
		set maskedSeed	[xor $seed $seedMask]

		# Let EM = maskedSeed || maskedDB
		set EM			""
		append EM $maskedSeed $maskedDB

		# Output EM
		return $EM
	}

	#>>>
	proc EME-OAEP-Decode {EM P Hash MGF} { #<<<
		# OAEP Decode
		# Options:		Hash	- Hash function (hLen denotes the length in
		#						  octets of the hash function output)
		#				MGF		- Mask Generation Function
		# Input:		EM		- Encoded Message, an octet string of length
		#						  at least 2hLen + 1 (emLen denotes the length
		#						  in octets of EM)
		#				P		- encoding parameters, an octet string
		# Output:		m		- recovered message, an octet string of length
		#						  at most emLen - 1 - 2*hLen
		# Throws:	decoding_error

		set hLen		[apply $Hash output_len]
		set emLen		[string length $EM]

		# If the length of P is greater than the input limitation for the hash
		# function (2⁶¹ − 1 octets for SHA-1) then output "decoding error"
		# and stop.
		if {[string length $P] > [apply $Hash input_limit]} {
			throw {decoding_error} "P is longer than the hash limit"
		}

		# If emLen < 2hLen + 1, output "decoding error" and stop.
		if {$emLen < 2*$hLen + 1} {
			throw {decoding_error} "EM is shorter than 2*$hLen + 1"
		}

		# Let maskedSeed be the first hLen octets of EM and let maskedDB be the
		# remaining emLen−hLen octets.
		set maskedSeed	[string range $EM 0 $hLen-1]
		set maskedDB	[string range $EM $hLen end]

		# Let seedMask = MGF(maskedDB, hLen).
		#lset MGF 2 [namespace current]
		set seedMask	[apply $MGF $maskedDB $hLen $Hash]

		# Let seed = maskedSeed ⊕ seedMask.
		#set seed		[expr {$maskedSeed ^ $seedMask}]
		set seed		[xor $maskedSeed $seedMask]

		# Let dbMask = MGF(seed, emLen − hLen).
		set dbMask		[apply $MGF $seed [expr {$emLen - $hLen}] $Hash]

		# Let DB = maskedDB ⊕ dbMask.
		#set DB			[expr {$maskedDB ^ $dbMask}]
		set DB			[xor $maskedDB $dbMask]

		# Let pHash = Hash(P), an octet string of length hLen.
		set pHash		[apply $Hash hash $P]

		# Separate DB into an octet string pHash’ consisting of the first hLen
		# octets of DB , a (possibly empty) octet string P S consisting of
		# consecutive zero octets following pHash’, and a message M as
		#             DB = pHash’ || PS || 01 || M
		# If there is no 01 octet to separate PS from M, output "decoding
		# error" and stop.
		set pHash'		[string range $DB 0 $hLen-1]
		set marker		[string first \1 $DB $hLen]
		if {$marker == -1} {
			throw {decoding_error} "No 0x01 marker between PS and M"
		}
		set PS			[string range $DB $hLen $marker-1]
		set M			[string range $DB $marker+1 end]

		# If pHash’ does not equal pHash, output "decoding error" and stop.
		if {$pHash ne ${pHash'}} {
			throw {decoding_error} "Hash mismatch"
		}

		# Output M.
		return $M
	}

	#>>>
	proc EMSA-PKCS1-V1_5-ENCODE {M emLen Hash} { #<<<
		# Implementation of section 9.2 of rfc3447
		#
		# Options:		Hash	- Hash function (hLen denotes the length in
		#						  octets of the hash function output)
		# Input:		M		- Message to be encoded
		#				emLen	- Intended length in octets of the encoded
		#						  message, at least tLen + 11, where tLen is
		#						  the octet length of the DER encoding T of a
		#						  certain value computed during the encoding
		#						  operation
		# Output:		EM		- Encoded message, an octet string of length
		#						  emLen
		# Throws:	message_too_long, emLen_too_short, padding_too_short

		set hLen	[apply $Hash output_len]

		# Apply the hash function to the message M to produce a hash value H:
		# H = Hash(M).
		#
		# If the hash function outputs "message too long," output "message
		# too long" and stop.
		set H		[apply $Hash hash $M]

		# Encode the algorithm ID for the hash function and the hash value
		# into an ASN.1 value of type DigestInfo (see Appendix A.2.4) with
		# the Distinguished Encoding Rules (DER), where the type DigestInfo
		# has the syntax
		#
		# DigestInfo ::= SEQUENCE {
		#     digestAlgorithm AlgorithmIdentifier,
		#     digest OCTET STRING
		# }
		#
		# The first field identifies the hash function and the second
		# contains the hash value.  Let T be the DER encoding of the
		# DigestInfo value (see the notes below) and let tLen be the length
		# in octets of T.
		set T [asn::asnSequence \
			[apply $Hash AlgorithmIdentifier] \
			[::asn::asnOctetString $H] \
		]
		#set T	[apply $Hash DigestInfoPrefix]$H
		set tLen	[string length $T]

		# If emLen < tLen + 11, output "intended encoded message length too
		# short" and stop.
		if {$emLen < $tLen + 11} {
			throw emLen_too_short "intended encoded message length too short"
		}

		# Generate an octet string PS consisting of emLen - tLen - 3 octets
		# with hexadecimal value 0xff.  The length of PS will be at least 8
		# octets.
		set PS	[string repeat \xff [expr {$emLen - $tLen - 3}]]
		if {[string length $PS] < 8} {
			# This check is reduntant given the emLen_too_short check
			throw padding_too_short "padding must be at least 8 octents, is: [string length $PS]"
		}

		# Concatenate PS, the DER encoding T, and other padding to form the
		# encoded message EM as
		# 
		#    EM = 0x00 || 0x01 || PS || 0x00 || T.
		set EM	""
		append EM	\0 \1 $PS \0 $T

		# Output EM.
		set EM
	}

	#>>>
	proc xor {a b} { #<<<
		binary scan $a cu* abytes
		binary scan $b cu* bbytes

		if {[string length $a] != [string length $b]} {
			error "xor a and b are different lengths: a([string length $a]) b([string length $b])"
		}
		set res	{}
		foreach abyte $abytes bbyte $bbytes {
			if {$abyte eq ""} {set abyte 0}
			if {$bbyte eq ""} {set bbyte 0}
			lappend res	[expr {$abyte ^ $bbyte}]
		}

		binary format c* $res
	}

	#>>>
	variable MGF [list {Z l Hash} { #<<<
		# Mask Generation Function
		# Options:	Hash		- hash function (hLen denotes the length in
		#						  octets of the hash function output)
		# Input:	Z			- seed from which mask is generated, an
		#						  octet string
		#			l			- intended length in octets of the mask, at
		#						  most 2³² * hLen
		# Output:	mask		- mask, an octet string of length l
		# Throws:	mask_too_long

		set hLen	[apply $Hash output_len]

		# If l > 2³² * hLen, output "mask too long" and stop
		if {$l > 2**32 * $hLen} {
			throw {mask_too_long} "Mask longer than 2**32 * hLen"
		}

		# Let T be the empty octet string
		set T	""
		set Z	$Z

		# For i = 0 to l/hLen − 1, do
		for {set i 0} {$i < int(ceil($l / double($hLen)))} {incr i} {
			# Convert i to an octet string C of length 4 with the primitive
			# I2OSP:
			#               C = I2OSP(i, 4)
			set C		[I2OSP $i 4]
			#set C		[binary format I $i]

			# Concatenate the hash of the seed Z and C to the octet string T:
			#               T = T || Hash(Z || C)
			append T	[apply $Hash hash $Z$C]
			#set h	[apply $Hash hash $Z$C]
			#append T	$h
		}

		# Output the leading l octets of T as the octet string mask
		return [string range $T 0 $l-1]
	} [namespace current]]

	#>>>
	proc modexp {b e n} { #<<<
		set r	1
		while {1} {
			if {$e & 1} {
				set r	[expr {($r * $b) % $n}]
			}
			set e	[expr {$e >> 1}]
			if {$e == 0} break
			set b	[expr {($b ** 2) % $n}]
		}

		return $r
	}

	#>>>
	proc RSAEP {n e m} { #<<<
		# RSA public key encryption
		# Input:	n	- RSA public key (modulus)
		#			e	- RSA public key (public exponent)
		#			m	- message representative, an integer between 0 and n-1
		# Output:	c	- ciphertext representative, an integer between
		#				  0 and n-1
		# Throws:	message_representative_out_of_range
		# Assumptions:
		#	- public key (n, e) is valid

		# If the message representative m is not between 0 and n − 1, output
		# "message representative out of range" and stop
		if {$m < 0 || $m > $n-1} {
			throw {message_representative_out_of_range} \
					"Message representative out of range"
		}

		# Let c = m**e % n
		#set c	[expr {$m**$e % $n}]
		set c	[modexp $m $e $n]

		# Output c
		return $c
	}

	#>>>
	proc RSADP {K c} { #<<<
		# RSA private key decryption
		# Input:	K	- RSA private key, in one of the following forms:
		#				  a list of (n, d)
		#				  a list of (p, q, dP, dQ, qInv)
		#					where:
		#					n		- modulus
		#					d		- private exponent
		#					p		- first prime factor of n
		#					q		- second prime factor of n
		#					dP		- p's exponent
		#					dQ		- q's exponent
		#					qInv	- Chinese Remainder Theorem coefficient
		#			c	- ciphertext representative, an integer between
		#				  0 and n-1
		# Output:	m	- message representative, an integer between 0 and n-1
		# Throws:	ciphertext_representative_out_of_range
		# Assumptions:
		#	- private key K is valid

		# If the first form (n, d) of K is used:
		if {[llength $K] == 2} {
			lassign $K n d

			# If the ciphertext representative c is not between 0 and n − 1,
			# output "ciphertext representative out of range" and stop
			if {$c < 0 || $c > $n+1} {
				throw {ciphertext_representative_out_of_range} \
						"Ciphertext representative out of range"
			}

			# Let m = c**d % n
			#set m	[expr {$c**$d % $n}]
			set m	[modexp $c $d $n]
		} else {
			# Else, if the second form (p, q, dP, dQ, qInv) of K is used:
			lassign $K p q dP dQ qInv
			set n	[expr {$p * $q}]

			# If the ciphertext representative c is not between 0 and n − 1,
			# output "ciphertext representative out of range" and stop
			if {$c < 0 || $c > $n-1} {
				throw {ciphertext_representative_out_of_range} \
						"Ciphertext representative out of range"
			}

			# Let m1 = c**dP % p
			#set m1	[expr {$c**$dP % $p}]
			set m1	[modexp $c $dP $p]

			# Let m2 = c**dQ % q
			#set m2	[expr {$c**$dQ % $q}]
			set m2	[modexp $c $dQ $q]

			# Let h = (m1 - m2) * qInv % p
			set h	[expr {($m1 - $m2) * $qInv % $p}]

			# Let m = m2 + q * h
			set m	[expr {$m2 + $q * $h}]
		}

		# Output m
		return $m
	}

	#>>>
	proc RSASP {n d m} { #<<<
		# RSA private key decryption
		# Input:	n	- modulus
		#			d	- private exponent
		#			m	- message representative, an integer between
		#				  0 and n-1
		# Output:	s	- ciphertext representative, an integer between
		#				  0 and n-1
		# Throws:	message_representative_out_of_range
		# Assumptions:
		#	- private key (d, n) is valid

		# If the message representative c is not between 0 and n − 1,
		# output "message representative out of range" and stop
		if {$m < 0 || $m > $n-1} {
			throw {message_representative_out_of_range} \
					"Message representative out of range"
		}

		# Let s = c**d % n
		modexp $m $d $n
	}

	#>>>
	proc RSAVP {n e s} { #<<<
		# RSA public key encryption
		# Input:	n	- RSA public key (modulus)
		#			e	- RSA public key (public exponent)
		#			s	- ciphertext representative, an integer between
		#				  0 and n-1
		# Output:	m	- message representative, an integer between
		#				  0 and n-1
		# Throws:	ciphertext_representative_out_of_range
		# Assumptions:
		#	- public key (n, e) is valid

		# If the ciphertext representative m is not between 0 and n − 1, output
		# "ciphertext representative out of range" and stop
		if {$s < 0 || $s > $n-1} {
			throw {ciphertext_representative_out_of_range} \
					"Ciphertext representative out of range"
		}

		# Let m = s**e % n
		modexp $s $e $n
	}

	#>>>
	proc RSAES-OAEP-Encrypt {n e M P Hash MGF} { #<<<
		# RSA Encrypt
		# Options:	Hash	- Hash function
		#			MGF		- Mask Generation Function
		# Input:	n		- recipient's RSA public key (modulus)
		#			e		- recipient's RSA public key (public exponent)
		#			M		- message to be encrypted, an octet string of length
		#					  at most k - 2 - 2hLen, where k is the length in
		#					  octets of the modulus n and hLen is the length in
		#					  octets of the hash function output for EME-OAEP
		#			P		- encoding parameters, an octet string that may be
		#					  empty
		# Output:	C		- ciphertext, an octet string of length k
		# Throws:	message_too_long
		# Assumptions:
		#	- public key (n, e) is valid
		variable debug

		set k		[expr {int(ceil([bitlength $n] / 8.0))}]

		if {$debug} {
			if {$M ne [testvec2os M]} {
				puts stderr "M doesn't match:\n[binary encode hex $M]\n[binary encode hex [testvec2os M]]"
			}
		}

		# 1. Apply the EME-OAEP encoding operation to the message M and the
		# encoding parameters P to produce an encoded message EM of length
		# k − 1 octets:
		#             EM = EME-OAEP-Encode(M, P, k − 1)
		# If the encoding operation outputs "message too long", then output
		# "message too long" and stop
		set EM	[EME-OAEP-Encode $M $P [expr {$k - 1}] $Hash $MGF]

		if {$debug} {
			if {$EM ne [testvec2os EM]} {
				puts stderr "EM doesn't match:\n[binary encode hex $EM]\n[binary encode hex [testvec2os EM]]"
			}
		}

		# 2. Convert the encoded message EM to an integer message
		# representative m:
		#             m = OS2IP(EM)
		set m	[OS2IP $EM]

		# 3. Apply the RSAEP encryption primitive to the public key (n, e) and
		# the message representative m to produce an integer ciphertext
		# representative c:
		#             c = RSAEP((n, e), m)
		set c	[RSAEP $n $e $m]

		# 4. Convert the ciphertext representative c to a ciphertext C of
		# length k octets:
		#             C = I2OSP(c, k)
		set C	[I2OSP $c $k]

		# 5. Output the ciphertext C
		return $C
	}

	#>>>
	proc RSAES-OAEP-Decrypt {K C P Hash MGF} { #<<<
		# RSA Decrypt
		# Options:		Hash	- Hash function used for EME-OAEP
		#				MGF		- Mask Generation Function used for EME-OAEP
		# Input:		K		- recipient's RSA private key, in one of the
		#						  forms described for RSADP
		#				C		- ciphertext to be decrypted, an octet string
		#						  of length k, where k is the length in octets
		#						  of the modulus n
		#				P		- encoding parameters, an octet string that may
		#						  be empty
		# Output:		M		- message, an octet string of length at most
		#						  k - 2 - 2*hLen, where hLen is the length in
		#						  octets of the hash function output for
		#						  EME-OAEP
		# Throws:	decryption_error
		# Assumptions:
		#	- private key K is valid

		if {[llength $K] == 2} {
			lassign $K n d
		} else {
			lassign $K p q dP dQ qInv
			set n	[expr {$p * $q}]
		}
		set k	[expr {int(ceil([bitlength $n]/8.0))}]

		# 1. If the length of the ciphertext C is not k octets, output
		# "decryption error" and stop
		if {[string length $C] != $k} {
			throw {decryption_error} "Ciphertext length is invalid"
		}

		# 2. Convert the ciphertext C to an integer ciphertext representative c
		#             c = OS2IP(C)
		set c	[OS2IP $C]

		# 3. Apply the RSADP decryption primitive to the private key K and the
		# ciphertext representative c to produce an integer message
		# representative m:
		#             m = RSADP(K, c)
		# If RSADP outputs "ciphertext representative out of range", then
		# output "decryption error" and stop
		try {
			set m	[RSADP $K $c]
		} trap {ciphertext_representative_out_of_range} {} {
			throw {decryption_error} "Ciphertext is out of range"
		}


		# Remark:
		# It is important that the errors in steps 4 and 5 are
		# indistinguishable, otherwise an adversary may be able to extract
		# useful information from the type of error occurred.  In particular,
		# the error messages in steps 4 and 5 must be identical.  Moreover, the
		# execution time of the decryption operation must not reveal whether an
		# error has occurred.  One way of achieving this is as follows: In case
		# of error in step 4, proceed to step 5 with EM set to a string of zero
		# octets.


		# 4. Convert the message representative m to an encoded message EM of
		# length k − 1 octets
		#             EM = I2OSP(m, k − 1)
		# If I2OSP outputs "integer too large", then output "decryption error"
		# and stop
		try {
			set EM		[I2OSP $m [expr {$k - 1}]]
		} trap {integer_too_large} {} {
			set EM		[string repeat \0 [expr {$k - 1}]]
		}

		# 5. Apply the EME-OAEP decoding operation to the encoded message EM
		# and the encoding parameters P to recover a message M:
		#             M = EME-OAEP-Decode(EM, P)
		# If the decoding operation outputs "decoding error", then output
		# "decryption error" and stop
		try {
			set M	[EME-OAEP-Decode $EM $P $Hash $MGF]
		} trap {decoding_error} {} {
			throw {decryption_error} "Decryption error"
		}

		# Output the message M
		return $M
	}

	#>>>
	proc RSAES-OAEP-Sign {n d M P Hash MGF} { #<<<
		# RSA Encrypt
		# Options:	Hash	- Hash function
		#			MGF		- Mask Generation Function
		# Input:	n		- our RSA private key (modulus)
		#			d		- our RSA private key (private exponent)
		#			M		- message to be encrypted, an octet string of length
		#					  at most k - 2 - 2hLen, where k is the length in
		#					  octets of the modulus n and hLen is the length in
		#					  octets of the hash function output for EME-OAEP
		#			P		- encoding parameters, an octet string that may be
		#					  empty
		# Output:	C		- ciphertext, an octet string of length k
		# Throws:	message_too_long
		# Assumptions:
		#	- public key (n, e) is valid
		variable debug

		set k		[expr {int(ceil([bitlength $n] / 8.0))}]

		if {$debug} {
			if {$M ne [testvec2os M]} {
				puts stderr "M doesn't match:\n[binary encode hex $M]\n[binary encode hex [testvec2os M]]"
			}
		}

		# 1. Apply the EME-OAEP encoding operation to the message M and the
		# encoding parameters P to produce an encoded message EM of length
		# k − 1 octets:
		#             EM = EME-OAEP-Encode(M, P, k − 1)
		# If the encoding operation outputs "message too long", then output
		# "message too long" and stop
		set EM	[EME-OAEP-Encode $M $P [expr {$k - 1}] $Hash $MGF]

		if {$debug} {
			if {$EM ne [testvec2os EM]} {
				puts stderr "EM doesn't match:\n[binary encode hex $EM]\n[binary encode hex [testvec2os EM]]"
			}
		}

		# 2. Convert the encoded message EM to an integer message
		# representative m:
		#             m = OS2IP(EM)
		set m	[OS2IP $EM]

		# 3. Apply the RSAEP encryption primitive to the public key (n, e) and
		# the message representative m to produce an integer ciphertext
		# representative c:
		#             c = RSASP((n, d), m)
		set c	[RSASP $n $d $m]

		# 4. Convert the ciphertext representative c to a ciphertext C of
		# length k octets:
		#             C = I2OSP(c, k)
		set C	[I2OSP $c $k]

		# 5. Output the ciphertext C
		return $C
	}

	#>>>
	proc RSAES-OAEP-Verify {n e C P Hash MGF} { #<<<
		# RSA Decrypt
		# Options:		Hash	- Hash function used for EME-OAEP
		#				MGF		- Mask Generation Function used for EME-OAEP
		# Input:		e		- sender's RSA public key, public exponent
		#				n		- sender's RSA public key, modulus
		#				C		- ciphertext to be decrypted, an octet string
		#						  of length k, where k is the length in octets
		#						  of the modulus n
		#				P		- encoding parameters, an octet string that may
		#						  be empty
		# Output:		M		- message, an octet string of length at most
		#						  k - 2 - 2*hLen, where hLen is the length in
		#						  octets of the hash function output for
		#						  EME-OAEP
		# Throws:	decryption_error
		# Assumptions:
		#	- private key K is valid

		set k	[expr {int(ceil([bitlength $n]/8.0))}]

		# 1. If the length of the ciphertext C is not k octets, output
		# "decryption error" and stop
		if {[string length $C] != $k} {
			throw {decryption_error} "Ciphertext length is invalid"
		}

		# 2. Convert the ciphertext C to an integer ciphertext representative c
		#             c = OS2IP(C)
		set c	[OS2IP $C]

		# 3. Apply the RSADP decryption primitive to the private key K and the
		# ciphertext representative c to produce an integer message
		# representative m:
		#             m = RSAVP(n, e, c)
		# If RSADP outputs "ciphertext representative out of range", then
		# output "decryption error" and stop
		try {
			set m	[RSAVP $n $e $c]
		} trap {ciphertext_representative_out_of_range} {} {
			throw {decryption_error} "Ciphertext is out of range"
		}


		# Remark:
		# It is important that the errors in steps 4 and 5 are
		# indistinguishable, otherwise an adversary may be able to extract
		# useful information from the type of error occurred.  In particular,
		# the error messages in steps 4 and 5 must be identical.  Moreover, the
		# execution time of the decryption operation must not reveal whether an
		# error has occurred.  One way of achieving this is as follows: In case
		# of error in step 4, proceed to step 5 with EM set to a string of zero
		# octets.


		# 4. Convert the message representative m to an encoded message EM of
		# length k − 1 octets
		#             EM = I2OSP(m, k − 1)
		# If I2OSP outputs "integer too large", then output "decryption error"
		# and stop
		try {
			set EM		[I2OSP $m [expr {$k - 1}]]
		} trap {integer_too_large} {} {
			set EM		[string repeat \0 [expr {$k - 1}]]
		}

		# 5. Apply the EME-OAEP decoding operation to the encoded message EM
		# and the encoding parameters P to recover a message M:
		#             M = EME-OAEP-Decode(EM, P)
		# If the decoding operation outputs "decoding error", then output
		# "decryption error" and stop
		try {
			set M	[EME-OAEP-Decode $EM $P $Hash $MGF]
		} trap {decoding_error} {} {
			throw {decryption_error} "Decryption error"
		}

		# Output the message M
		return $M
	}

	#>>>
	proc RSASSA-PKCS1-V1_5-SIGN {K M Hash} { #<<<
		# Implementation of section 8.2.1 of rfc3447
		#
		# Input:	K		- Signer's RSA private key
		#			M		- Message to be signed, an octet string
		# Output:	S		- Signature, an octet string of length k, where k
		#					  is the length in octets of the RSA modulus n
		# Throws: message_too_long, RSA_modulus_too_short
		# Assumptions:
		#	- private key K is valid

		set k	[expr {[bitlength [dict get $K n]] / 8}]

		# EMSA-PKCS1-v1_5 encoding: Apply the EMSA-PKCS1-v1_5 encoding
		# operation (Section 9.2) to the message M to produce an encoded
		# message EM of length k octets:
		#
		#    EM = EMSA-PKCS1-V1_5-ENCODE (M, k).
		#
		# If the encoding operation outputs "message too long," output
		# "message too long" and stop.  If the encoding operation outputs
		# "intended encoded message length too short," output "RSA modulus
		# too short" and stop.
		try {
			set EM	[EMSA-PKCS1-V1_5-ENCODE $M $k $Hash]
		} trap message_too_long {} {
			# This is redundant, but made explicit here to match the rfc
			throw message_too_long "message too long"
		} trap emLen_too_short {} {
			throw RSA_modulus_too_short "RSA modulus too short"
		}

		# RSA signature:
		#
		# a. Convert the encoded message EM to an integer message
		#    representative m (see Section 4.2):
		#
		#       m = OS2IP (EM).
		set m	[OS2IP $EM]

		# b. Apply the RSASP1 signature primitive (Section 5.2.1) to the RSA
		#    private key K and the message representative m to produce an
		#    integer signature representative s:
		#
		#       s = RSASP1 (K, m).
		set s	[RSASP [dict get $K n] [dict get $K d] $m]

		# c. Convert the signature representative s to a signature S of
		#    length k octets (see Section 4.1):
		#
		#       S = I2OSP (s, k).
		set S	[I2OSP $s $k]

		# Output the signature S.
		set S
	}

	#>>>
	proc RSAKG {L e} { #<<<
		# Generate an RSA key pair
		# Input:	L	- the desired bit length for the modulus
		#			e	- the public exponent, an odd integer greater than 1
		# Output:	K	- a valid private key pair containing the fields:
		#					n		- modulus
		#					e		- public exponent
		#					d		- private exponent
		#					p		- first prime factor of n
		#					q		- second prime factor of n
		#					dP		- p's exponent
		#					dQ		- q's exponent
		#					qInv	- Chinese Remainder Theorem coefficient
		# Assumptions:
		#	- L is even
		#	- L is an integer power of 2 (and therefore that L % 2 == 0)

		# Generate a prime p such that
		# ⌊2**((L−1)/2)⌋ + 1 ≤ p ≤ ⌈2**(L/2)⌉ − 1
		# and such that GCD(p, e) = 1 using PG with input
		# (⌊2**((L−1)/2)⌋ + 1, ⌈2**(L/2)⌉ − 1, e)
		lassign [prime_range $L] prime_lower prime_upper
		set p	[PG $prime_lower $prime_upper $e]

		# Generate a prime q such that
		# ⌊2**((L−1)/2)⌋ + 1 ≤ q ≤ ⌈2**(L/2)⌉ − 1
		# and such that GCD(q, e) = 1 using PG with input
		# (⌊2**((L−1)/2)⌋ + 1, ⌈2**(L/2)⌉ − 1, e)
		set q	[PG $prime_lower $prime_upper $e]

		set n	[expr {$p * $q}]

		# Compute d, dP dQ qInv via Extended Euclidean Algorithm

		# Find d where de ≡ 1 (mod φ(n))
		# φ(n) = (p-1)(q-1)
		set φn	[expr {($p-1) * ($q-1)}]
		# ed ≡ 1 (mod φ(n))
		# d ≡ e⁻¹ (mod φ(n))
		lassign [extended_gcd $e [set φn]] d -> gcd
		set d		[expr {$d % [set φn]}]
		set dP		[expr {$d % ($p-1)}]
		set dQ		[expr {$d % ($q-1)}]
		# q·q⁻¹ ≡ 1 (mod p)
		set qInv	[expr {[lindex [extended_gcd $q $p] 0] % $p}]

		dict set K p	$p
		dict set K q	$q
		dict set K n	$n
		dict set K e	$e
		dict set K d	$d
		dict set K dP	$dP
		dict set K dQ	$dQ
		dict set K qInv	$qInv

		return $K
	}

	#>>>
	proc prime_range {modulus_bitlength} { #<<<
		set lower	[expr {isqrt((2**(($modulus_bitlength-1)/2))**2 * 2) + 1}]
		set upper	[expr {2**($modulus_bitlength/2) - 1}]
		return [list $lower $upper]
	}

	#>>>
	proc extended_gcd {a b} { #<<<
		set x		0
		set y		1
		set lastx	1
		set lasty	0
		while {$b != 0} {
			set quotient	[expr {$a / $b}]
			set temp		$b
			set b			[expr {$a % $b}]
			set a			$temp

			set temp		$x
			set x			[expr {$lastx - $quotient*$x}]
			set lastx		$temp

			set temp		$y
			set y			[expr {$lasty - $quotient*$y}]
			set lasty		$temp
		}

		return [list $lastx $lasty $a]
	}

	#>>>
	proc bitlength {num} { #<<<
		# floating point issues cause the log based implementation to become
		# inaccurate around num = 2**47-1
		#expr {int(log($num) / log(2))+1}

		set i	1
		while {[set num [expr {$num >> 1}]] > 0} {
			incr i
		}

		return $i
	}

	#>>>
	proc rand_odd_int {lower higher} { #<<<
		# Reduce the bias for the first (256 % $half_range)*2 choices to 2⁻³²
		set extra		32

		set range		[expr {$higher - $lower}]
		set half_range	[expr {$range >> 1}]
		set bytes	[expr {int(ceil(([bitlength $half_range]+$extra) / 8.0))}]
		#set base	[OS2IP [random_bytes $bytes]]
		set base	[OS2IP [crypto::blowfish::csprng $bytes]]
		# Although $base<<1 is always even, modulo ($range+1) can make it odd
		# again, which is then overcorrected for by the (1-($lower % 2))
		#expr {(($base<<1) % ($range+1)) + $lower + (1 - ($lower % 2))}
		expr {(($base % ($half_range+1)) << 1) + $lower + (1 - ($lower % 2))}
	}

	#>>>
	proc rand_int {lower higher} { #<<<
		# Reduce the bias for the first (256 % $range) choices to 2⁻³²
		set extra		32

		set range		[expr {$higher - $lower}]
		set bytes	[expr {int(ceil(([bitlength $range]+$extra) / 8.0))}]
		#set base	[OS2IP [random_bytes $bytes]]
		set base	[OS2IP [crypto::blowfish::csprng $bytes]]
		expr {($base % ($range+1)) + $lower}
	}

	#>>>
	proc PG {r s e} { #<<<
		variable smallprimes

		# Generate a prime in the interval [$r, $s] such that GCD(p-1, e) = 1
		# Input:	r	- the lower bound for the prime to be generated
		#			s	- the upper bound for the prime to be generated
		#			e	- an odd positive integer
		# Output:	p	- an odd random prime uniformly chosen from the
		#				  interval [r, s] such that GCD(p-1, e) = 1
		# Assumptions:
		#	- r, s are the same bitlength

		set e_factors	[factors [expr {$e}]]
		if {[llength $e_factors] == 2} {
			set e_is_prime	1
		} else {
			set e_is_prime	0
		}

		set bitlength	[bitlength $r]

		if {$bitlength >= 1024} {
			set t	4
		} elseif {$bitlength >= 768} {
			set t	5
		} elseif {$bitlength >= 683} {
			set t	6
		} elseif {$bitlength >= 512} {
			set t	8
		} elseif {$bitlength >= 410} {
			set t	10
		} elseif {$bitlength >= 384} {
			set t	11
		} elseif {$bitlength >= 342} {
			set t	12
		} elseif {$bitlength >= 256} {
			set t	17
		} else {
			error "Requested bitlength too small: $bitlength"
		}

		while {1} {
			# 1. Generate a random odd integer p uniformly from the interval
			# [r − 2, s − 2]
			set p	[rand_odd_int [expr {$r-2}] [expr {$s-2}]]
			if {$p % 2 == 0} {
				puts stderr "asked for a random odd integer and got $p"
				incr p
			}

			try {
				while {1} {
					# 2. Set p ← p + 2
					incr p 2

					try {
						# 3. If p is divisible by any of the, say, 2000
						# smallest primes, return to step 2
						foreach prime $smallprimes {
							if {$p % $prime == 0} {
								throw {failed} "candidate is a multiple of small prime $prime:\n$p"
							}
						}

						# 4. If GCD(p − 1, e) != 1, then return to step 2
						# even if e is prime, it might be a factor of p-1 itself
						foreach factor [lrange $e_factors 1 end] {
							if {($p - 1) % $factor == 0} {
								throw {failed} "candidate not coprime with e"
							}
						}

						# 5. Let v, w be such that w is odd and p − 1 = w*(2**v)
						# w = (p - 1)/(2**v)
						# (p - 1)/w = 2**v
						set found	0
						#for {set v $bitlength} {$v >= 1} {incr v -1}
						for {set v 1} {$v <= $bitlength} {incr v} {
							set vp	[expr {2**$v}]
							set rem	[expr {($p-1) % $vp}]
							#puts "trying v=$v: remain: $rem"
							if {$rem == 0} {
								set w	[expr {($p-1) / $vp}]
								#puts "\ttrying w: $w"
								if {$w % 2 == 1} {
									set found	1
									break
								}
							}
						}
						if {!($found)} {
							error "Couldn't find v and w such that w is odd and p - 1 = w*(2**v)"
						}

						# 6. Choose a positive integer t such that the
						# primality test in step 8 is successful with a
						# sufficiently large probability (see Remark 1 below)
						# - Chosen above

						# 7. Set i ← 1
						set i	1

						# 8. While i ≤ t do
						while {$i <= $t} {
							# 8.1. Generate a random integer uniformly from
							# the interval [1, p − 1]
							set a	[rand_int 1 [expr {$p-1}]]

							# 8.2. Set b ← a**w mod p
							#set b	[expr {$a**$w % $p}]
							set b	[modexp $a $w $p]

							# 8.3. If b = 1 or b = p − 1, then go to step 8.6
							if {$b == 1 || $b == $p - 1} {
								incr i
								continue
							}

							# 8.4. Set j ← 0
							set j	0

							# 8.5. While b != p − 1 do
							while {$b != $p - 1} {
								# 8.5.1. Set j ← j + 1
								incr j

								# 8.5.2. If j = v, then return to step 2 (p is
								# composite)
								if {$j == $v} {
									throw {failed} "candidate is composite (j=v)"
								}

								# 8.5.3. Set b ← b² mod p (= a**(w(2**j)) mod p)
								#set b	[expr {($b**2) % $p}]
								set b	[modexp $b 2 $p]

								# 8.5.4. If b = 1, then return to step 2 (p is
								# composite)
								if {$b == 1} {
									throw {failed} "candidate is composite (b=1)"
								}
							}

							# 8.6. Set i ← i + 1
							incr i
						}

						# 9. If p is greater than s, return to step 1
						if {$p > $s} {
							throw {epic_fail} "overran range searching for prime"
						}
					} trap {failed} {errmsg} {
						#puts "fail: $errmsg"
						continue
					}

					# 10. Output p
					return $p
				}
			} trap {epic_fail} {errmsg} {
				#puts "epic fail: $errmsg, trying again"
				continue
			}
		}

		# Remarks.
		#  1. The Miller-Rabin primality test in step 8 is a probabilistic
		#  test, which means that there is a small chance that an error occurs,
		#  i.e., a random composite number passes the test. For a randomly
		#  chosen candidate this error has been estimated in [I. Damgard, P.
		#  Landrock, and C. Pomerance. Average case error estimates for the
		#  strong probable prime test. Mathematics of Computation, 61:
		#  177--194, (1993)]; to achieve an error probability less than 2⁻¹⁰⁰
		#  for a random k -bit integer, it suffices to choose the parameter t
		#  in accordance with the following table.
		#		k	256	342	384	410	512	683	768	1024
		#		t	17	12	11	10	8	6	5	4
		#  342 = ceil(1024/3), 410 = ceil(2048/5) and 683 = ceil(2048/3) are
		#  included for completeness, being typical values in the multi-prime
		#  setting
		#
		#  2. Step 8.5 in the Miller-Rabin primality test is based on the
		#  following facts: If p is a prime, then a**(p−1) ≡ 1 (mod p).  If,
		#  in addition, t is even and satisfies a**t ≡ 1 (mod p), then
		#  a**(t/2) ≡ ±1 (mod p)
		#
		#  3. To check whether p is divisible by any of the smallest primes
		#  p1, p2, . . ., p2000, we have to compute the remainder ri when p is
		#  divided by pi; if ri = 0 for some i, then p is not a prime.  Yet,
		#  we need to perform this trial division only once for each prime pi;
		#  when p is replaced with p + 2, just replace ri with (ri + 2) mod pi
		#
		#  4. Instead of increasing the value of p in steps of 2 until a prime
		#  is found, one may generate a brand new random integer each time a
		#  number p proves to be composite.  In this manner, the prime
		#  eventually found will be chosen uniformly at random; an ostensible
		#  drawback with incremental search is that the prime eventually found
		#  will no longer be uniformly chosen (primes preceded by a big "gap"
		#  containing no primes will be chosen with a larger probability than
		#  other primes).  Yet, Brandt and Damgard [J. Brandt and I. Damgard.
		#  On generation of probable primes by incremental search. In, E.F.
		#  Brickell, editor, Advances in Cryptology -- Crypto’92, pages
		#  358--370. Springer-Verlag, 1993] have shown that this bias does not
		#  affect security.  Moreover, with the alternative approach, we cannot
		#  simplify our computations in the way described in Remark 3.
		#
		#  5. A practical method for generating a number p nearly uniformly
		#  from an interval [r, s] is as follows.  Let M be the bitlength of s
		#  and let m be a suitably chosen number, for example, m = 32.
		#  Generate an (M + m)-bit random integer x uniformly from the interval
		#  [0, 2**(M+m) − 1] and put
		#                    p = (x mod (s − r + 1)) + r
		#  The extra m bits of x are included to make p more uniformly
		#  distributed over the interval [r, s]; any of the most probable
		#  integers (which are at the beginning of the interval) will be chosen
		#  with probability at most 1 + 2**−m times the probability for any of
		#  the least probable integers (which are at the end of the interval).
	}

	#>>>
	proc GCD {a b} { #<<<
		# Return the Greatest Common Denominator of both a and b

		if {$a > $b} {
			set small	$b
			set large	$a
		} else {
			set small	$a
			set large	$b
		}

		set upper	[expr {isqrt($small)}]

		# This is going to hurt for really large values of $small
		for {set i $upper} {$i > 1} {incr i -1} {
			if {
				$small % $i == 0 &&
				$large % $i == 0
			} {
				return $i
			}
		}

		return 1
	}

	#>>>
	proc relprime {a b} { #<<<
		# Return true if a and b share a factor greater than 1

		if {$a > $b} {
			set small	$b
			set large	$a
		} else {
			set small	$a
			set large	$b
		}

		set upper	[expr {isqrt($small)}]

		# Use sort of a heuristic seive, skipping multiples of 2 and 3
		# Reduces the set to search by a factor of 3
		# Extending to multiples of 5 gives a periodicity of 30, testing
		# 8 cendidates each loop for a saving factor of 3.75

		# doesn't actually have to be prime, but computation is wasted building
		# the primes list if it isn't.  Must be >= 2
		set highestprime 13

		set seive	[lrepeat [expr {$highestprime+1}] 1]
		lset seive 0 0	;# every integer % 1 == 0
		# build the primes up to highestprime with a sieve
		set primeset	{}
		for {set i 2} {$i <= ($highestprime >> 1)} {incr i} {
			if {![lindex $seive $i]} {
				#puts "$i was eliminated by one of $primeset"
				continue
			}
			for {set j [expr {$i<<1}]} {$j <= $highestprime} {incr j $i} {
				# Eliminate this prime's multiples
				#puts "eliminating $j as a multiple of $i"
				lset seive $j 0
			}
			lappend primeset	$i
		}
		for {} {$i <= $highestprime} {incr i} {
			if {[lindex $seive $i]} {
				lappend primeset $i
			}
		}
		#puts "primeset: $primeset"
		set highestprime	[lindex $primeset end]
		#puts "highestprime: $highestprime"

		set periodicity		[tcl::mathop::* {*}$primeset]
		#puts "periodicity: $periodicity"

		# Seive the multiples of the members of the primeset from the testset
		# to get the skip intervals
		set testset			[lrepeat $periodicity 1]
		lset testset 0 0
		set testcount	0
		foreach prime $primeset {
			incr testcount
			if {
				$small % $prime == 0 &&
				$large % $prime == 0
			} {
				#puts "not coprime: share factor $prime (needed $testcount tests)"
				return 0
			}
			for {set j $prime} {$j <= $periodicity} {incr j $prime} {
				lset testset $j 0
			}
		}
		#puts "testset: $testset"

		# Find the first un-eliminated member of the test set
		set skiplist	{}
		set skip		2
		for {set i 3} {$i < $periodicity} {incr i 2; incr skip 2} {
			if {[lindex $testset $i]} {
				lappend skiplist	$skip
				set skip			0
			}
		}
		lappend skiplist	$skip	; # Not certain about this
		set skiplistlen	[llength $skiplist]
		#puts "skiplistlen: $skiplistlen"

		# Sanity check
		if {[tcl::mathop::+ {*}$skiplist] != $periodicity} {
			throw {sanity_check_failed} "Programmer logic error detected"
		}

		set i	[expr {1 + [lindex $skiplist 0]}]
		set si	[expr {1 % $skiplistlen}]

		# Note that this is trivially parallelizable by looping in increments
		# of $threads * $periodicity and on each interation testing each
		# interval of $periodicity in it's own thread

		# This is going to hurt for really large values of $small
		while {$i <= $upper} {
			incr testcount
			if {
				$small % $i == 0 &&
				$large % $i == 0
			} {
				#puts "not coprime: share factor $i (needed $testcount tests)"
				return 0
			}
			incr i	[lindex $skiplist $si]
			set si	[expr {($si + 1) % $skiplistlen}]
		}

		#puts "are coprime (needed $testcount tests)"
		return 1
	}

	#>>>
	proc factors {a} { #<<<
		# Return integer factors of a
		set factors	{1}

		set upper	[expr {isqrt($a)}]
		#puts "searching for factors to upper bound $upper"

		# Use sort of a heuristic seive, skipping multiples of 2 and 3
		# Reduces the set to search by a factor of 3
		# Extending to multiples of 5 gives a periodicity of 30, testing
		# 8 cendidates each loop for a saving factor of 3.75

		# doesn't actually have to be prime, but computation is wasted building
		# the primes list if it isn't.  Must be >= 2
		set highestprime [expr {min(17, $a-1)}]

		set seive	[lrepeat [expr {$highestprime+1}] 1]
		lset seive 0 0	;# every integer % 1 == 0
		# build the primes up to highestprime with a sieve
		set primeset	{}
		for {set i 2} {$i <= ($highestprime >> 1)} {incr i} {
			if {![lindex $seive $i]} continue
			for {set j [expr {$i<<1}]} {$j <= $highestprime} {incr j $i} {
				# Eliminate this prime's multiples
				lset seive $j 0
			}
			lappend primeset	$i
		}
		for {} {$i <= $highestprime} {incr i} {
			if {[lindex $seive $i]} {
				lappend primeset $i
			}
		}
		#puts "primeset: $primeset"
		set highestprime	[lindex $primeset end]
		#puts "highestprime: $highestprime"

		set periodicity		[tcl::mathop::* {*}$primeset]
		#puts "periodicity: $periodicity"

		# Seive the multiples of the members of the primeset from the testset
		# to get the skip intervals
		set testset			[lrepeat $periodicity 1]
		lset testset 0 0
		set testcount	0
		foreach prime $primeset {
			incr testcount
			if {$a % $prime == 0} {
				lappend factors	$prime
			}
			for {set j $prime} {$j <= $periodicity} {incr j $prime} {
				lset testset $j 0
			}
		}
		#puts "testset: $testset"

		# Find the first un-eliminated member of the test set
		set skiplist	{}
		set skip		2
		for {set i 3} {$i < $periodicity} {incr i 2; incr skip 2} {
			if {[lindex $testset $i]} {
				lappend skiplist	$skip
				set skip			0
			}
		}
		lappend skiplist	$skip	; # Not certain about this
		set skiplistlen	[llength $skiplist]
		#puts "skiplistlen: $skiplistlen"
		set avgskip	[expr {$periodicity / double($skiplistlen)}]
		#puts "avgskip: $avgskip"
		set expectedtests	[expr {$upper / $avgskip}]
		#puts "expecting $expectedtests"
		set repintvl	[expr {round($expectedtests / 10.0)}]

		# Sanity check
		if {[tcl::mathop::+ {*}$skiplist] != $periodicity} {
			throw {sanity_check_failed} "Programmer logic error detected"
		}

		set i	[expr {1 + [lindex $skiplist 0]}]
		set si	[expr {1 % $skiplistlen}]

		# Note that this is trivially parallelizable by looping in increments
		# of $threads * $periodicity and on each interation testing each
		# interval of $periodicity in it's own thread

		# This is going to hurt for really large values of $small
		while {$i <= $upper} {
			incr testcount
			if {$a % $i == 0} {
				lappend factors $i
			}
			incr i	[lindex $skiplist $si]
			set si	[expr {($si + 1) % $skiplistlen}]
			#if {$testcount % $repintvl == 0} {
			#	puts [format "%.1f %%" [expr {100 * $testcount / $expectedtests}]]
			#}
		}

		lappend factors $a
		#puts "required $testcount tests to find [llength $factors] factors"
		return $factors
	}

	#>>>
	proc load_asn1_pubkey {fn} { #<<<
		set h	[open $fn r]
		set dat	[chan read $h]
		close $h

		load_asn1_pubkey_from_value $dat
	}

	#>>>
	proc load_asn1_pubkey_from_value {dat} { #<<<
		try {
			lsort [dict keys $dat]
		} on ok {keys} {
			if {$keys eq [lsort {n e}]} {
				return $dat
			}
		} on error {} {}

		set base64_key	""
		set inkey		0
		foreach line [split $dat \n] {
			if {!($inkey)} {
				if {$line eq "-----BEGIN RSA PUBLIC KEY-----"} {
					set inkey	1
					continue
				}
			} else {
				if {$line eq "-----END RSA PUBLIC KEY-----"} {
					set inkey	0
					break
				}
				append base64_key	$line
			}
		}

		set raw_key	[binary decode base64 $base64_key]

		set K		[dict create]
		set sequence	[asnGetSequence raw_key]
		dict set K n	[asnGetInteger sequence]
		dict set K e	[asnGetInteger sequence]

		return $K
	}

	#>>>
	proc asnGetInteger {bytesvar} { #<<<
		upvar $bytesvar bytes

		set ofs		0
		# GetByte <<<
		set tag		[string index $bytes $ofs]
		if {$tag ne "\x02"} {
			throw {parse_error} "Expect an integer tag at ofs $ofs, got [binary encode hex $tag]"
		}
		incr ofs
		# GetByte >>>

		# GetLength <<<
		binary scan [string index $bytes $ofs] cu length
		if {$length == 0x80} {
			throw {parse_error} "Indefinite length BER encoding not yet supported"
		}
		incr ofs
		if {$length > 0x80} {
			set len_length	[expr {$length & 0x7f}]
			if {[string length $bytes] < $len_length + $ofs} {
				throw {parse_error} "length information is invalid, not enough octets left"
			}

			# GetBytes <<<
			set intbytes	[string range $bytes $ofs [expr {$ofs+$len_length-1}]]
			incr ofs $len_length
			# GetBytes >>>

			switch -- $len_length {
				1 {binary scan $intbytes cu length}
				2 {binary scan $intbytes Su length}
				3 {binary scan \x00$intbytes Iu length}
				4 {binary scan $intbytes Iu length}
				default {
					scan [binary encode hex $intbytes] %llx length
				}
			}
		}
		# GetLength >>>

		# GetBytes <<<
		set osi	[string range $bytes $ofs [expr {$ofs+$length-1}]]
		set integer	[OS2IP $osi]
		incr ofs $length
		# GetBytes >>>

		set bytes	[string range $bytes $ofs end]

		return $integer
	}

	#>>>
	proc asnGetLength {bytesvar ofsvar} { #<<<
		upvar $bytesvar bytes
		upvar $ofsvar ofs

		binary scan [string index $bytes $ofs] cu length
		if {$length == 0x80} {
			throw {parse_error} "Indefinite length BER encoding not yet supported"
		}
		incr ofs
		if {$length > 0x80} {
			set len_length	[expr {$length & 0x7f}]
			if {[string length $bytes] < $len_length + $ofs} {
				throw {parse_error} "length information is invalid, not enough octets left"
			}

			# GetBytes <<<
			set intbytes	[string range $bytes $ofs [expr {$ofs+$len_length-1}]]
			incr ofs $len_length
			# GetBytes >>>

			switch -- $len_length {
				1 {binary scan $intbytes cu length}
				2 {binary scan $intbytes Su length}
				3 {binary scan \x00$intbytes Iu length}
				4 {binary scan $intbytes Iu length}
				default {
					scan [binary encode hex $intbytes] %llx length
				}
			}
		}

		set length
	}

	#>>>
	proc asnGetOctetString {bytesvar} { #<<<
		upvar $bytesvar bytes

		set ofs		0
		# GetByte <<<
		set tag	[string index $bytes $ofs]
		if {$tag ne "\x04"} {
			throw {parse_error} "Expect a sequence tag at ofs $ofs, got [binary encode hex $tag]"
		}
		incr ofs
		# GetByte >>>

		# GetLength <<<
		set seqlength	[asnGetLength bytes ofs]
		# GetLength >>>

		# GetBytes <<<
		set sequence	[string range $bytes $ofs [expr {$ofs+$seqlength-1}]]
		incr ofs $seqlength
		# GetBytes >>>

		set bytes	[string range $bytes $ofs end]

		return $sequence
	}

	#>>>
	proc asnGetSequence {bytesvar} { #<<<
		upvar $bytesvar bytes

		set ofs		0
		# GetByte <<<
		set tag	[string index $bytes $ofs]
		if {$tag ne "\x30"} {
			throw {parse_error} "Expect a sequence tag at ofs $ofs, got [binary encode hex $tag]"
		}
		incr ofs
		# GetByte >>>

		# GetLength <<<
		set seqlength	[asnGetLength bytes ofs]
		# GetLength >>>

		# GetBytes <<<
		set sequence	[string range $bytes $ofs [expr {$ofs+$seqlength-1}]]
		incr ofs $seqlength
		# GetBytes >>>

		set bytes	[string range $bytes $ofs end]

		return $sequence
	}

	#>>>
	proc load_asn1_prkey {fn} { #<<<
		set h	[open $fn r]
		set dat	[chan read $h]
		close $h

		try {
			lsort [dict keys $dat]
		} on ok {keys} {
			if {$keys eq [lsort {n e d p q dP dQ qInv}]} {
				return $dat
			}
		} on error {} {}

		set base64_key	""
		set inkey		0
		foreach line [split $dat \n] {
			if {!($inkey)} {
				if {$line eq "-----BEGIN RSA PRIVATE KEY-----"} {
					set inkey	1
					continue
				}
			} else {
				if {$line eq "-----END RSA PRIVATE KEY-----"} {
					set inkey	0
					break
				}
				append base64_key	$line
			}
		}

		set raw_key	[binary decode base64 $base64_key]

		set K	[dict create]

		set sequence		[asnGetSequence raw_key]
		set version			[asnGetInteger sequence]
		dict set K n			[asnGetInteger sequence]
		dict set K e			[asnGetInteger sequence]
		dict set K d			[asnGetInteger sequence]
		dict set K p			[asnGetInteger sequence]
		dict set K q			[asnGetInteger sequence]
		dict set K dP			[asnGetInteger sequence]
		dict set K dQ			[asnGetInteger sequence]
		dict set K qInv			[asnGetInteger sequence]

		return $K
	}

	#>>>

	variable sha1 {{cmd args} { #<<<
		switch -- $cmd {
			input_limit	{return [expr {2**61-1}]}
			output_len	{return 20}
			AlgorithmIdentifier {
				package require asn
				asn::asnSequence \
					[asn::asnObjectIdentifier {1 3 14 3 2 26}] \
					]asn::asnNull]
			}
			DigestInfoPrefix {
				binary decode hex {30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14}
			}
			hash {
				package require sha1

				set in	[lindex $args 0]
				return [sha1::sha1 -bin $in]
			}
			default {throw {invalid_cmd} "Invalid hash command"}
		}
	}}

	#>>>
	variable sha256 {{cmd args} { #<<<
		switch -- $cmd {
			input_limit	{return [expr {2**64-1}]}
			output_len	{return 32}
			AlgorithmIdentifier {
				package require asn
				asn::asnSequence \
					[asn::asnObjectIdentifier {2 16 840 1 101 3 4 2 1}] \
					[asn::asnNull]
			}
			DigestInfoPrefix {
				binary decode hex {30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20}
			}
			hash {
				package require hash
				binary decode hex [hash::sha256 [lindex $args 0]]
			}
			default {
				throw invalid_cmd "Invalid hash command"
			}
		}
	}}

	#>>>
	proc random_bytes {bytecount} { #<<<
		#set h	[open /dev/random r]
		#puts stderr "WARNING: fudging random numbers.  Under no circumstances allow this into production"
		set h	[open /dev/urandom r]
		try {
			chan configure $h -translation binary -encoding binary
			#puts "reading $bytecount random bytes"
			chan read $h $bytecount
		} finally {
			catch {chan close $h}
		}
	}

	#>>>

	# Test vectors <<<

	# Integers are represented by strings of octets with the leftmost octet
	# being the most significant octet.  For example, 9202000 = 8c 69 50.

	set test_vectors {
		n {
			bb f8 2f 09 06 82 ce 9c 23 38 ac 2b 9d a8 71 f7 36 8d 07 ee d4 10
			43 a4 40 d6 b6 f0 74 54 f5 1f b8 df ba af 03 5c 02 ab 61 ea 48 ce
			eb 6f cd 48 76 ed 52 0d 60 e1 ec 46 19 71 9d 8a 5b 8b 80 7f af b8
			e0 a3 df c7 37 72 3e e6 b4 b7 d9 3a 25 84 ee 6a 64 9d 06 09 53 74
			88 34 b2 45 45 98 39 4e e0 aa b1 2d 7b 61 a5 1f 52 7a 9a 41 f6 c1
			68 7f e2 53 72 98 ca 2a 8f 59 46 f8 e5 fd 09 1d bd cb
		}

		e {
			11
		}

		p {
			ee cf ae 81 b1 b9 b3 c9 08 81 0b 10 a1 b5 60 01 99 eb 9f 44 ae f4
			fd a4 93 b8 1a 9e 3d 84 f6 32 12 4e f0 23 6e 5d 1e 3b 7e 28 fa e7
			aa 04 0a 2d 5b 25 21 76 45 9d 1f 39 75 41 ba 2a 58 fb 65 99
		}

		q {
			c9 7f b1 f0 27 f4 53 f6 34 12 33 ea aa d1 d9 35 3f 6c 42 d0 88 66
			b1 d0 5a 0f 20 35 02 8b 9d 86 98 40 b4 16 66 b4 2e 92 ea 0d a3 b4
			32 04 b5 cf ce 33 52 52 4d 04 16 a5 a4 41 e7 00 af 46 15 03
		}

		dP {
			54 49 4c a6 3e ba 03 37 e4 e2 40 23 fc d6 9a 5a eb 07 dd dc 01 83
			a4 d0 ac 9b 54 b0 51 f2 b1 3e d9 49 09 75 ea b7 74 14 ff 59 c1 f7
			69 2e 9a 2e 20 2b 38 fc 91 0a 47 41 74 ad c9 3c 1f 67 c9 81
		}

		dQ {
			47 1e 02 90 ff 0a f0 75 03 51 b7 f8 78 86 4c a9 61 ad bd 3a 8a 7e
			99 1c 5c 05 56 a9 4c 31 46 a7 f9 80 3f 8f 6f 8a e3 42 e9 31 fd 8a
			e4 7a 22 0d 1b 99 a4 95 84 98 07 fe 39 f9 24 5a 98 36 da 3d
		}

		qInv {
			b0 6c 4f da bb 63 01 19 8d 26 5b db ae 94 23 b3 80 f2 71 f7 34 53
			88 50 93 07 7f cd 39 e2 11 9f c9 86 32 15 4f 58 83 b1 67 a9 67 bf
			40 2b 4e 9e 2e 0f 96 56 e6 98 ea 36 66 ed fb 25 79 80 39 f7
		}

		M {
			d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49
		}

		P {
		}

		pHash {
			da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09
		}

		DB {
			da 39 a3 ee 5e 6b 4b 0d 32 55 bf ef 95 60 18 90 af d8 07 09 00 00
			00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
			00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
			00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
			00 00 01 d4 36 e9 95 69 fd 32 a7 c8 a0 5b bc 90 d3 2c 49
		}

		seed {
			aa fd 12 f6 59 ca e6 34 89 b4 79 e5 07 6d de c2 f0 6c b5 8f
		}

		dbMask {
			06 e1 de b2 36 9a a5 a5 c7 07 d8 2c 8e 4e 93 24 8a c7 83 de e0 b2
			c0 46 26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c
			dc fe 4f f4 77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41
			21 43 58 11 59 1b e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f
			3a c1 4e af f4 9c 8c 3b 7c fc 95 1a 51 ec d1 dd e6 12 64
		}

		maskedDB {
			dc d8 7d 5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2
			c0 46 26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c
			dc fe 4f f4 77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41
			21 43 58 11 59 1b e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f
			3a c1 4f 7b c2 75 19 52 81 ce 32 d2 f1 b7 6d 4d 35 3e 2d
		}

		seedMask {
			41 87 0b 5a b0 29 e6 57 d9 57 50 b5 4c 28 3c 08 72 5d be a9
		}

		maskedSeed {
			eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26
		}

		EM {
			eb 7a 19 ac e9 e3 00 63 50 e3 29 50 4b 45 e2 ca 82 31 0b 26 dc d8
			7d 5c 68 f1 ee a8 f5 52 67 c3 1b 2e 8b b4 25 1f 84 d7 e0 b2 c0 46
			26 f5 af f9 3e dc fb 25 c9 c2 b3 ff 8a e1 0e 83 9a 2d db 4c dc fe
			4f f4 77 28 b4 a1 b7 c1 36 2b aa d2 9a b4 8d 28 69 d5 02 41 21 43
			58 11 59 1b e3 92 f9 82 fb 3e 87 d0 95 ae b4 04 48 db 97 2f 3a c1
			4f 7b c2 75 19 52 81 ce 32 d2 f1 b7 6d 4d 35 3e 2d
		}

		C {
			12 53 e0 4d c0 a5 39 7b b4 4a 7a b8 7e 9b f2 a0 39 a3 3d 1e 99 6f
			c8 2a 94 cc d3 00 74 c9 5d f7 63 72 20 17 06 9e 52 68 da 5d 1c 0b
			4f 87 2c f6 53 c1 1d f8 23 14 a6 79 68 df ea e2 8d ef 04 bb 6d 84
			b1 c3 1d 65 4a 19 70 e5 78 3b d6 eb 96 a0 24 c2 ca 2f 4a 90 fe 9f
			2e f5 c9 c1 40 e5 bb 48 da 95 36 ad 87 00 c8 4f c9 13 0a de a7 4e
			55 8d 51 a7 4d df 85 d8 b5 0d e9 68 38 d6 06 3e 09 55
		}

		c_mod_p {
			de 63 d4 72 35 66 fa a7 59 bf e4 08 82 1d d5 25 72 ec 92 85 4d df
			87 a2 b6 64 d4 4d aa 37 ca 34 6a 05 20 3d 82 ff 2d e8 e3 6c ec 1d
			34 f9 8e b6 05 e2 a7 d2 6d e7 af 36 9c e4 ec ae 14 e3 56 33
		}

		c_mod_q {
			a2 d9 24 de d9 c3 6d 62 3e d9 a6 5b 5d 86 2c fb ec 8b 19 9c 64 27
			9c 54 14 e6 41 19 6e f1 c9 3c 50 7a 9b 52 13 88 1a ad 05 b4 cc fa
			02 8a c1 ec 61 42 09 74 bf 16 25 83 6b 0b 7d 05 fb b7 53 36
		}

		m1 {
			89 6c a2 6c d7 e4 87 1c 7f c9 68 a8 ed ea 11 e2 71 82 4f 0e 03 65
			52 17 94 f1 e9 e9 43 b4 a4 4b 57 c9 e3 95 a1 46 74 78 f5 26 49 6b
			4b b9 1f 1c ba ea 90 0f fc 60 2c f0 c6 63 6e ba 84 fc 9f f7
		}

		m2 {
			4e bb 22 75 85 f0 c1 31 2d ca 19 e0 b5 41 db 14 99 fb f1 4e 27 0e
			69 8e 23 9a 8c 27 a9 6c da 9a 74 09 74 de 93 7b 5c 9c 93 ea d9 46
			2c 65 75 02 1a 23 d4 64 99 dc 9f 6b 35 89 75 59 60 8f 19 be
		}

		h {
			01 2b 2b 24 15 0e 76 e1 59 bd 8d db 42 76 e0 7b fa c1 88 e0 8d 60
			47 cf 0e fb 8a e2 ae bd f2 51 c4 0e bc 23 dc fd 4a 34 42 43 94 ad
			a9 2c fc be 1b 2e ff bb 60 fd fb 03 35 9a 95 36 8d 98 09 25
		}
	}


	proc testvec2int {name} { #<<<
		variable test_vectors
		set vec	[dict get $test_vectors $name]

		set acc		0

		set s		0

		foreach o [lreverse $vec] {
			set v		0x$o
			incr acc	[expr {$v << ($s<<3)}]
			incr s
		}

		return $acc
	}

	#>>>
	proc testvec2os {name} { #<<<
		variable test_vectors
		set vec	[dict get $test_vectors $name]

		binary decode hex [join $vec ""]
	}

	#>>>
	# Test vectors >>>
}
# Copyright Cyan Ogilvie <cyan@codeforge.co.za>
# License terms are the same as the Tcl core

# While I have been careful to adhere to the implementation guidelines as
# closely as possible, no cryptographic audit has been performed on this code
# and I make no warrenties as to its correctness or security.  You are
# encouraged to examine the code yourself or get a qualified cryptographer to
# audit this code before using it in an application with specific security
# requirements.
#
# In particular it should be noted that key privacy is poor - the limitations
# of working in a scripting language means that the keys could be leaked
# through freed memory, so this code should not be used in any situation where
# an attacker could have access to system memory.  Certain timing attacks
# are also probably made more feasible because the script runs more slowly
# than native code, magnifying the effects of taking different branches in
# the code.

namespace eval crypto::blowfish {
	namespace path {::tcl::mathop ::tcl::mathfunc}

	proc init_key {key} { #<<<
		set keylength	[string length $key]
		if {![<= 4 $keylength 56]} {
			throw {invalid_keysize} "key length in bytes must be in the range \[4, 56\]"
		}

		# Initial P and S arrays <<<
		set P	{
			0x243F6A88 0x85A308D3 0x13198A2E 0x03707344
			0xA4093822 0x299F31D0 0x082EFA98 0xEC4E6C89
			0x452821E6 0x38D01377 0xBE5466CF 0x34E90C6C
			0xC0AC29B7 0xC97C50DD 0x3F84D5B5 0xB5470917
			0x9216D5D9 0x8979FB1B
		}

		set S	{
			{
				0xD1310BA6 0x98DFB5AC 0x2FFD72DB 0xD01ADFB7
				0xB8E1AFED 0x6A267E96 0xBA7C9045 0xF12C7F99
				0x24A19947 0xB3916CF7 0x0801F2E2 0x858EFC16
				0x636920D8 0x71574E69 0xA458FEA3 0xF4933D7E
				0x0D95748F 0x728EB658 0x718BCD58 0x82154AEE
				0x7B54A41D 0xC25A59B5 0x9C30D539 0x2AF26013
				0xC5D1B023 0x286085F0 0xCA417918 0xB8DB38EF
				0x8E79DCB0 0x603A180E 0x6C9E0E8B 0xB01E8A3E
				0xD71577C1 0xBD314B27 0x78AF2FDA 0x55605C60
				0xE65525F3 0xAA55AB94 0x57489862 0x63E81440
				0x55CA396A 0x2AAB10B6 0xB4CC5C34 0x1141E8CE
				0xA15486AF 0x7C72E993 0xB3EE1411 0x636FBC2A
				0x2BA9C55D 0x741831F6 0xCE5C3E16 0x9B87931E
				0xAFD6BA33 0x6C24CF5C 0x7A325381 0x28958677
				0x3B8F4898 0x6B4BB9AF 0xC4BFE81B 0x66282193
				0x61D809CC 0xFB21A991 0x487CAC60 0x5DEC8032
				0xEF845D5D 0xE98575B1 0xDC262302 0xEB651B88
				0x23893E81 0xD396ACC5 0x0F6D6FF3 0x83F44239
				0x2E0B4482 0xA4842004 0x69C8F04A 0x9E1F9B5E
				0x21C66842 0xF6E96C9A 0x670C9C61 0xABD388F0
				0x6A51A0D2 0xD8542F68 0x960FA728 0xAB5133A3
				0x6EEF0B6C 0x137A3BE4 0xBA3BF050 0x7EFB2A98
				0xA1F1651D 0x39AF0176 0x66CA593E 0x82430E88
				0x8CEE8619 0x456F9FB4 0x7D84A5C3 0x3B8B5EBE
				0xE06F75D8 0x85C12073 0x401A449F 0x56C16AA6
				0x4ED3AA62 0x363F7706 0x1BFEDF72 0x429B023D
				0x37D0D724 0xD00A1248 0xDB0FEAD3 0x49F1C09B
				0x075372C9 0x80991B7B 0x25D479D8 0xF6E8DEF7
				0xE3FE501A 0xB6794C3B 0x976CE0BD 0x04C006BA
				0xC1A94FB6 0x409F60C4 0x5E5C9EC2 0x196A2463
				0x68FB6FAF 0x3E6C53B5 0x1339B2EB 0x3B52EC6F
				0x6DFC511F 0x9B30952C 0xCC814544 0xAF5EBD09
				0xBEE3D004 0xDE334AFD 0x660F2807 0x192E4BB3
				0xC0CBA857 0x45C8740F 0xD20B5F39 0xB9D3FBDB
				0x5579C0BD 0x1A60320A 0xD6A100C6 0x402C7279
				0x679F25FE 0xFB1FA3CC 0x8EA5E9F8 0xDB3222F8
				0x3C7516DF 0xFD616B15 0x2F501EC8 0xAD0552AB
				0x323DB5FA 0xFD238760 0x53317B48 0x3E00DF82
				0x9E5C57BB 0xCA6F8CA0 0x1A87562E 0xDF1769DB
				0xD542A8F6 0x287EFFC3 0xAC6732C6 0x8C4F5573
				0x695B27B0 0xBBCA58C8 0xE1FFA35D 0xB8F011A0
				0x10FA3D98 0xFD2183B8 0x4AFCB56C 0x2DD1D35B
				0x9A53E479 0xB6F84565 0xD28E49BC 0x4BFB9790
				0xE1DDF2DA 0xA4CB7E33 0x62FB1341 0xCEE4C6E8
				0xEF20CADA 0x36774C01 0xD07E9EFE 0x2BF11FB4
				0x95DBDA4D 0xAE909198 0xEAAD8E71 0x6B93D5A0
				0xD08ED1D0 0xAFC725E0 0x8E3C5B2F 0x8E7594B7
				0x8FF6E2FB 0xF2122B64 0x8888B812 0x900DF01C
				0x4FAD5EA0 0x688FC31C 0xD1CFF191 0xB3A8C1AD
				0x2F2F2218 0xBE0E1777 0xEA752DFE 0x8B021FA1
				0xE5A0CC0F 0xB56F74E8 0x18ACF3D6 0xCE89E299
				0xB4A84FE0 0xFD13E0B7 0x7CC43B81 0xD2ADA8D9
				0x165FA266 0x80957705 0x93CC7314 0x211A1477
				0xE6AD2065 0x77B5FA86 0xC75442F5 0xFB9D35CF
				0xEBCDAF0C 0x7B3E89A0 0xD6411BD3 0xAE1E7E49
				0x00250E2D 0x2071B35E 0x226800BB 0x57B8E0AF
				0x2464369B 0xF009B91E 0x5563911D 0x59DFA6AA
				0x78C14389 0xD95A537F 0x207D5BA2 0x02E5B9C5
				0x83260376 0x6295CFA9 0x11C81968 0x4E734A41
				0xB3472DCA 0x7B14A94A 0x1B510052 0x9A532915
				0xD60F573F 0xBC9BC6E4 0x2B60A476 0x81E67400
				0x08BA6FB5 0x571BE91F 0xF296EC6B 0x2A0DD915
				0xB6636521 0xE7B9F9B6 0xFF34052E 0xC5855664
				0x53B02D5D 0xA99F8FA1 0x08BA4799 0x6E85076A
			}
			{
				0x4B7A70E9 0xB5B32944 0xDB75092E 0xC4192623
				0xAD6EA6B0 0x49A7DF7D 0x9CEE60B8 0x8FEDB266
				0xECAA8C71 0x699A17FF 0x5664526C 0xC2B19EE1
				0x193602A5 0x75094C29 0xA0591340 0xE4183A3E
				0x3F54989A 0x5B429D65 0x6B8FE4D6 0x99F73FD6
				0xA1D29C07 0xEFE830F5 0x4D2D38E6 0xF0255DC1
				0x4CDD2086 0x8470EB26 0x6382E9C6 0x021ECC5E
				0x09686B3F 0x3EBAEFC9 0x3C971814 0x6B6A70A1
				0x687F3584 0x52A0E286 0xB79C5305 0xAA500737
				0x3E07841C 0x7FDEAE5C 0x8E7D44EC 0x5716F2B8
				0xB03ADA37 0xF0500C0D 0xF01C1F04 0x0200B3FF
				0xAE0CF51A 0x3CB574B2 0x25837A58 0xDC0921BD
				0xD19113F9 0x7CA92FF6 0x94324773 0x22F54701
				0x3AE5E581 0x37C2DADC 0xC8B57634 0x9AF3DDA7
				0xA9446146 0x0FD0030E 0xECC8C73E 0xA4751E41
				0xE238CD99 0x3BEA0E2F 0x3280BBA1 0x183EB331
				0x4E548B38 0x4F6DB908 0x6F420D03 0xF60A04BF
				0x2CB81290 0x24977C79 0x5679B072 0xBCAF89AF
				0xDE9A771F 0xD9930810 0xB38BAE12 0xDCCF3F2E
				0x5512721F 0x2E6B7124 0x501ADDE6 0x9F84CD87
				0x7A584718 0x7408DA17 0xBC9F9ABC 0xE94B7D8C
				0xEC7AEC3A 0xDB851DFA 0x63094366 0xC464C3D2
				0xEF1C1847 0x3215D908 0xDD433B37 0x24C2BA16
				0x12A14D43 0x2A65C451 0x50940002 0x133AE4DD
				0x71DFF89E 0x10314E55 0x81AC77D6 0x5F11199B
				0x043556F1 0xD7A3C76B 0x3C11183B 0x5924A509
				0xF28FE6ED 0x97F1FBFA 0x9EBABF2C 0x1E153C6E
				0x86E34570 0xEAE96FB1 0x860E5E0A 0x5A3E2AB3
				0x771FE71C 0x4E3D06FA 0x2965DCB9 0x99E71D0F
				0x803E89D6 0x5266C825 0x2E4CC978 0x9C10B36A
				0xC6150EBA 0x94E2EA78 0xA5FC3C53 0x1E0A2DF4
				0xF2F74EA7 0x361D2B3D 0x1939260F 0x19C27960
				0x5223A708 0xF71312B6 0xEBADFE6E 0xEAC31F66
				0xE3BC4595 0xA67BC883 0xB17F37D1 0x018CFF28
				0xC332DDEF 0xBE6C5AA5 0x65582185 0x68AB9802
				0xEECEA50F 0xDB2F953B 0x2AEF7DAD 0x5B6E2F84
				0x1521B628 0x29076170 0xECDD4775 0x619F1510
				0x13CCA830 0xEB61BD96 0x0334FE1E 0xAA0363CF
				0xB5735C90 0x4C70A239 0xD59E9E0B 0xCBAADE14
				0xEECC86BC 0x60622CA7 0x9CAB5CAB 0xB2F3846E
				0x648B1EAF 0x19BDF0CA 0xA02369B9 0x655ABB50
				0x40685A32 0x3C2AB4B3 0x319EE9D5 0xC021B8F7
				0x9B540B19 0x875FA099 0x95F7997E 0x623D7DA8
				0xF837889A 0x97E32D77 0x11ED935F 0x16681281
				0x0E358829 0xC7E61FD6 0x96DEDFA1 0x7858BA99
				0x57F584A5 0x1B227263 0x9B83C3FF 0x1AC24696
				0xCDB30AEB 0x532E3054 0x8FD948E4 0x6DBC3128
				0x58EBF2EF 0x34C6FFEA 0xFE28ED61 0xEE7C3C73
				0x5D4A14D9 0xE864B7E3 0x42105D14 0x203E13E0
				0x45EEE2B6 0xA3AAABEA 0xDB6C4F15 0xFACB4FD0
				0xC742F442 0xEF6ABBB5 0x654F3B1D 0x41CD2105
				0xD81E799E 0x86854DC7 0xE44B476A 0x3D816250
				0xCF62A1F2 0x5B8D2646 0xFC8883A0 0xC1C7B6A3
				0x7F1524C3 0x69CB7492 0x47848A0B 0x5692B285
				0x095BBF00 0xAD19489D 0x1462B174 0x23820E00
				0x58428D2A 0x0C55F5EA 0x1DADF43E 0x233F7061
				0x3372F092 0x8D937E41 0xD65FECF1 0x6C223BDB
				0x7CDE3759 0xCBEE7460 0x4085F2A7 0xCE77326E
				0xA6078084 0x19F8509E 0xE8EFD855 0x61D99735
				0xA969A7AA 0xC50C06C2 0x5A04ABFC 0x800BCADC
				0x9E447A2E 0xC3453484 0xFDD56705 0x0E1E9EC9
				0xDB73DBD3 0x105588CD 0x675FDA79 0xE3674340
				0xC5C43465 0x713E38D8 0x3D28F89E 0xF16DFF20
				0x153E21E7 0x8FB03D4A 0xE6E39F2B 0xDB83ADF7
			}
			{
				0xE93D5A68 0x948140F7 0xF64C261C 0x94692934
				0x411520F7 0x7602D4F7 0xBCF46B2E 0xD4A20068
				0xD4082471 0x3320F46A 0x43B7D4B7 0x500061AF
				0x1E39F62E 0x97244546 0x14214F74 0xBF8B8840
				0x4D95FC1D 0x96B591AF 0x70F4DDD3 0x66A02F45
				0xBFBC09EC 0x03BD9785 0x7FAC6DD0 0x31CB8504
				0x96EB27B3 0x55FD3941 0xDA2547E6 0xABCA0A9A
				0x28507825 0x530429F4 0x0A2C86DA 0xE9B66DFB
				0x68DC1462 0xD7486900 0x680EC0A4 0x27A18DEE
				0x4F3FFEA2 0xE887AD8C 0xB58CE006 0x7AF4D6B6
				0xAACE1E7C 0xD3375FEC 0xCE78A399 0x406B2A42
				0x20FE9E35 0xD9F385B9 0xEE39D7AB 0x3B124E8B
				0x1DC9FAF7 0x4B6D1856 0x26A36631 0xEAE397B2
				0x3A6EFA74 0xDD5B4332 0x6841E7F7 0xCA7820FB
				0xFB0AF54E 0xD8FEB397 0x454056AC 0xBA489527
				0x55533A3A 0x20838D87 0xFE6BA9B7 0xD096954B
				0x55A867BC 0xA1159A58 0xCCA92963 0x99E1DB33
				0xA62A4A56 0x3F3125F9 0x5EF47E1C 0x9029317C
				0xFDF8E802 0x04272F70 0x80BB155C 0x05282CE3
				0x95C11548 0xE4C66D22 0x48C1133F 0xC70F86DC
				0x07F9C9EE 0x41041F0F 0x404779A4 0x5D886E17
				0x325F51EB 0xD59BC0D1 0xF2BCC18F 0x41113564
				0x257B7834 0x602A9C60 0xDFF8E8A3 0x1F636C1B
				0x0E12B4C2 0x02E1329E 0xAF664FD1 0xCAD18115
				0x6B2395E0 0x333E92E1 0x3B240B62 0xEEBEB922
				0x85B2A20E 0xE6BA0D99 0xDE720C8C 0x2DA2F728
				0xD0127845 0x95B794FD 0x647D0862 0xE7CCF5F0
				0x5449A36F 0x877D48FA 0xC39DFD27 0xF33E8D1E
				0x0A476341 0x992EFF74 0x3A6F6EAB 0xF4F8FD37
				0xA812DC60 0xA1EBDDF8 0x991BE14C 0xDB6E6B0D
				0xC67B5510 0x6D672C37 0x2765D43B 0xDCD0E804
				0xF1290DC7 0xCC00FFA3 0xB5390F92 0x690FED0B
				0x667B9FFB 0xCEDB7D9C 0xA091CF0B 0xD9155EA3
				0xBB132F88 0x515BAD24 0x7B9479BF 0x763BD6EB
				0x37392EB3 0xCC115979 0x8026E297 0xF42E312D
				0x6842ADA7 0xC66A2B3B 0x12754CCC 0x782EF11C
				0x6A124237 0xB79251E7 0x06A1BBE6 0x4BFB6350
				0x1A6B1018 0x11CAEDFA 0x3D25BDD8 0xE2E1C3C9
				0x44421659 0x0A121386 0xD90CEC6E 0xD5ABEA2A
				0x64AF674E 0xDA86A85F 0xBEBFE988 0x64E4C3FE
				0x9DBC8057 0xF0F7C086 0x60787BF8 0x6003604D
				0xD1FD8346 0xF6381FB0 0x7745AE04 0xD736FCCC
				0x83426B33 0xF01EAB71 0xB0804187 0x3C005E5F
				0x77A057BE 0xBDE8AE24 0x55464299 0xBF582E61
				0x4E58F48F 0xF2DDFDA2 0xF474EF38 0x8789BDC2
				0x5366F9C3 0xC8B38E74 0xB475F255 0x46FCD9B9
				0x7AEB2661 0x8B1DDF84 0x846A0E79 0x915F95E2
				0x466E598E 0x20B45770 0x8CD55591 0xC902DE4C
				0xB90BACE1 0xBB8205D0 0x11A86248 0x7574A99E
				0xB77F19B6 0xE0A9DC09 0x662D09A1 0xC4324633
				0xE85A1F02 0x09F0BE8C 0x4A99A025 0x1D6EFE10
				0x1AB93D1D 0x0BA5A4DF 0xA186F20F 0x2868F169
				0xDCB7DA83 0x573906FE 0xA1E2CE9B 0x4FCD7F52
				0x50115E01 0xA70683FA 0xA002B5C4 0x0DE6D027
				0x9AF88C27 0x773F8641 0xC3604C06 0x61A806B5
				0xF0177A28 0xC0F586E0 0x006058AA 0x30DC7D62
				0x11E69ED7 0x2338EA63 0x53C2DD94 0xC2C21634
				0xBBCBEE56 0x90BCB6DE 0xEBFC7DA1 0xCE591D76
				0x6F05E409 0x4B7C0188 0x39720A3D 0x7C927C24
				0x86E3725F 0x724D9DB9 0x1AC15BB4 0xD39EB8FC
				0xED545578 0x08FCA5B5 0xD83D7CD3 0x4DAD0FC4
				0x1E50EF5E 0xB161E6F8 0xA28514D9 0x6C51133C
				0x6FD5C7E7 0x56E14EC4 0x362ABFCE 0xDDC6C837
				0xD79A3234 0x92638212 0x670EFA8E 0x406000E0
			}
			{
				0x3A39CE37 0xD3FAF5CF 0xABC27737 0x5AC52D1B
				0x5CB0679E 0x4FA33742 0xD3822740 0x99BC9BBE
				0xD5118E9D 0xBF0F7315 0xD62D1C7E 0xC700C47B
				0xB78C1B6B 0x21A19045 0xB26EB1BE 0x6A366EB4
				0x5748AB2F 0xBC946E79 0xC6A376D2 0x6549C2C8
				0x530FF8EE 0x468DDE7D 0xD5730A1D 0x4CD04DC6
				0x2939BBDB 0xA9BA4650 0xAC9526E8 0xBE5EE304
				0xA1FAD5F0 0x6A2D519A 0x63EF8CE2 0x9A86EE22
				0xC089C2B8 0x43242EF6 0xA51E03AA 0x9CF2D0A4
				0x83C061BA 0x9BE96A4D 0x8FE51550 0xBA645BD6
				0x2826A2F9 0xA73A3AE1 0x4BA99586 0xEF5562E9
				0xC72FEFD3 0xF752F7DA 0x3F046F69 0x77FA0A59
				0x80E4A915 0x87B08601 0x9B09E6AD 0x3B3EE593
				0xE990FD5A 0x9E34D797 0x2CF0B7D9 0x022B8B51
				0x96D5AC3A 0x017DA67D 0xD1CF3ED6 0x7C7D2D28
				0x1F9F25CF 0xADF2B89B 0x5AD6B472 0x5A88F54C
				0xE029AC71 0xE019A5E6 0x47B0ACFD 0xED93FA9B
				0xE8D3C48D 0x283B57CC 0xF8D56629 0x79132E28
				0x785F0191 0xED756055 0xF7960E44 0xE3D35E8C
				0x15056DD4 0x88F46DBA 0x03A16125 0x0564F0BD
				0xC3EB9E15 0x3C9057A2 0x97271AEC 0xA93A072A
				0x1B3F6D9B 0x1E6321F5 0xF59C66FB 0x26DCF319
				0x7533D928 0xB155FDF5 0x03563482 0x8ABA3CBB
				0x28517711 0xC20AD9F8 0xABCC5167 0xCCAD925F
				0x4DE81751 0x3830DC8E 0x379D5862 0x9320F991
				0xEA7A90C2 0xFB3E7BCE 0x5121CE64 0x774FBE32
				0xA8B6E37E 0xC3293D46 0x48DE5369 0x6413E680
				0xA2AE0810 0xDD6DB224 0x69852DFD 0x09072166
				0xB39A460A 0x6445C0DD 0x586CDECF 0x1C20C8AE
				0x5BBEF7DD 0x1B588D40 0xCCD2017F 0x6BB4E3BB
				0xDDA26A7E 0x3A59FF45 0x3E350A44 0xBCB4CDD5
				0x72EACEA8 0xFA6484BB 0x8D6612AE 0xBF3C6F47
				0xD29BE463 0x542F5D9E 0xAEC2771B 0xF64E6370
				0x740E0D8D 0xE75B1357 0xF8721671 0xAF537D5D
				0x4040CB08 0x4EB4E2CC 0x34D2466A 0x0115AF84
				0xE1B00428 0x95983A1D 0x06B89FB4 0xCE6EA048
				0x6F3F3B82 0x3520AB82 0x011A1D4B 0x277227F8
				0x611560B1 0xE7933FDC 0xBB3A792B 0x344525BD
				0xA08839E1 0x51CE794B 0x2F32C9B7 0xA01FBAC9
				0xE01CC87E 0xBCC7D1F6 0xCF0111C3 0xA1E8AAC7
				0x1A908749 0xD44FBD9A 0xD0DADECB 0xD50ADA38
				0x0339C32A 0xC6913667 0x8DF9317C 0xE0B12B4F
				0xF79E59B7 0x43F5BB3A 0xF2D519FF 0x27D9459C
				0xBF97222C 0x15E6FC2A 0x0F91FC71 0x9B941525
				0xFAE59361 0xCEB69CEB 0xC2A86459 0x12BAA8D1
				0xB6C1075E 0xE3056A0C 0x10D25065 0xCB03A442
				0xE0EC6E0E 0x1698DB3B 0x4C98A0BE 0x3278E964
				0x9F1F9532 0xE0D392DF 0xD3A0342B 0x8971F21E
				0x1B0A7441 0x4BA3348C 0xC5BE7120 0xC37632D8
				0xDF359F8D 0x9B992F2E 0xE60B6F47 0x0FE3F11D
				0xE54CDA54 0x1EDAD891 0xCE6279CF 0xCD3E7E6F
				0x1618B166 0xFD2C1D05 0x848FD2C5 0xF6FB2299
				0xF523F357 0xA6327623 0x93A83531 0x56CCCD02
				0xACF08162 0x5A75EBB5 0x6E163697 0x88D273CC
				0xDE966292 0x81B949D0 0x4C50901B 0x71C65614
				0xE6C6C7BD 0x327A140A 0x45E1D006 0xC3F27B9A
				0xC9AA53FD 0x62A80F00 0xBB25BFE2 0x35BDD2F6
				0x71126905 0xB2040222 0xB6CBCF7C 0xCD769C2B
				0x53113EC0 0x1640E3D3 0x38ABBD60 0x2547ADF0
				0xBA38209C 0xF746CE76 0x77AFA1C5 0x20756060
				0x85CBFE4E 0x8AE88DD8 0x7AAAF9B0 0x4CF9AA7E
				0x1948C25C 0x02FB8A8C 0x01C36AE4 0xD6EBE1F9
				0x90D4F869 0xA65CDEA0 0x3F09252D 0xC208E69F
				0xB74E6132 0xCE77E25B 0x578FDFE3 0x3AC372E6
			}
		}
		# Initial P and S arrays >>>

		set reqbytes	[expr {4 * [llength $P]}]
		set cycledkey	[string repeat $key [expr {
			int(ceil( double($reqbytes) / [string length $key] ))
		}]]
		for {set i 0} {$i < [llength $P]} {incr i} {
			set a	[lindex $P $i]
			set o	[expr {$i * 4}]
			binary scan $cycledkey @${o}I keyportion
			lset P $i [expr {$keyportion ^ $a}]
		}

		set l		0
		set r		0
		for {set i 0} {$i < [llength $P]} {} {
			lassign [_transform_block $P $S $l $r] l r
			lset P $i $l
			incr i
			lset P $i $r
			incr i
		}

		for {set i 0} {$i < 4} {incr i} {
			for {set j 0} {$j < 256} {} {
				lassign [_transform_block $P $S $l $r] l r
				lset S $i $j $l
				incr j
				lset S $i $j $r
				incr j
			}
		}

		list $P $S
	}

	#>>>
	proc encrypt {schedule bytes} { #<<<
		lassign $schedule P S
		_apply $P $S $bytes
	}

	#>>>
	proc decrypt {schedule bytes} { #<<<
		lassign $schedule P S
		_apply [lreverse $P] $S $bytes
	}

	#>>>
	proc encrypt_cbc {schedule bytes iv} { #<<<
		lassign $schedule P S
		_apply_cbc_e $P $S [_pad $bytes] $iv
	}

	#>>>
	proc decrypt_cbc {schedule bytes iv} { #<<<
		lassign $schedule P S
		_unpad [_apply_cbc_d [lreverse $P] $S $bytes $iv]
	}

	#>>>
	proc _apply {P S bytes} { #<<<
		set bytelen	[string length $bytes]
		if {$bytelen % 8 != 0} {
			throw {invalid_plaintext_length} "ECB mode requires input to be a multiple of blocksize (64 bits): $bytelen"
		}

		if {$bytelen < 8192} {
			binary scan $bytes Iu* ints
			set oints	{}
			foreach {l r} $ints {
				lappend oints {*}[_transform_block $P $S $l $r]
			}

			binary format I* $oints
		} else {
			# Use a less memory intesive method - the faster one above would
			# use more than 1.5MB for a 50kb message
			set O	""
			set o	0
			while {$o + $bs <= $bytelen} {
				binary scan $bytes @${o}Iu2048 ints
				set oints	{}
				foreach {l r} $ints {
					lappend oints	{*}[_transform_block $P $S $l $r]
				}
				append O	[binary format I* $oints]
			}
			if {$o < $bytelen} {
				binary scan $bytes @${o}Iu[expr {($bytelen-$o)/4}] ints
				set oints	{}
				foreach {l r} $ints {
					lappend oints	{*}[_transform_block $P $S $l $r]
				}
				append O	[binary format I* $oints]
			}
			set O
		}
	}

	#>>>
	proc _apply_cbc_e {P S bytes iv} { #<<<
		if {[binary scan $iv IuIu ivl ivr] != 2} {
			throw {invalid_iv_length} "Invalid IV length, must be one block (64 bits)"
		}

		set bytelen	[string length $bytes]
		if {$bytelen % 8 != 0} {
			throw {invalid_plaintext_length} "ECB mode requires input to be a multiple of blocksize (64 bits): $bytelen"
		}

		if {$bytelen < 8192} {
			binary scan $bytes Iu* ints
			set oints	{}
			foreach {l r} $ints {
				set l	[^ $l $ivl]
				set r	[^ $r $ivr]
				lassign [_transform_block $P $S $l $r] l r
				set ivl	$l
				set ivr	$r
				lappend oints	$l $r
			}

			return [binary format I* $oints]
		} else {
			# Use a less memory intesive method - the faster one above would be
			# using more than 1.5MB for a 50kb message
			set O	""
			for {set o 0} {$o < $bytelen} {incr o 8192} {
				binary scan $bytes @${o}Iu[expr {min($bs, $bytelen-$o)/4}] ints
				set oints	{}
				foreach {l r} $ints {
					set l	[^ $l $ivl]
					set r	[^ $r $ivr]
					lassign [_transform_block $P $S $l $r] l r
					set ivl	$l
					set ivr	$r
					lappend oints	$l $r
				}
				append O	[binary format I* $oints]
			}
			return $O
		}
	}

	#>>>
	proc _apply_cbc_d {P S bytes iv} { #<<<
		if {[binary scan $iv IuIu ivl ivr] != 2} {
			throw {invalid_iv_length} "Invalid IV length, must be one block (64 bits)"
		}


		set bytelen	[string length $bytes]
		if {$bytelen % 8 != 0} {
			throw {invalid_plaintext_length} "ECB mode requires input to be a multiple of blocksize (64 bits): $bytelen"
		}

		if {$bytelen < 8192} {
			binary scan $bytes Iu* ints
			set oints	{}
			foreach {l r} $ints {
				lassign [_transform_block $P $S $l $r] ol or
				set ol	[^ $ol $ivl]
				set or	[^ $or $ivr]
				set ivl	$l
				set ivr	$r
				lappend oints	$ol $or
			}

			return [binary format I* $oints]
		} else {
			# Use a less memory intesive method - the faster one above would be
			# using more than 1.5MB for a 50kb message
			set O	""
			for {set o 0} {$o < $bytelen} {incr o 8192} {
				binary scan $bytes @${o}Iu[expr {min($bs, $bytelen-$o)/4}] ints
				set oints	{}
				foreach {l r} $ints {
					lassign [_transform_block $P $S $l $r] ol or
					set ol	[^ $ol $ivl]
					set or	[^ $or $ivr]
					set ivl	$l
					set ivr	$r
					lappend oints	$ol $or
				}
				append O	[binary format I* $oints]
			}
			return $O
		}
	}

	#>>>
	proc _transform_block {P S l r} { #<<<
		lassign $S S1 S2 S3 S4
		foreach p [lrange $P 0 end-2] {
			set l		[expr {$l ^ $p}]

			set s1	[lindex $S1 [expr {($l >> 24) & 0xff}]]
			set s2	[lindex $S2 [expr {($l >> 16) & 0xff}]]
			set s3	[lindex $S3 [expr {($l >>  8) & 0xff}]]
			set s4	[lindex $S4 [expr { $l        & 0xff}]]

			set hold	$l
			set l	[expr {(((($s1 + $s2) ^ $s3) + $s4) & 0xffffffff) ^ $r}]
			set r	$hold
		}

		list \
				[expr {($r ^ [lindex $P end])   & 0xffffffff}] \
				[expr {($l ^ [lindex $P end-1]) & 0xffffffff}]
	}

	#>>>
	proc _pad {bytes} { #<<<
		set bytelen		[string length $bytes]
		set lastbyte	[string index $bytes end]
		set padlen		[expr {8-($bytelen % 8)}]

		set padchar	[csprng 1]
		while {$padchar eq $lastbyte} {
			set padchar	[csprng 1]
		}

		append bytes [string repeat $padchar $padlen]
		return $bytes
	}

	#>>>
	proc _unpad {bytes} { #<<<
		set paddedlen	[string length $bytes]
		set last		[string index $bytes end]
		set i			[expr {$paddedlen - 2}]
		while {[string index $bytes $i] eq $last} {incr i -1}
		string range $bytes 0 $i
	}

	#>>>
	proc csprng {bytes} { #<<<
		variable _csprngstate

		# Based on blowfish run in counter mode, with cbc
		#
		# Setup consumes 72 bytes (576 bits) of entropy.
		# This effectively selects one of 2⁵¹² sequences, each with a
		# period of 2⁶⁷ bytes, initialized to a random block aligned
		# (8 byte) point within their period (ie, one of 2⁶⁴ points)
		#
		# TODO: does this satisfy the next bit test (assuming no knowledge
		# of initial key, iv and i)?
		# Since blowfish at full 16 rounds cannot currently be distinguished
		# from a random number source even with weak keys to the best of
		# my knowledge as of April 2009, this should be ok.
		#
		# Basic testing seems to indicate uniform distribution

		if {![info exists _csprngstate]} {
			set rand	[randbytes 72]
			lassign [init_key [string range $rand 0 55]] P S
			binary scan [string range $rand 56 63] W i
			binary scan [string range $rand 64 71] II ivl ivr
			dict set _csprngstate P		$P
			dict set _csprngstate S		$S
			dict set _csprngstate i		$i
			dict set _csprngstate ivl	$ivl
			dict set _csprngstate ivr	$ivr
			dict set _csprngstate O		""
		}

		dict with _csprngstate {
			while {[string length $O] < $bytes} {
				set i	[expr {($i + 1) & 0xffffffffffffffff}]

				set l	[expr {(($i >> 32) & 0xffffffff) ^ $ivl}]
				set r	[expr {( $i        & 0xffffffff) ^ $ivr}]

				lassign [_transform_block $P $S $l $r] l r
				set ivl		$l
				set ivr		$r
				append O	[binary format II $l $r]
			}
			set res	[string range $O 0 $bytes-1]
			set O	[string range $O $bytes end]
			set res
		}
	}

	#>>>
	proc randbytes {bytecount} { #<<<
		#set h	[open /dev/random r]
		set h	[open /dev/urandom r]
		try {
			chan configure $h -translation binary -encoding binary -blocking 1
			chan read $h $bytecount
		} finally {
			catch {chan close $h}
		}
	}

	#>>>
}

# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4
