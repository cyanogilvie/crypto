# vim: ft=tcl foldmethod=marker foldmarker=<<<,>>> ts=4 shiftwidth=4

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

		set count	0
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
			incr count
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

		try {
			lsort [dict keys $dat]
		} on ok {keys} {
			if {$keys eq [lsort {n e}]} {
				return $dat
			}
		} on error {} {}

		load_asn1_pubkey_from_value $dat
	}

	#>>>
	proc load_asn1_pubkey_from_value {dat} { #<<<
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
				1 {binary scan $intbytes cu seqlength}
				2 {binary scan $intbytes Su seqlength}
				3 {binary scan \x00$intbytes Iu seqlength}
				4 {binary scan $intbytes Iu seqlength}
				default {
					scan [binary encode hex $intbytes] %llx seqlength
				}
			}
		}
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
			hash {
				package require sha1

				set in	[lindex $args 0]
				return [sha1::sha1 -bin $in]
			}
			default {throw {invalid_cmd} "Invalid hash command"}
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
