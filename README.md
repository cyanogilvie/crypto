Crypto
======

Provides basic RSA, blowfish and CSPRNG functions.  Supports OAEP and PKCS v1.5 padding.

Examples
--------

Generate a 1024 bit RSA key pair:
~~~tcl
set K	[crypto::rsa::RSAKG 1024 0x10001]
~~~

Sign a string using RSA with OAEP and SHA256:
~~~tcl
set signature	[crypto::rsa::RSAES-OAEP-Sign \
	[dict get $K n] \
	[dict get $K d] \
	[encoding convertto utf-8 "This is the data I want to sign"] \
	{} \
	$::crypto::rsa::sha256 \
	$::crypto::rsa::MGF]
~~~

Generate a blowfish session key and encrypt it with an RSA public key:
~~~tcl
set key		[crypto::blowfish::csprng 56]
set e_key	[crypto::rsa::RSAES-OAEP-Encrypt \
	[dict get $K n] \
	[dict get $K e] \
	$key \
	{} \
	$crypto::rsa::sha256 \
	$crypto::rsa::MGF]
~~~

Decrypt a session key with an RSA private key:
~~~tcl
set key		[crypto::rsa::RSAES-OAEP-Decrypt \
	[list \
		[dict get $K p] \
		[dict get $K q] \
		[dict get $K dP] \
		[dict get $K dQ] \
		[dict get $K qInv] \
	] \
	$e_key \
	{}
	$crypto::rsa::sha265 \
	$crypto::rsa::MGF]
~~~

Encrypt and decrypt a message with blowfish in CBC (Cipher Block Chaining) mode:
~~~tcl
# Client
set plaintext    "hello, world"
set key          [crypto::blowfish::csprng 56]
set ks           [crypto::blowfish::init_key $key]
set iv           [crypto::blowfish 8]
set ciphertext   [crypto::blowfish::encrypt_cbc $ks [encoding convertto utf-8 $plaintext] $iv
set e_msg        $iv$ciphertext
# send $e_msg to server

# Server
# assumes $key from client, transferred security using RSA as in the above examples
set ks           [crypto::blowfish::init_key $key]
set iv           [string range $e_msg 0 7]
set cipertext    [string range $e_msg 8 end]
set plaintext    [encoding convertfrom utf-8 [crypto::blowfish::decrypt_cbc $ks $ciphertext $iv]]
# $plaintext is "hello, world"
~~~

Building
--------
This uses tbuild to build the .tm.  You very likely don't have tbuild, so
just use the pre-built .tm included in the repo.

Security
--------
While I have been careful to adhere to the implementation guidelines as
closely as possible, no cryptographic audit has been performed on this code
and I make no warrenties as to its correctness or security.  You are
encouraged to examine the code yourself or get a qualified cryptographer to
audit this code before using it in an application with specific security
requirements.

In particular it should be noted that key privacy is poor - the limitations
of working in a scripting language means that the keys could be leaked
through freed memory, so this code should not be used in any situation where
an attacker could have access to system memory.  Certain timing attacks
are also probably made more feasible because the script runs more slowly
than native code, magnifying the effects of taking different branches in
the code.

License
-------
This package is licensed under the same terms as the Tcl core.
