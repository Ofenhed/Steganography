# Steganography
This app will hide data in images based on a shared key and a predetermined encryption complexity between a sender and a receiver.

Notice: This is pretty much just a project I created to learn Haskell, and while the crypto is strong the steganography is not!

Notice: I've greatly reduced the performance of the encrypter, but in a way which may secure the hidden data from Steganalysis. This can be turned off with the --quick flag.

## Maintaining security
To maintain security with this application, the following needs to be true.
* The picutre you are using **must** used for the sole purpose of hiding data once, or it would be obvious for someone looking at the picture that it contains hidden data.
  * The original **must not** be published anywhere (and will be automatically destroyed by the Steganography program during the encryption).
  * A picture **must not** be used more than once for encryption.
* The picture **must not** be predictable.
  * The picture **should not** have filters applied.
    * The picture **must not** be greyscale.
  * The picture **must not** be generated by a computer.
* Different salts **should** be used every time.
* For PKI you **should** use the Curve25519 option. The RSA option is to be considered to be to simplify key exchange, since you may already hold someones public RSA key.
* You **should** use relatively small keys for RSA (ideally 2048 bits). See title RSA for details.
* **Don't trust me!** You **should** encrypt your data in another program before hiding it in an image. I am just a random person on the internet, and while I may have good intentions you have no way of proving that.
  * You **must not** use the same password for encrypting the data in this program as you did in the other program.

### A secure shared secret
The shared secret **should** be a file that ONLY you and the receiver has access to. If it's truely random it should be at least 32 bytes, but you could also use a significantly bigger secret, such as a picture.

### Curve25519 key generation
The program can generate a Curve25519 key pair for you using the `generateKey` command. This will create two files, one which ends with ".public.key" which you are to share with anyone you want to communicate with, and one that ends with ".secret.key" which you must keep secret at all times."

### Recommended complexity
A minimum of 1000 iterations were recommended back in 2000 for PBKDF2. This number is greatly outdated, but I included it to give you a slight understanding of which sizes we're talking about. A rule of thumb is that it shold take you a long time to encrypt the data for it to be secure. Using a bigger shared secret allows you to use a smaller number for complexity.

### A secure salt
If you and the person/people you are sending data to has the same key then you mustn't use the same salt twice or you will have lowered the security of the data. To achieve this, a salt can be as simple as a unique identifier for you and a number which you raise for every package you send. For example:

> Alice sends a picture to Bob. They use the same secret. Alice uses the salt `Alice-1`. Bob receives the message, and knows who it's from and knows it's the first message and therefore applies the same salt when decrypting. Bob answers the message with the salt `Bob-1`, since it's his first message. The fact that they both used the number 1 is not an issue, since the salt still differs between the packages Alice and Bob sends. They can therefore have counters that tick independently of eachother.

The salt is not considered part of the secret, so including it with the picture would be ok. For example:

> Alice sends a picture to Bob in a mail. Besides the mail is the text "Check out this picture of my cute little Eve. She turned 3 today.". She uses the salt `Check out this picture of my cute little Eve. She turned 3 today.` for the encryption. A list **should** be kept of all salts used to make sure that the same salt isn't used twice.

## What the program does to protect you
If you do use the same password and salt every time, but change the picture, the program will still not create the same key stream for the secret data because a huge additional salt is read out from the picture before any sensitive data is added.

## Technical description

### PBKDF2
The PBKDF2 algorithm in this program has been slightly modified for increased security. The difference is that now for every block the first iteration will have a salt based on previous results. This prevents jumps in the hash stream, since to calculate block N you need to calculate N blocks, unlike PBKDF2 which allows you to calculate any block.

Since PBKDF2 appends the counter to the salt, a huge salt can be reduced to the size of the internal state of the hash plus a maximum of one block size. The added salt in the modified PBKDF2 algorithm is instead prepended to the chosen salt, which means that for every block the hash for the salt will have to be calculated in its entirety.

These two modicitations will improve the security of this program without adding any workload worth mentioning.

For more information on the change, check [the documentation for Lazy-Pbkdf2](https://hackage.haskell.org/package/Lazy-Pbkdf2-2.1.0/docs/Crypto-Pbkdf2.html).

### Pixel stream
A pixel stream is used to perform the Steganography encryption. It has the type `[(x, y, color, invertBit)]`. It refers to which pixel should be modified, where the data modified is the least significant bit of the pixel and color chosen. The bit that is read/written is inverted if invertBit is 1.

The pixel stream is generated by selecting a random element among a complete list of all valid values for `(x, y, color)` (with invertBit attached afterwards, disregarded for now). This is done by selecting a value in the range `[0..(len unusedPixels) - 1]` in the forementioned list. The value is chosen by extracting a big enough random number from the random stream. If the random number is too big, for example if you try to get a value between 0 and 12 (which would require 4 bits of random data) and you get the value 14, all four bits extracted from the random stream will be discarded and the random operation is retried.

A huge amount of data will be calculated (with parts of it discarded as described above) just to find the salt in the image, and after that a huge key is selected for PBKDF2, before any data is even touched. All of this needs to be calculated to find where in the pixel stream the user data even starts, and even more so to be able to find the user data encryption stream.

### Encryption/Decryption
Your password and salt will be used with the PBKDF2 function, with the number of iterations you have chosen. This will create the initial crypto stream `SHA512PBKDF2 { password = content(SHARED-SECRET-FILE), salt = salt, iter = complexity }`. The initial crypto stream will be used to fetch 1/30 of all pixels, and save their entire value in the chosen color in the variable `bigSalt`. Every seperate byte in `bigSalt` has a 50% chance of getting inverted before being used in the salt. The crypto stream will then be used to create the 256 byte PBKDF2 random, `newPbkdfSecret`, and the first AES256 key, `aesSecret1`. The crypto stream will now be replaced by the stream `hmacSha512Pbkdf2(newPbkdfSecret, bigSalt || yourSalt, 5 iterations)`. From this new crypto stream we read the second AES256 key, `aesSecret2`. We now add the AES256 keys to the stream by setting the stream to `drop(16 bytes, hmacSha512Pbkdf2(newPbkdfSecret, bigSalt || yourSalt, 5 iterations)) ⊕ AES256(aesSecret1)`⊕ AES256(aesSecret2)`. This will be the "random data" used to choose pixels and xor values for the encrypted PKI key, header and data.

This is done to assure that all user data is encrypted against an unique crypto stream every time, even if the same key and salt is being used.

This can all be verified in the function `createRandomStates` in Steganography.hs.

#### PKI

The program supports RSA and Curve25519 DH. The RSA algorithm has a checksum and could possibly be used to gain more information, even though it's not likely. This is not the case with Curve25519. The RSA also has much bigger keys. For these two reasons it's recommended that the Curve algorithm is used. The RSA is implemented to allow users to use their own keys (instead of keys generated by this program) and to allow for users to use public keys that are already in use. Apart from that it's only in the program because it's the first PKI system I built.


##### RSA
After the Encryption/Decryption step, RSA can be used. This is done by adding a public key for encryption and private key for decryption. For encryption a big random secret `bigRandom` will be created from the system random source (so not pseudorandom coming from the program). This random will be encrypted using OEAP and write it to the image in the exact same way as data is usually written. Once it has been put in the image a new salt `salt` of 256 bytes is generated. At this point a new cryptostream, `hmacSha512Pbkdf2(bigRandom, salt, 5)`, is added to the entropy sources.

On the receiving end it works pretty much the same, except `bigRandom` is read from the image and decrypted using the private key, after which the salt is created and they are both added to the new cryptostream in the same way.

Note that when you encrypt using a 2048 bit RSA key, the result will be 2048 bits long. This means that a 2048 key will probably change additionally ~1024 bits in the image (or in the worst case 2048 bits), which makes the Steganography manipulation easier to detect. For this reason, if you want to keep the detection rate down you should have small RSA keys (or skip the RSA function all together). It will, however, add an extra layer of security where you could exchange keys over an untrusted channel.

If the private RSA keys are kept safe then it would be safe to only use the RSA encryption and let the symmetric encryption be known. A specific use case for this would be used to share symmetric keys in a group, to allow for broadcast messages while using RSA encryption for specific receivers. Notice: The messages aren't signed, so a receiver would not be able to verify the source of the encrypted message unless they are signed before they are encrypted with this program.

##### Elliptic Curve 25519
This is implemented as a DH exchange where the receiver creates a public and secret Curve25519 key, `Rpub` and `Rsec`, once and share `Rpub` with anyone who wants to communicate with him.

When someone wants to send something using Curve 25519 the sender will create a secret and public key, `Spub` and `Ssec` every time he sends something. The sender writes `Spub` to the image. The sender then creates the shared key `shared = DH(Rpub, Ssec)` and generates the new salt `salt` of 256 bytes from the existing crypto stream. He then adds `AES256(shared)` to the crypto stream. The much bigger iteration count here is since the keys are considerably smaller than in the RSA case.

When the receiver wants to receive data he simply reads `Spub` from the image and creates `shared = DH(Spub, Rsec)`, and adds to the crypto stream in the same way as the sender.

Notice that the Curve25519 shared key is 256 bits. This means that there will probably be ~128 bits changed. This is considerably smaller than for RSA and should be used to keep detection down.

#### Encryption
Using the pixel stream, write a 20 byte HMACSHA1 hash sum of the data to be encrypted, with a password from the random stream, and append the data. All data using the pixel stream is subject to the invertBit variable in the pixel stream, so both the HMACSHA1 sum and the data is now encrypted.

#### Decryption
Using the pixel stream, read out a 20 byte HMACSHA1 hash sum from the image and the password from the random stream. Read out data byte by byte until the hash sum matches.

#### Signature checksum
The signature is calculated on a huge checksum list, consisting of SHA-512 and some of the finalists for SHA3, namely SHA3-512, Blake2b-512 and Skein512-512. These are calculated on the actual plain text (note that ED25519 hashes the signed data) and is encrypted before being added to the image. The reason for this is that I want to make sure that someone can't mess with the crypto stream somehow (should be impossible, but still). The header hash is calculated as (simplified) SHA1(data xor random). This means that if you can modify random, you can change it so that the SHA1 can be a hash of any data of equal length. This is acceptable for the header hash, but not for signatures which is implemented so that it's verifiable that the exact decrypted data came from the sender.

The exact format of the signature will be `ED25519(HMAC-SHA3-512(random^4096, data), HMAC-SHA512(random^4096, data), HMAC-Skein512-512(random^4096, data), HMAC-Blake2b-512(random^4096, data))` with different randoms for each algorithm. Since it's HMAC the extra bytes over the block size does matter for security.

#### Encrypted stream format
The encrypted data is scattered around the image, but for simplicitys sake (to be able to verify security without relying on the shuffeling on data), the format is as follows:

<table>
  <thead>
    <tr>
      <td>Field</td>
      <td>Data</td>
      <td>Size</td>
      <td>Encrypted by symmetric key</td>
      <td>Required</td>
      <td>Comment</td>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td rowspan="2">Header</td>
      <td>PKI key data</td>
      <td>256 bits (Elliptic Curve)<hr />
          Key Size (RSA)</td>
      <td>x</td>
      <td></td>
      <td>A symmetric key encrypted with a public RSA key or a Public DH key that in combination with the right secret key will give a shared symmetric key.</td>
    </tr>
    <tr>
      <td>Checksum</td>
      <td>160 bits</td>
      <td>x</td>
      <td>x</td>
      <td>A single HMACSHA1 hash sum of the form <code>HMACSHA1(random(0..255)^40, Enc(random, UserData))</code></td>
    </tr>
    <tr>
      <td>Data</td>
      <td>User Data</td>
      <td></td>
      <td>x</td>
      <td>x</td>
      <td>This is the only field included in the checksum.</td>
    </tr>
    <tr>
      <td>Footer</td>
      <td>Signature</td>
      <td>512 bits</td>
      <td>x</td>
      <td></td>
      <td>A ED25519 signature of the signature checksum. This is put at the end since it's not required and to give full compatibility between signed and unsigned packages.</td>
    </tr>
  </tbody>
</table>

Worth noticing is that the HMACSHA1 hash sum is done on with a password of exactly one block size to optimize speed and the user data encrypted with a seperate crypto key (fetched from the same pseudo random stream). This encryption of the user data is only used in this HMACSHA1 sum and is then thrown away.

As you see in the previous table, the header for symmetric encryption is 160 bits long and leaks no information about the user data.

The header for public key encryption will be the key size of the PKI key + 160 bits and leaks no information about the user data, since the symetric key generated from the PKI data adds to the encryption instead of replacing the encryption for the header and the data.

As shown in the table, everything is encrypted with the symmetric key and there is no known data in the protocol (such as length fields or a boolean informing if there is a PKI encrypted key or not) which an attacker could try to use to gain more knowledge. Notice also that unlike this table there is no end of the User Data until every single pixel in the image has been used up, so without the encryption key it is not possible to know the exact length of the user data. An attack where the attacker is able to decrypt the data could ofcourse allow the attacker to guess the length based on the data it decrypts, but actually decrypting the data would require the attacker to hold the key mass which would also unlock the SHA1 HMAC, so it's not viable to decrypt the data without being able to verify the data against the SHA1 HMAC. Notice that it may be possible for the attacker could get a pretty good approximation of the length of the hidden data anyways, see Known weaknesses.

### Known weaknesses
PBKDF2 is sensitive to SIMD brute force attacks. For this reason, this program uses a modified version of PBKDF2 which removes this weakness. This modified verison, however, has not gone through the same scrutiny as PBKDF2, which means that it may have introduced new weaknesses.

**Using public key cryptography introduces brute force weakness**. Since OAEP has a checksum of sorts anyone with the private RSA key (which should not be the attacker) can brute force the symmetric key without having to verify the header against the data for every single attempt. Since the heaviest workload should be done before the RSA key is added into the mix (by having a strong key or a large number of iterations) this shouldn't be a problem in reality.

**The PNG images are sensitive to steganalysis**. By using statistics based on for examle camera type an attacker can compare the image against a list of known artifacts that should exist. When these doesn't exist an attacker can draw the conclusion that they don't exist because the image has been tampered with, for example by hiding data. Since every written byte has a 50% chance of changing a pixel in the image steganalysis can also be used to figure out approximately how much data is hidden in the image. The less data you hide the smaller the chance of detection.

## Future thoughts
I will add additional PRNG's. The one that comes to mind now is scrypt.

I will add additional formats to hide data in. Primary goal is JPEG, as it opens up the possibility of using MPEG in the future.

As this project is still in early development, I do not guarantee backwards or forwards compatibility between versions of this program.

## Disclaimer
As stated before, **do not trust me!** I will not take responsibility if this crypto is broken alongside with all of your bones as a result from it. Using this program is your choice and what you do with it or what happens because of it is your responsibility. This is delivered as is.

**I do not recommend anyone using this program for truely sensitive information**. There are weaknesses, especially against steganalysis, which allows an attacker to know that there actually is hidden data in the image.

**If you do find a vulnerable aspect of this program that I haven't considered, please contact me!**

