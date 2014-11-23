crypto-utils
=====================================

I needed a quick and dirty way to do some AES encrypting/decrypting with a 128 bits encryption key in Java. So I created this util class.

I might add some other encryption techniques in here, hence the generic "crypto-utils" name for the repo.


Dependencies
------------

Apache commons codec (included in the lib folder) for Base64 encoding/decoding

Example
-------

You can check the ''main'' function in the util class but the gist of it is this:

    final String text_to_encrypt = "This is the text to encrypt";
    final String encryption_key = "the encryption key"; // can be any size

    String encrypted_text = AESCrypto128bits.encrypt(text_to_encrypt, encryption_key);

    String decrypted_text = AESCrypto128bits.decrypt(encrypted_text, encryption_key);