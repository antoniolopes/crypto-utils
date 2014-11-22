package info.antoniolopes.crypto.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * AES encryption (128 bits) wrapper class (with example in main function)
 */
public class AESCrypto128bits {

	private static SecretKeySpec generateSecretKey(String encryption_key) throws UnsupportedEncodingException, NoSuchAlgorithmException {
		MessageDigest sha = MessageDigest.getInstance("SHA-1");
		byte[] key = encryption_key.getBytes("UTF-8");
		key = sha.digest(key);
		key = Arrays.copyOf(key, 16); // use only first 128 bit (16 bytes)
		return new SecretKeySpec(key, "AES");
	}

	public static String encrypt(String text_to_encrypt, String encryption_key) throws IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, generateSecretKey(encryption_key));
		return Base64.encodeBase64String(cipher.doFinal(text_to_encrypt.getBytes("UTF-8")));
	}

	public static String decrypt(String text_to_decrypt, String encryption_key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, UnsupportedEncodingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, generateSecretKey(encryption_key));
		return new String(cipher.doFinal(Base64.decodeBase64(text_to_decrypt)));
	}

	public static void main(String args[]) {
		try {
			final String text_to_encrypt = "This is the text to encrypt";
			final String encryption_key = "the encryption key"; // can be any size

			String encrypted_text = AESCrypto128bits.encrypt(text_to_encrypt.trim(), encryption_key);
			System.out.println("String to Encrypt: " + text_to_encrypt);
			System.out.println("Encrypted: " + encrypted_text);

			String decrypted_text = AESCrypto128bits.decrypt(encrypted_text, encryption_key);
			System.out.println("String To Decrypt: " + encrypted_text);
			System.out.println("Decrypted String: " + decrypted_text);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | UnsupportedEncodingException | NoSuchAlgorithmException | NoSuchPaddingException e) {
			System.err.println("Error while encrypting/decrypting text: " + e.getMessage());
			e.printStackTrace();
		}
	}
}