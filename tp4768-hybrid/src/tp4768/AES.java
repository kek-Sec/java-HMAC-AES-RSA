package tp4768;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES encryption ECB mode PKCS5Padding fill mode
 * 
 * @author Petrakis Georgios
 * @see tp4768@edu.hmu.gr
 *
 */
public class AES {

	static String ENCRYPT_CHARSET = "UTF-8";
	static String mode = "AES/ECB/PKCS5Padding";
	public static SecretKeySpec pswd;
	
	public static void main(String[] args) throws Exception {
		init_key();
	}

	public static void init_key()
	{
		try {
			// pairnoume random apo -> /dev/urandom
			SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");

			// Etoimazoume to keygenerator me keysize ---> 128
			KeyGenerator kgen = KeyGenerator.getInstance("AES");

			// set to seed oste akoma kai se apanota calls na min exoume idio rnd
			secureRandom.setSeed("tp4768".getBytes());

			// initialize kgen
			kgen.init(128, secureRandom);

			// generate key
			SecretKey secretKey = kgen.generateKey();

			// encodeFormat == raw bytes with pkcs5 encoding
			byte[] enCodeFormat = secretKey.getEncoded();

			// ftiaxnoume to key me vasi to raw byte feed apo panw
			SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
			  pswd = key;
			  
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}
	
	public  String encrypt(String content) {
		try {

			// Setaroume providers giati exw linux kai akoma den exw kataferei na to ftia3w
			// na doulevei
			Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

			//dhlwnw ena cipher algo -> AES/ECB/PKCS5
			Cipher cipher = Cipher.getInstance(mode);

			//spame to plaintext se byte
			byte[] byteContent = content.getBytes(ENCRYPT_CHARSET);

			// Initialize
			cipher.init(Cipher.ENCRYPT_MODE, pswd);
			
			//get result
			byte[] result = cipher.doFinal(byteContent);

			if (result != null && result.length > 0) {
				/*
				 * Note: return new String(result,ENCRYPT_CHARSET);
				 * javax.crypto.IllegalBlockSizeException will appear: Input length must be
				 * multiple of 16 when decrypting with padded cipher The encrypted byte array
				 * cannot be cast to a string. Strings and byte arrays are not reciprocal in
				 * this case; you need to convert binary data to hexadecimal representation
				 * 
				 * TL:DR logo padding prepei ta block na einai 16ria/ to ciphertext den ginete string mono hexstring
				 */
				return parseByte2HexStr(result);
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decrypt
	 * 
	 * @param content  to be decrypted
	 * @param password decryption key
	 * @return
	 */
	public String decrypt(String content) throws Exception {
		try {
			if (content == null) {
				return null;
			}
			//pernoume to omorfo ciphertext kai to kanoume binary afou den 8a to dei kaneis kai mono etsi to trwei to algo
			byte[] newContent = parseHexStr2Byte(content);
			
			
			Cipher cipher = Cipher.getInstance(mode);

			cipher.init(Cipher.DECRYPT_MODE, pswd);// apla gyrname ton diakopti

			byte[] result = cipher.doFinal(newContent);
			if (result != null && result.length > 0) {
				return new String(result, "UTF-8");
			}
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	//Utils , documentation ends here have fun

	/**
	 * Convert binary to hexadecimal
	 * 
	 * @param buf
	 * @return
	 */
	public static String parseByte2HexStr(byte buf[]) {
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < buf.length; i++) {
			String hex = Integer.toHexString(buf[i] & 0xFF);
			if (hex.length() == 1) {
				hex = '0' + hex;
			}
			sb.append(hex.toUpperCase());
		}
		return sb.toString();
	}

	/**
	 * Convert hex to binary
	 * 
	 * @param hexStr
	 * @return
	 */
	public static byte[] parseHexStr2Byte(String hexStr) {
		if (hexStr.length() < 1)
			return null;
		byte[] result = new byte[hexStr.length() / 2];
		for (int i = 0; i < hexStr.length() / 2; i++) {
			int high = Integer.parseInt(hexStr.substring(i * 2, i * 2 + 1), 16);
			int low = Integer.parseInt(hexStr.substring(i * 2 + 1, i * 2 + 2), 16);
			result[i] = (byte) (high * 16 + low);
		}
		return result;
	}

}