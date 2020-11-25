package tp4768;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Main {

	public static void main(String[] args) throws NoSuchAlgorithmException {
		
		try {
			//init hmac and aes
			AES ae = new AES();
			ae.init_key();
			hmac_hash hm = new hmac_hash();
			
			//create new users
			User bob = new User();
			User alice = new User();
			
			//generate users' key pair
			bob.user_key_pair = RSA.generate();
			alice.user_key_pair = RSA.generate();
			
			//save each others pub key
			bob.saved_pub_key = alice.user_key_pair.getPublic();
			alice.saved_pub_key = bob.user_key_pair.getPublic();

			//generate aes key and save to bob
			SecretKey sk = ae.pswd;
			bob.aes_key = sk;
			
			byte[] encrypted;
			//Double encryption bob sends key to alice
			encrypted = RSA.encrypt(Base64.getEncoder().encodeToString(sk.getEncoded()), bob.user_key_pair.getPrivate());
			encrypted = RSA.encrypt(encrypted, bob.saved_pub_key,true);	//no padding
			printer(Base64.getEncoder().encodeToString(encrypted),1);
			String decrypted = RSA.decrypt(encrypted,alice.user_key_pair.getPrivate(),alice.saved_pub_key);
			printer(decrypted + "---> OK", 2);
			
			//save key for alice aswell
			byte[] decodedKey = Base64.getDecoder().decode(decrypted);
			alice.aes_key = new SecretKeySpec(decodedKey,0,decodedKey.length,"AES");
			
			//send aes encrypted message and verify with hmac
			String test_message = "bob can you read this?";
			String alice_encrypted = ae.encrypt(test_message);
			String alice_digest = hm.Hash(alice_encrypted, alice.aes_key);
			System.out.println("---------------------------------------------");
			printer(alice_encrypted,2);
			printer(alice_digest,2);
			System.out.println("---------------------------------------------");
			
			//bob receives and verifies!
			String bob_digest = hm.Hash(alice_encrypted, bob.aes_key);
			boolean match = hm.checkMatch(alice_digest, bob_digest);
			printer("hmac check -> " + match,1);
			String decrypt = ae.decrypt(alice_encrypted);
			printer(decrypt,1);
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
 	
		

	}
	//function that prints to the debug out
	//@param message -> the message to be printed
	//@param who -> 1 for bob 2 for alice
	public static void printer(String message,int who)
	{
		if(who == 1)
		{
			System.out.println("\n[BOB] -> " + message);
		}
		else
		{
			System.err.println("\n[ALICE] -> " + message);
		}
	}
	

}
