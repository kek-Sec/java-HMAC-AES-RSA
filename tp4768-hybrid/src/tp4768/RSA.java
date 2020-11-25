package tp4768;

import java.security.SecureRandom;
import java.security.Security;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {


    public static KeyPair generate() {

        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

            // initialize key generator in RSA mode
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");

            //initialize base64 encoder
            Encoder b64 = Base64.getEncoder();

            //Get a secure random
            SecureRandom random = createFixedRandom();

            //get a 2048bit key
            generator.initialize(2048, random);

            KeyPair pair = generator.generateKeyPair();
            Key pubKey = pair.getPublic();
            Key privKey = pair.getPrivate();

            //return key pair
            return pair;

        } catch (Exception e) {
            System.out.println(e);
            return null;
        }
    }

    //encrypt string using RSA with ECB blocks and PKCS1Padding return byte[]
    public static byte[] encrypt(String data, Key publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }
    //no padding
    public static byte[] encrypt(byte[] data, Key publicKey,boolean noPadding) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
    //akrivws to anti8eto apo panw
    public static String decrypt(byte[] data, Key privateKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(data));
    }
    
    //noPadding
    public static String decrypt(byte[] data, Key privateKey,Key publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher chiper2 = Cipher.getInstance("RSA/None/NoPadding");
        chiper2.init(Cipher.DECRYPT_MODE,privateKey);
        data = chiper2.doFinal(data);
    	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE,publicKey);
        return new String(cipher.doFinal(data));
    }




    //#region UTILITIES

    public static SecureRandom createFixedRandom() {
        return new FixedRand();
    }

    private static class FixedRand extends SecureRandom {

        MessageDigest sha;
        byte[] state;

        FixedRand() {
            try {
                this.sha = MessageDigest.getInstance("SHA-1");
                this.state = sha.digest();
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("can't find SHA-1!");
            }
        }

        public void nextBytes(byte[] bytes) {

            int off = 0;

            sha.update(state);

            while (off < bytes.length) {
                state = sha.digest();

                if (bytes.length - off > state.length) {
                    System.arraycopy(state, 0, bytes, off, state.length);
                } else {
                    System.arraycopy(state, 0, bytes, off, bytes.length - off);
                }

                off += state.length;

                sha.update(state);
            }
        }
    }


    //#endregion
}