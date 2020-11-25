package tp4768;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Base64;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class hmac_hash {

	    public String Hash(String text, SecretKey key)
	    {
	    	// register the BouncyCastleProvider with the Security Manager
			Security.addProvider(new BouncyCastleProvider());

			//Init messageDigest
			String Mac_algorithm = "HmacSHA512";
			Mac myMac;
			try {
				myMac = Mac.getInstance(Mac_algorithm);
				myMac.init(key);
				byte [] dataMac = myMac.doFinal(text.getBytes());

		        return Base64.getEncoder().encodeToString(dataMac);
			} catch (NoSuchAlgorithmException | InvalidKeyException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			return null;

	    }
	    public Boolean checkMatch(String a,String b)
	    {
	    	return a.equalsIgnoreCase(b);
	    }
}
