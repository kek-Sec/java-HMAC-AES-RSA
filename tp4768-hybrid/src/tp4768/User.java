package tp4768;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import java.security.Key;

public class User {

	SecretKey aes_key;
	KeyPair user_key_pair;
	Key saved_pub_key;
}
