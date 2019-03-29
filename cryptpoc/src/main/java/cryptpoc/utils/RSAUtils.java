package cryptpoc.utils;

import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

import cryptpoc.model.KeyPairResponse;

public class RSAUtils {

	private static final String ALGORITHM = "RSA";

	private RSAUtils() {
		super();
	}

	public static KeyPairResponse generateKeyPair() {
		try {
			KeyPair generatedKeyPair = generateInternalKeyPair();
			byte[] privateKey = generatedKeyPair.getPrivate().getEncoded();
			byte[] publicKey = generatedKeyPair.getPublic().getEncoded();
			KeyPairResponse keyPairResponse = new KeyPairResponse(Base64.getEncoder().encodeToString(publicKey),
					Base64.getEncoder().encodeToString(privateKey));
			return keyPairResponse;
		} catch (Exception e) {
			return null;
		}
	}

	public static String encrypt(String publicKeyAsString, String message) throws Exception {
		Key key = getKeyFromString(publicKeyAsString);
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes()));
	}

	public static String decrypt(String privateKeyAsString, String encrypted) throws Exception {
		Cipher cipher = Cipher.getInstance(ALGORITHM);
		Key key = getKeyFromString(privateKeyAsString);
		cipher.init(Cipher.DECRYPT_MODE, key);
		return new String(cipher.doFinal(Base64.getDecoder().decode(encrypted)));
	}

	private static KeyPair generateInternalKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
		keyGen.initialize(2048);
		return keyGen.genKeyPair();
	}

	private static PrivateKey getPrivateKeyFromString(String privateKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
		byte[] encodedPv = Base64.getDecoder().decode(privateKey);
		PKCS8EncodedKeySpec keySpecPv = new PKCS8EncodedKeySpec(encodedPv);
		return kf.generatePrivate(keySpecPv);
	}

	private static PublicKey getPublicKeyFromString(String publicKeyString)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance(ALGORITHM);
		byte[] decodedPb = Base64.getDecoder().decode(publicKeyString);
		X509EncodedKeySpec keySpecPb = new X509EncodedKeySpec(decodedPb);
		return kf.generatePublic(keySpecPb);
	}

	private static Key getKeyFromString(String keyString) {
		try {
			PrivateKey privateKeyFromString = getPrivateKeyFromString(keyString);
			return privateKeyFromString;
		} catch (Exception e) {
			try {
				return getPublicKeyFromString(keyString);
			} catch (Exception e2) {
				return null;
			}
		}
	}

}
