package com.websystem.security;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public final class CommonRSAKeyGen {
	
	private ThreadLocal<KeyPair> keyPairCache = null;
	
	public CommonRSAKeyGen(int keysize, String algorithm, boolean useSeed){
		keyPairCache = new ThreadLocal<KeyPair>();
		try {
			KeyPairGenerator kg = keyGeneratorFactory(keysize,algorithm,useSeed);
			KeyPair kp = kg.generateKeyPair();
			keyPairCache.set(kp);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	private KeyPairGenerator keyGeneratorFactory(int keysize, String algorithm,boolean useSeed) throws NoSuchAlgorithmException{
		KeyPairGenerator kg = KeyPairGenerator.getInstance(algorithm);
		if(useSeed){
			kg.initialize(keysize, new SecureRandom());
		}else{
			kg.initialize(keysize);
		}
		return kg;
	}
	
	public RSAPrivateKey createRSAPrivateKey(){
		RSAPrivateKey privateKey = null;
		KeyPair kp = keyPairCache.get();
		privateKey = (RSAPrivateKey) kp.getPrivate();
		return privateKey;
	}
	public RSAPublicKey createRSAPublicKey(){
		RSAPublicKey publicKey = null;
		KeyPair kp = keyPairCache.get();
		publicKey = (RSAPublicKey) kp.getPublic();
		return publicKey;
	}

}
