package com.websystem.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.websystem.util.PlatformUtil;

public class RSACipher {

	byte[] rsadecode(List<byte[]> encodeMatrix, RSAPrivateKey privateKey) {
		byte[] bytes = null;
		try {
			Cipher cipher = Cipher
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_CIPHER_TYPE);
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
			int size = encodeMatrix.size();
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < size; i++) {
				byte[] tmps = cipher.doFinal(encodeMatrix.get(i));
				String tmp = new String(tmps, "utf-8");
				sb.append(tmp);
			}
			bytes = Base64Util.base64decode(sb.toString(), "utf-8");

		} catch (NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidKeyException | IllegalBlockSizeException
				| BadPaddingException | UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return bytes;
	}


	public Object RSAdecode(List<byte[]> encodeMatrix, RSAPrivateKey privateKey) {
		Object obj = null;
		byte[] objbytes = rsadecode(encodeMatrix, privateKey);
		try {
			obj = PlatformUtil.objectUnMarshal(objbytes);
		} catch (ClassNotFoundException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return obj;
	}
	

	public List<byte[]> RSAencode(Object obj, RSAPublicKey publicKey) {
		List<byte[]> encodeMatrix = new ArrayList<byte[]>();
		try {
			byte[] objBytes = PlatformUtil.objectMarshal(obj);
			int bounds = WebsystemSecurityConstance.WEBSYS_SECURITY_CIPHER_ENCODE_SIZE;
			Cipher cipher = Cipher
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_CIPHER_TYPE);
			String source = Base64Util.base64econde(objBytes, "utf-8");
			int len = source.length();
			int n = 0;
			int remaining = len % bounds;;
			if (len >= bounds) {
				n = len / bounds;
			}
			len = n + (remaining == 0 ? 0 : 1);
			String[] items = new String[len];
			if (remaining != 0) {
				items[len - 1] = source.substring(n * bounds);
				for (int i = 0; i < len - 1; i++) {
					items[i] = source
							.substring(i * bounds, i * bounds + bounds);
				}

			} else {
				for (int i = 0; i < len; i++) {
					items[i] = source
							.substring(i * bounds, i * bounds + bounds);
				}
			}
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			for (int i = 0; i < len; i++) {
				byte[] tmps = items[i].getBytes("utf-8");
				encodeMatrix.add(cipher.doFinal(tmps));
			}

		} catch (IOException | NoSuchAlgorithmException
				| NoSuchPaddingException | InvalidKeyException
				| IllegalBlockSizeException | BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encodeMatrix;
	}

}
