package com.websystem.security;

import java.io.UnsupportedEncodingException;

import javax.xml.bind.DatatypeConverter;

public class Base64Util {

	public static String base64econde(String data, String charsetmod) {
		String result = null;
		try {
			result = DatatypeConverter.printBase64Binary(data
					.getBytes(charsetmod));
			return result;
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;

	}

	public static String base64econde(byte[] data, String charsetmod) {
		String result = null;
		result = DatatypeConverter.printBase64Binary(data);
		return result;
	}

	public static byte[] base64decode(String base64encode, String charsetmod) {
		byte[] buffer = null;
		buffer = DatatypeConverter.parseBase64Binary(base64encode);
		return buffer;
	}

}
