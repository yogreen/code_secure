package com.websystem.security;

public interface WebsystemSecurityConstance {

	public static final int WEBSYS_SECURITY_CIPHER_ENCODE_SIZE = 64;
	public static final String WEBSYS_SECURITY_CIPHER_TYPE = "RSA/ECB/PKCS1PADDING";
	public static final String WEBSYS_SECURITY_COMMON_KEYPAIR_DIR_KEY = "common_key_dir";
	public static final String WEBSYS_SECURITY_COMMON_KEYPAIR_PRV_FILE_KEY = "prv.key";
	public static final String WEBSYS_SECURITY_COMMON_KEYPAIR_PUB_FILE_KEY = "pub.key";
	public static final String WEBSYS_SECURITY_CONFIG_FILE = "websys_security.properties";
	public static final String[] WEBSYS_SECURITY_DNAME_BOUNDS = {"CN", "OU",
			"O", "L", "ST", "C"};
	public static final String WEBSYS_SECURITY_ENTRY_ALIAS_FILE = "entry_alias.dat";
	public static final String WEBSYS_SECURITY_ENTRY_DATA_DIR_KEY = "entry_data_dir";
	public static final String WEBSYS_SECURITY_ENTRY_ITEM = "META-INF/configs/websys_security";
	public static final String WEBSYS_SECURITY_ENTRY_PASSWORD_FILE = "entry_pass.dat";
	public static final String WEBSYS_SECURITY_ENTRY_PROTECTED_PASSWORD_FILE = "entry_protected.dat";
	public static final String WEBSYS_SECURITY_KEYSTORE_DEFAULT_FILENAME = "websys_secure.jks";
	public static final String WEBSYS_SECURITY_KEYSTORE_KEYSIZE_KEY = "keypair_size";
	public static final String WEBSYS_SECURITY_KEYSTORE_KEYTYPE = "RSA";
	public static final String WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE = "SHA256withRSA";
	public static final String WEBSYS_SECURITY_KEYSTORE_TYPE = "jks";
	public static final String WEBSYS_SECURITY_STORE_DIR_KEY = "keystore_dir";
	public static final String WEBSYS_SECURITY_STORE_ENTRY_ALIAS_KEY = "entry_alias";
	public static final String WEBSYS_SECURITY_STORE_ENTRY_DIR_KEY = "entry_dir";
	public static final String WEBSYS_SECURITY_STORE_ENTRY_FILE = "websys_security_entry.properties";
	public static final String WEBSYS_SECURITY_STORE_ENTRY_PASSWORD_KEY = "entry_password";
	public static final String WEBSYS_SECURITY_STORE_PRIMARYFILE_KEY = "keystore_file";
	public static final String WEBSYS_SECURITY_STORE_PROTECTED_PASSWORD_KEY = "protected_password";

}
