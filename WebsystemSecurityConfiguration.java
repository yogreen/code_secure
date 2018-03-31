package com.websystem.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.logging.Logger;

import com.websystem.util.PlatformUtil;

public class WebsystemSecurityConfiguration {

	private static final String CURRENT_BASE_DIR_KEY = "current_base_dir";
	private ResourceBundle bundle;
	private RSAPrivateKey common_rsa_prv;
	private RSAPublicKey common_rsa_pub;
	private CommonRSAKeyGen commonkeygen;
	private Properties entryProps;
	private boolean isInitial = false;

	private Logger logger = Logger.getLogger("WebsystemSecurityConfiguration");

	public WebsystemSecurityConfiguration() {

		bundle = ResourceBundle
				.getBundle(WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_ITEM);
		entryProps = new Properties();
		commonkeygen = commonKeyGenFactory();
		if (!isInitial) {
			initial();
			initialKeyFile();
		}

	}
	CommonRSAKeyGen commonKeyGenFactory() {
		CommonRSAKeyGen keygen = null;
		int keysize = loadKeysize();
		keygen = new CommonRSAKeyGen(keysize,
				WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_KEYTYPE,
				true);
		return keygen;
	}
	void initial() {
		entryProps
				.put(WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_ENTRY_DIR_KEY,
						bundle.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_ENTRY_DIR_KEY));
		Path p = null;
		for (String name : entryProps.stringPropertyNames()) {
			String dirs = entryProps.getProperty(name);
			p = Paths.get(dirs);
			if (!p.toFile().exists()) {
				try {
					Files.createDirectories(p);
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		p = Paths.get(p.toFile().getPath(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_ENTRY_FILE);
		if (!p.toFile().exists()) {
			logger.info(String
					.format("File: %s, is not found.",
							WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_ENTRY_FILE));
			return;
		}
		entryProps.put(CURRENT_BASE_DIR_KEY, p.toFile().getParent());
		try {
			InputStream ins = new FileInputStream(p.toFile());
			entryProps.load(ins);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		isInitial = true;

	}
	void initialKeyFile() {
		String common_dir = bundle
				.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_DIR_KEY);
		if (common_dir == null || common_dir.isEmpty()) {
			throw new RuntimeException(
					String.format(
							"%s must set in %s.",
							WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_DIR_KEY,
							WebsystemSecurityConstance.WEBSYS_SECURITY_CONFIG_FILE));
		}
		File file = new File(common_dir);
		Path path = Paths.get(file.getPath());
		if (!file.exists()) {
			try {
				Files.createDirectories(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		common_rsa_prv = commonkeygen.createRSAPrivateKey();
		common_rsa_pub = commonkeygen.createRSAPublicKey();
		String baseDir = loadCommonKeyPath().toString();
		path = Paths
				.get(baseDir,
						WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PRV_FILE_KEY);
		Path pub = Paths
				.get(baseDir,
						WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PUB_FILE_KEY);
		if (!path.toFile().exists()) {
			try {
				Files.createFile(path);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		if (!pub.toFile().exists()) {
			try {
				Files.createFile(pub);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		try {
			byte[] prvbytes = PlatformUtil.objectMarshal(common_rsa_prv);
			byte[] pubbytes = PlatformUtil.objectMarshal(common_rsa_pub);
			Files.write(path, prvbytes, StandardOpenOption.WRITE);
			Files.write(pub, pubbytes, StandardOpenOption.WRITE);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	public Path loadCommonKeyPath() {
		if (!isInitial) {
			logger.info(String
					.format("workspace initial is incomplete, return null"));
			return null;
		}
		Path commonkeyPath = null;
		String commonkey_dir = bundle
				.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_DIR_KEY);
		if (commonkey_dir.isEmpty()) {
			commonkey_dir = entryProps.getProperty(CURRENT_BASE_DIR_KEY);
		}
		commonkey_dir = new File(commonkey_dir).getPath();
		commonkeyPath = Paths.get(commonkey_dir);
		return commonkeyPath;
	}
	public String loadEntry_alias() {
		String dir = loadCommonKeyPath().toString();
		String prvkeyPath = Paths
				.get(dir,
						WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PRV_FILE_KEY)
				.toString();
		Object obj = loadFromFile(loadEntry_data_dir(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_ALIAS_FILE,
				prvkeyPath);

		return (String) obj;
	}
	public String loadEntry_data_dir() {
		String path = bundle
				.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_DATA_DIR_KEY);
		path = new File(path).getPath();
		Path p = Paths.get(path);
		if (!p.toFile().exists()) {
			try {
				Files.createDirectories(p);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		return path;
	}
	public String loadEntry_password() {
		String dir = loadCommonKeyPath().toString();
		String prvkeyPath = Paths
				.get(dir,
						WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PRV_FILE_KEY)
				.toString();
		Object obj = loadFromFile(loadEntry_data_dir(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_PASSWORD_FILE,
				prvkeyPath);
		return (String) obj;
	}
	public String loadEntryAlias() {
		if (!isInitial) {
			logger.info(String
					.format("workspace initial is incomplete, return null"));
			return null;
		}
		
		return loadEntry_alias();
	}
	public String loadEntryPassword() {
		if (!isInitial) {
			logger.info(String
					.format("workspace initial is incomplete, return null"));
			return null;
		}
		
		return loadEntry_password();
	}

	@SuppressWarnings("unchecked")
	private Object loadFromFile(String dir, String filename, String prvkeyPath) {
		Object obj = null;
		Path prvKeypath = Paths.get(prvkeyPath);
		Path loadPath = Paths.get(dir, filename);
		try {
			byte[] prvkeybytes = Files.readAllBytes(prvKeypath);
			byte[] contents = Files.readAllBytes(loadPath);
			logger.info(loadPath.toString());
			RSAPrivateKey prvKey = (RSAPrivateKey) PlatformUtil
					.objectUnMarshal(prvkeybytes);
			if(prvKey!=null){
				logger.info(String.format("load %s is up.", "RSAPrivateKey"));
			}else{
				throw new RuntimeException(String.format("load %s is error.", "RSAPrivateKey"));
			}
			List<byte[]> contentlist = (List<byte[]>) PlatformUtil
					.objectUnMarshal(contents);
			if(contentlist!=null){
				logger.info(String.format("load %s is up.", "List<byte[]>"));
			}else{
				throw new RuntimeException(String.format("load %s is error.", "List<byte[]>"));
			}
			RSACipher cipher = new RSACipher();
			obj = cipher.RSAdecode(contentlist, prvKey);
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return obj;
	}
	public int loadKeysize() {
		String keysize = bundle
				.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_KEYSIZE_KEY);
		int size = Integer.parseInt(keysize);
		return size;
	}
	public String loadKeystore_path() {
		String path = null;
		path = bundle
				.getString(WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_DIR_KEY);
		path = new File(path).getPath();
		return path;
	}
	public Path loadKeyStorePath() {
		if (!isInitial) {
			logger.info(String
					.format("workspace initial is incomplete, return null"));
			return null;
		}
		Path keystorePath = null;
		String keystore_dir =loadKeystore_path();
		if (keystore_dir==null||keystore_dir.isEmpty()) {
			keystore_dir = entryProps.getProperty(CURRENT_BASE_DIR_KEY);
		}
		String keystore_file = entryProps
				.getProperty(WebsystemSecurityConstance.WEBSYS_SECURITY_STORE_PRIMARYFILE_KEY);
		if (keystore_file==null||keystore_file.isEmpty()) {
			keystore_file = "websys_keystore.jks";
		}
		keystorePath = Paths.get(keystore_dir, keystore_file);
		return keystorePath;
	}
	public String loadProtected_password() {
		String dir = loadCommonKeyPath().toString();
		String prvkeyPath = Paths
				.get(dir,
						WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PRV_FILE_KEY)
				.toString();
		Object obj = loadFromFile(
				loadEntry_data_dir(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_PROTECTED_PASSWORD_FILE,
				prvkeyPath);
		return (String) obj;
	}

	public String loadProtectedPassword() {
		if (!isInitial) {
			logger.info(String
					.format("workspace initial is incomplete, return null"));
			return null;
		}
		String protectedPassword = loadProtected_password();
		if (protectedPassword==null||protectedPassword.isEmpty()) {
			protectedPassword = loadEntryPassword();
		}
		return protectedPassword;
	}
	public void setEntry_alias(String entry_alias) {
		String targetPath = Paths.get(loadEntry_data_dir(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_ALIAS_FILE)
				.toString();
		write2File(
				entry_alias,
				loadCommonKeyPath().toString(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PUB_FILE_KEY,
				targetPath);
	}
	public void setEntry_password(String entry_password) {
		String targetPath = Paths.get(loadEntry_data_dir(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_PASSWORD_FILE)
				.toString();
		write2File(
				entry_password,
				loadCommonKeyPath().toString(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PUB_FILE_KEY,
				targetPath);

	}
	public void setProtected_password(String protected_password) {
		String targetPath = Paths
				.get(loadEntry_data_dir(),
						WebsystemSecurityConstance.WEBSYS_SECURITY_ENTRY_PROTECTED_PASSWORD_FILE)
				.toString();
		write2File(
				protected_password,
				loadCommonKeyPath().toString(),
				WebsystemSecurityConstance.WEBSYS_SECURITY_COMMON_KEYPAIR_PUB_FILE_KEY,
				targetPath);
	}
	private void write2File(String input, String dir, String pubkeyFile,
			String targetPath) {
		Path pub = Paths.get(dir, pubkeyFile);
		try {
			byte[] pubbytes = Files.readAllBytes(pub);
			RSAPublicKey pubkey = (RSAPublicKey) PlatformUtil
					.objectUnMarshal(pubbytes);
			if(pubkey!=null){
				logger.info(String.format("load %s is up.", "RSAPublicKey"));
			}else{
				throw new RuntimeException(String.format("load %s is error.", "RSAPublicKey"));
			}
			RSACipher cipher = new RSACipher();
			List<byte[]> encodes = cipher.RSAencode(input, pubkey);
			if(encodes!=null){
				logger.info(String.format("RSACipher encode %s is up.", "List<byte[]>"));
			}else{
				throw new RuntimeException(String.format("RSACipher encode %s is error.", "List<byte[]>"));
			}
			byte[] aliasbytes = PlatformUtil.objectMarshal(encodes);
			Path aliaspath = Paths.get(targetPath);
			if (!aliaspath.toFile().exists()) {
				Files.createFile(aliaspath);
			}
			Files.write(aliaspath, aliasbytes, StandardOpenOption.WRITE);
			logger.info(String.format("RSACipher encode %s is completed.", "List<byte[]>"));
		} catch (IOException | ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

}
