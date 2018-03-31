package com.websystem.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import sun.misc.BASE64Encoder;
import sun.security.tools.keytool.CertAndKeyGen;
import sun.security.x509.AlgorithmId;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

import com.websystem.util.CalendarInstance;
import com.websystem.util.DateUnit;

public final class WebsystemKeygenX509CertAction {

	private final static Calendar timeAt1970 = Calendar.getInstance();
	private CertAndKeyGen certgen;
	private Logger logger = Logger
			.getLogger(WebsystemKeygenX509CertAction.class.getName());

	private PrivateKey privateKey = null;
	private int keysize = -1;

	public WebsystemKeygenX509CertAction() {
		this(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_KEYTYPE,
				WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE,
				new WebsystemSecurityConfiguration().loadKeysize());
	}
	public WebsystemKeygenX509CertAction(String keyType, String signType,
			int keysize) {
		this.keysize = keysize;
		try {
			certgen = new CertAndKeyGen(keyType, signType, "SUN");
			SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
			certgen.setRandom(sr);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		privateKey = certgen.getPrivateKey();
		timeAt1970.set(1970, 0, 0, 0, 0, 0);
	}
	public X509Certificate createX509Certificate(String dname) throws Exception {
		return createX509Certificate(dname,
				WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE,
				null);

	}

	public X509Certificate createX509Certificate(String dname, Calendar date)
			throws Exception {
		return createX509Certificate(dname,
				WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE,
				date);

	}
	public X509Certificate createX509Certificate(String dname, String signAlgo)
			throws Exception {
		return createX509Certificate(dname, signAlgo, null);

	}

	public X509Certificate createX509Certificate(String dname, String signAlgo,
			Calendar date) throws Exception {
		Calendar datenow = Calendar.getInstance();
		long begin = 0;
		if (date == null || datenow.compareTo(date) >= 0) {
			datenow.set(datenow.get(Calendar.YEAR) + 3,
					datenow.get(Calendar.MONTH) + 1,
					datenow.get(Calendar.DATE), datenow.get(Calendar.MINUTE),
					datenow.get(Calendar.SECOND),
					datenow.get(Calendar.MILLISECOND));
			begin = datenow.getTimeInMillis() - timeAt1970.getTimeInMillis()
					- new Date().getTime();
		} else {

			begin = date.getTimeInMillis() - timeAt1970.getTimeInMillis();
		}
		begin = begin / 1000;
		return createX509Certificate(dname, signAlgo, begin);

	}

	/**
	 * 
	 * @param dname
	 * @param signAlgo
	 * @param timelen
	 *            时间长度格式为(天L*24L*60L*60L)
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidKeyException
	 * @throws IOException
	 * @throws CertificateException
	 * @throws SignatureException
	 * @throws UnrecoverableKeyException
	 */
	X509Certificate createX509Certificate(String dname, String signAlgo,
			long timelen) {

		// Generates a random public/private key pair, with a given key size.
		X509Certificate certificate = null;
		try {
			certgen.generate(keysize);
			X500Name subject = new X500Name(dname);

			certificate = certgen.getSelfCertificate(subject, new Date(),
					timelen);
		} catch (InvalidKeyException | IOException | CertificateException
				| SignatureException | NoSuchAlgorithmException
				| NoSuchProviderException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		}

		return certificate;

	}
	private PrivateKey getPrivateKey() {
		return privateKey;
	}
	public X509Certificate[] listX509Certificate(String path) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		return listX509Certificate(path, config.loadEntryAlias(),
				config.loadEntryPassword());

	}
	public X509Certificate[] listX509Certificate(String path,
			String entryAlias, String entryPassword) {
		X509Certificate[] xcerts = null;
		InputStream ins = null;
		try {
			ins = new FileInputStream(path);
			KeyStore keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			keystore.load(ins, entryPassword.toCharArray());
			Certificate[] certs = keystore.getCertificateChain(entryAlias);
			int len = certs.length;
			xcerts = new X509Certificate[len];
			System.arraycopy(certs, 0, xcerts, 0, len);
		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (ins != null) {

				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return xcerts;

	}

	public X509Certificate loaderFromKeyStore() {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		return loaderFromKeyStore(config.loadKeyStorePath().toString());
	}
	public X509Certificate loaderFromKeyStore(String path) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		return loaderFromKeyStore(config.loadEntryAlias(),
				config.loadEntryPassword(), path);
	}
	public X509Certificate loaderFromKeyStore(String alias, String keypasswd,
			String keypath) {
		if (!(new File(keypath).exists())) {
			logger.info(String.format("File: %s not found, return null",
					keypath));
			return null;
		}
		X509Certificate x509cert = null;
		InputStream ins = null;
		try {
			KeyStore ks = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			ins = new FileInputStream(keypath);
			ks.load(ins, keypasswd.toCharArray());
			x509cert = (X509Certificate) ks.getCertificate(alias);
		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}

		}

		return x509cert;
	}

	public void removeAllCertificate(String path) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		removeAllCertificate(path, config.loadEntryAlias(),
				config.loadEntryPassword(), config.loadProtectedPassword());
	}

	void removeAllCertificate(String path, String entryAlias,
			String entryPassword, String protectedPassword) {
		InputStream ins = null;
		try {
			ins = new FileInputStream(path);

			KeyStore keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			keystore.load(ins, entryPassword.toCharArray());
			privateKey = (PrivateKey) keystore.getKey(entryAlias,
					protectedPassword.toCharArray());
			keystore.deleteEntry(entryAlias);

		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException
				| UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	void removeCertificateByFuzzy(String path, String issuerX500Principal,
			String subjectX500Principal, String entryAlias,
			String entryPassword, String protectedPassword) {
		InputStream ins = null;
		OutputStream outs = null;
		try {
			KeyStore keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			ins = new FileInputStream(path);
			keystore.load(ins, entryPassword.toCharArray());
			Certificate[] certs = keystore.getCertificateChain(entryAlias);
			List<Certificate> caches = new ArrayList<Certificate>();
			caches.add(certs[0]);
			int len = certs.length;
			for (int i = 1; i < len; i++) {
				X509Certificate x509 = (X509Certificate) certs[i];
				if (x509.getIssuerX500Principal().getName()
						.contains(issuerX500Principal)
						&& x509.getSubjectX500Principal().getName()
								.contains(subjectX500Principal)) {
					certs[i] = null;
				}
				if (certs[i] != null) {
					caches.add(certs[i]);
				}
			}
			certs = new Certificate[caches.size()];
			privateKey = (PrivateKey) keystore.getKey(entryAlias,
					protectedPassword.toCharArray());
			keystore.deleteEntry(entryAlias);
			caches.toArray(certs);
			keystore.setKeyEntry(entryAlias, privateKey,
					protectedPassword.toCharArray(), certs);
			outs = new FileOutputStream(path);
			keystore.store(outs, entryPassword.toCharArray());
		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException
				| UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}
	public void removeCertificateByPrecisely(String path,
			String issuerX500Principal, String subjectX500Principal) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		removeCertificateByPrecisely(path, issuerX500Principal,
				subjectX500Principal, config.loadEntryAlias(),
				config.loadEntryPassword(), config.loadProtectedPassword());
	}
	void removeCertificateByPrecisely(String path, String issuerX500Principal,
			String subjectX500Principal, String entryAlias,
			String entryPassword, String protectedPassword) {
		InputStream ins = null;
		OutputStream outs = null;
		try {
			ins = new FileInputStream(path);
			KeyStore keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			keystore.load(ins, entryPassword.toCharArray());
			privateKey = (PrivateKey) keystore.getKey(entryAlias,
					protectedPassword.toCharArray());
			Certificate[] certs = keystore.getCertificateChain(entryAlias);
			Certificate[] newcerts = null;
			List<Certificate> certlist = new ArrayList<Certificate>();
			int len = certs.length;
			for (int i = 0; i < len; i++) {
				X509Certificate cert = (X509Certificate) certs[i];
				if (cert.getIssuerX500Principal().getName()
						.equals(issuerX500Principal)
						&& cert.getSubjectX500Principal().getName()
								.equals(subjectX500Principal)) {
					certs[i] = null;
				}
				if (certs[i] != null) {
					certlist.add(certs[i]);
				}
			}
			newcerts = new Certificate[certlist.size()];
			certlist.toArray(newcerts);
			keystore.deleteEntry(entryAlias);
			keystore.setKeyEntry(entryAlias, privateKey,
					protectedPassword.toCharArray(), newcerts);
			outs = new FileOutputStream(path);
			keystore.store(outs, entryPassword.toCharArray());

		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException
				| UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}

	}
	/**
	 * @param keystorePath
	 * 		keystore location
	 * @param entryalias
	 * 		keystore entry user
	 * @param entrypassword
	 *  	entry password
	 * @param protectedpassword
	 * 		The password to protected privateKey 
	 * @param timelen
	 * 		time overflow
	 * @param unit
	 * 		time unit, default 3 year.
	 * @param waitSignature
	 * 		X509Certificate who will be signed.
	 * @return	X509Certificate
	 */
	public X509Certificate signatureCertificateAction(String keystorePath,
			String entryalias, String entrypassword, String protectedpassword,
			int timelen, DateUnit unit, X509Certificate waitSignature) {
		X509Certificate afterSignature = null;
		InputStream ins = null;
		try {
			KeyStore keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			ins = new FileInputStream(keystorePath);
			char[] pp = entrypassword.toCharArray();
			keystore.load(ins, pp);
			Arrays.fill(pp, ' ');
			pp = protectedpassword.toCharArray();
			PrivateKey issuerPrivateKey = (PrivateKey) keystore.getKey(
					entryalias, pp);
			Arrays.fill(pp, ' ');
			X509Certificate sourceCert = (X509Certificate) keystore
					.getCertificate(entryalias);

			PublicKey commonpublickey = waitSignature.getPublicKey();
			byte[] encode = waitSignature.getEncoded();
			X509CertImpl commonx509certimpl = new X509CertImpl(encode);
			X509CertInfo x509certinfo = (X509CertInfo) commonx509certimpl
					.get("x509.info");
			x509certinfo.set("key", new CertificateX509Key(commonpublickey));

			CertificateExtensions certificateextensions = new CertificateExtensions();
			certificateextensions.set("SubjectKeyIdentifier",
					new SubjectKeyIdentifierExtension((new KeyIdentifier(
							commonpublickey)).getIdentifier()));
			x509certinfo.set("extensions", certificateextensions);

			X500Name issuer = new X500Name(sourceCert.getSubjectX500Principal()
					.toString());
			x509certinfo.set("issuer.dname", issuer);
			X500Name subject = new X500Name(waitSignature.getSubjectDN()
					.getName());
			x509certinfo.set("subject.dname", subject);

			AlgorithmId algorithmid = AlgorithmId
					.get(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE);
			x509certinfo.set("algorithmID", new CertificateAlgorithmId(
					algorithmid));
			Date bdate = new Date();
			Date edate = new Date();
			Calendar len = CalendarInstance.selector(bdate, timelen, unit);
			edate.setTime(bdate.getTime() + len.getTimeInMillis()
					- timeAt1970.getTimeInMillis() - bdate.getTime());
			CertificateValidity certificatevalidity = new CertificateValidity(
					bdate, edate);
			x509certinfo.set("validity", certificatevalidity);

			x509certinfo.set("serialNumber", new CertificateSerialNumber(
					(int) (new Date().getTime() / 1000L)));
			CertificateVersion cv = new CertificateVersion(
					CertificateVersion.V3);
			x509certinfo.set(X509CertInfo.VERSION, cv);

			X509CertImpl x509certimplnew = new X509CertImpl(x509certinfo);
			x509certimplnew
					.sign(issuerPrivateKey,
							WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_SIGN_TYPE);

			afterSignature = x509certimplnew;

		} catch (KeyStoreException | NoSuchAlgorithmException
				| CertificateException | IOException
				| UnrecoverableKeyException | InvalidKeyException
				| NoSuchProviderException | SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		return afterSignature;
	}
	public X509Certificate signatureCertificateAction(String keystorePath,
			String entryalias, String entrypassword, String protectedpassword,
			X509Certificate waitSignature) {
		return signatureCertificateAction(keystorePath, entryalias,
				entrypassword, protectedpassword, 3, DateUnit.YEAR,
				waitSignature);
	}
	public void writeCertificateFile(Certificate cert, String path)
			throws IOException, CertificateException {
		X509Certificate certificate = (X509Certificate) cert;
		OutputStream outs = null;
		File file = null;
		try {

			file = new File(path);
			if (file.isFile()) {
				if (!file.exists()) {
					File dir = new File(file.getParent());
					if (!dir.exists()) {
						dir.mkdirs();
					}
				}

			} else {
				throw new RuntimeException(String.format("%s is not a file",
						file));
			}
			outs = new FileOutputStream(path);
			Writer wr = new OutputStreamWriter(outs, "UTF-8");
			wr.write("-----BEGIN CERTIFICATE-----\r\n");
			wr.write(new BASE64Encoder().encode(certificate.getEncoded()));
			wr.write("-----END CERTIFICATE-----\r\n");
			wr.flush();
			wr.close();

		} finally {
			if (outs != null) {
				outs.close();
			}
		}

	}
	public void writeCertificateToKeyStore(Certificate cert) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		writeCertificateToKeyStore(cert, config.loadKeyStorePath().toString());
	}
	public void writeCertificateToKeyStore(Certificate cert, String path) {
		WebsystemSecurityConfiguration config = new WebsystemSecurityConfiguration();
		writeCertificateToKeyStore(cert, config.loadEntryAlias(),
				config.loadEntryPassword(), config.loadProtectedPassword(),
				path);
	}
	private void writeCertificateToKeyStore(Certificate cert, String alias,
			String entryPassword, String protectedPassword, String path) {
		KeyStore keystore = null;
		Certificate[] certChains = null;
		OutputStream outs = null;
		InputStream ins = null;
		try {
			keystore = KeyStore
					.getInstance(WebsystemSecurityConstance.WEBSYS_SECURITY_KEYSTORE_TYPE);
			File file = new File(path);
			if (!file.exists()) {
				logger.info(String.format(
						"%s is not found, don't do nothing but return.", file));
				return;
			}
			try {
				ins = new FileInputStream(path);
				keystore.load(ins, entryPassword.toCharArray());
			} catch (Exception e) {
				// TODO Auto-generated catch block
				try {
					keystore.load(null, null);
					outs = new FileOutputStream(path);
					certChains = new Certificate[1];
					certChains[0] = cert;
					keystore.setKeyEntry(alias, getPrivateKey(),
							protectedPassword.toCharArray(), certChains);
					keystore.store(outs, entryPassword.toCharArray());
					logger.info(String.format(
							"store %s is complete, certChain length is: %d.",
							((X509Certificate) cert).getSubjectX500Principal(),
							1));

				} catch (Exception fe) {
					// TODO Auto-generated catch block
					throw new RuntimeException(fe);
				}
				return;
			}

			certChains = keystore.getCertificateChain(alias);
			privateKey = (PrivateKey) keystore.getKey(alias,
					protectedPassword.toCharArray());
			int len = certChains.length;
			boolean isEquals = false;
			for (int i = 0; i < len; i++) {
				if (certChains[i].equals(cert)) {
					certChains[i] = cert;
					outs = new FileOutputStream(path);
					keystore.setKeyEntry(alias, privateKey,
							protectedPassword.toCharArray(), certChains);
					keystore.store(outs, entryPassword.toCharArray());
					isEquals = true;
					break;
				}

			}
			if (!isEquals) {

				Certificate[] newcertChains = new Certificate[certChains.length + 1];
				newcertChains[0] = cert;
				System.arraycopy(certChains, 0, newcertChains, 1,
						certChains.length);
				outs = new FileOutputStream(path);
				keystore.setKeyEntry(alias, privateKey,
						protectedPassword.toCharArray(), newcertChains);
				keystore.store(outs, entryPassword.toCharArray());
				logger.info(String.format(
						"store %s is complete,certChain length is: %d.",
						((X509Certificate) cert).getSubjectX500Principal(),
						newcertChains.length));
			}
		} catch (KeyStoreException | IOException | NoSuchAlgorithmException
				| CertificateException | UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			throw new RuntimeException(e);
		} finally {
			if (ins != null) {
				try {
					ins.close();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
	}

}
