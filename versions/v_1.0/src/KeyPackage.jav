package me.keys;

import java.io.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;

public class KeyPackage {
	private final File file;
	private final String algorithm;
	private final int publicOff;
	private final int privateOff;
	private final int secretOff;
	public KeyPackage(File file) throws IOException {
		if (!file.exists()) throw new IOException("Keys file isn't exist!");
		this.file = file;
		try (FileInputStream fis = new FileInputStream(file)) {
			int data = fis.read();
			if (data == -1) throw new IOException("Illegal file format!");
			int algorithml = ((data >> 3) & 0x1F);
			byte[] intb = new byte[4];
			publicOff = ((data & 0x01) == 1) ? readInt(intb, fis): -1;
			privateOff = (((data >> 1) & 0x01) == 1) ? readInt(intb, fis): -1;
			secretOff = (((data >> 2) & 0x01) == 1) ? readInt(intb, fis): -1;
			byte[] algorithmb = new byte[algorithml];
			readFully(algorithmb, fis);
			algorithm = new String(algorithmb, StandardCharsets.UTF_8);
		}
	}

	public String getAlgorithm() {
		return algorithm;
	}

	public PublicKey getPublicKey() throws Exception {
		if (publicOff == -1) return null;
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(getPublicKeyBytes());
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePublic(keySpec);
	}
	public byte[] getPublicKeyBytes() throws Exception {
		if (publicOff == -1) return null;
		byte[] r;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(publicOff);
			byte[] intb = new byte[4];
			raf.readFully(intb);
			int length = toInt(intb);
			r = new byte[length];
			raf.readFully(r);
		}
		return r;
	}

	public PrivateKey getPrivateKey() throws Exception {
		if (privateOff == -1) return null;
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(getPrivateKeyBytes());
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
		return keyFactory.generatePrivate(keySpec);
	}
	public byte[] getPrivateKeyBytes() throws Exception {
		if (privateOff == -1) return null;
		byte[] r;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(privateOff);
			byte[] intb = new byte[4];
			raf.readFully(intb);
			int length = toInt(intb);
			r = new byte[length];
			raf.readFully(r);
		}
		return r;
	}

	private SecretKey getSecretKey() throws Exception {
		if (secretOff == -1) return null;
		return new SecretKeySpec(getSecretKeyBytes(), "AES");
	}
	public byte[] getSecretKeyBytes() throws Exception {
		if (secretOff == -1) return null;
		byte[] r;
		try (RandomAccessFile raf = new RandomAccessFile(file, "r")) {
			raf.seek(secretOff);
			byte[] intb = new byte[4];
			raf.readFully(intb);
			int length = toInt(intb);
			r = new byte[length];
			raf.readFully(r);
		}
		return r;
	}

	private static int readInt(byte[] arr, InputStream in) throws IOException {
		if (arr.length != 4) throw new IOException("Illegal int array!");
		readFully(arr, in);
		return toInt(arr);
	}
	private static int toInt(byte[] b) {
		int r = 0;
		for (int i = 0; i < 4; i++) {
			r |= ((b[i] & 0xFF) << (24 - (i * 8)));
		}
		return r;
	}
	private static void readFully(byte[] arr, InputStream in) throws IOException {
		int read = 0;
		while (read < arr.length) {
			int c = in.read(arr, read, arr.length - read);
			if (c == -1) throw new IOException("EOF");
			read += c;
		}
	}
}
