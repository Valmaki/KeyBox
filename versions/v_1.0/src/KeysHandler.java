package me.keys;

import java.io.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.*;
import java.security.spec.*;
import java.nio.charset.StandardCharsets;

public class KeysHandler {
	public static void main(String[] args) throws Exception {
		Scanner scanner = new Scanner(System.in, "UTF-8");
		while (true) {
			System.out.print("Set operation! (c-create/e-edit/p-print/l-exit) ");
			String op = scanner.nextLine();
			try {
				if (op.equals("l")) {
					break;
				} else if (op.equals("c")) {
					create(scanner);
				} else if (op.equals("e")) {
					edit(scanner);
				} else if (op.equals("p")) {
					print(scanner);
				} else {
					System.err.println("Invalid operation!");
				}
			} catch (Exception e) {
				System.err.println(e);
			}
		}
	}

	private static void create(Scanner scanner) throws Exception {
		System.out.print("Algorithm name: ");
		String algorithm = scanner.nextLine();
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(algorithm);
			System.out.print("The key size: ");
			int size = scanner.nextInt();
			scanner.nextLine();
			keyPairGen.initialize(size);
			KeyPair keyPair = keyPairGen.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			algorithm = publicKey.getAlgorithm();
			byte[] algorithmb = algorithm.getBytes(StandardCharsets.UTF_8);
			int first = (algorithmb.length << 3) | 0x03; //xxxxx011
			if (first > 255) {
				System.err.println("The algorithm name is too long!");
				return;
			}
			System.out.print("Save to: ");
			String path = scanner.nextLine();
			try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
				raf.seek(0);
				raf.write((byte) first & 0xFF);
				byte[] intb = new byte[4];
				raf.write(intb);
				raf.write(intb);
				raf.write(algorithmb);
				//Public key
				int pubStart = (int) raf.getFilePointer();
				byte[] pub = publicKey.getEncoded();
				writeInt(intb, pub.length);
				raf.write(intb);
				raf.write(pub);
				//Private key
				int privateStart = (int) raf.getFilePointer();
				byte[] privateKey = keyPair.getPrivate().getEncoded();
				writeInt(intb, privateKey.length);
				raf.write(intb);
				raf.write(privateKey);
				//Linking
				writeInt(intb, pubStart);
				raf.seek(1);
				raf.write(intb);
				writeInt(intb, privateStart);
				raf.write(intb);
			}
			System.out.println("The " + algorithm + " keypair saved to \"" + path + "\".");
		} catch (NoSuchAlgorithmException e) {
			try {
				KeyGenerator kg = KeyGenerator.getInstance(algorithm);
				System.out.print("The key size: ");
				int size = scanner.nextInt();
				scanner.nextLine();
				SecureRandom r;
				try {
					r = SecureRandom.getInstanceStrong();
				} catch (Exception ex) {
					r = new SecureRandom();
				}
				kg.init(size, r);
				SecretKey k = kg.generateKey();
				byte[] key = k.getEncoded();
				algorithm = k.getAlgorithm();
				byte[] algorithmb = algorithm.getBytes(StandardCharsets.UTF_8);
				int first = (algorithmb.length << 3) | 0x04; //xxxxx100
				if (first > 255) {
					System.err.println("The algorithm name is too long!");
					return;
				}
				System.out.print("Save to: ");
				String path = scanner.nextLine();
				try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
					raf.seek(0);
					raf.write((byte) first & 0xFF);
					byte[] intb = new byte[4];
					raf.write(intb);
					raf.write(algorithmb);
					//Key
					int start = (int) raf.getFilePointer();
					writeInt(intb, key.length);
					raf.write(intb);
					raf.write(key);
					//Linking
					writeInt(intb, start);
					raf.seek(1);
					raf.write(intb);
				}
				System.out.println("The " + algorithm + " key saved to \"" + path + "\".");
			} catch (NoSuchAlgorithmException ex) {
				System.err.println(algorithm + " is not available!");
			}
		}
	}
	
	private static void edit(Scanner scanner) throws Exception {
		System.out.print("Path to the keys file: ");
		String path = scanner.nextLine();
		KeyPackage keys = new KeyPackage(new File(path));
		byte[] pub = keys.getPublicKeyBytes();
		byte[] priv = keys.getPrivateKeyBytes();
		byte[] sec = keys.getSecretKeyBytes();
		String alg = keys.getAlgorithm();
		while (true) {
			System.out.print("Operation (r-remove from file/a-add to file/f-save modifications): ");
			String op = scanner.nextLine();
			if (op.equals("r")) {
				System.out.print("Set the removed key (");
				if (pub != null) System.out.print("pub-public key");
				if (priv != null) System.out.print(pub != null ? "/priv-private key" : "priv-private key");
				if (sec != null) System.out.print((pub != null || priv != null) ? "/s-secret key" : "s-secret key");
				System.out.print(") ");
				String key = scanner.nextLine();
				if (key.equals("pub") && pub != null) {
					pub = null;
					System.out.println("Public key removed!");
				} else if (key.equals("priv") && priv != null) {
					priv = null;
					System.out.println("Private key removed!");
				} else if (key.equals("s") && sec != null) {
					sec = null;
					System.out.println("Secret key removed!");
				} else {
					System.err.println("Invalid key!");
					continue;
				}
			} else if (op.equals("a")) {
				System.out.print("Copy key from: ");
				String from = scanner.nextLine();
				KeyPackage fromKeys;
				try {
					fromKeys = new KeyPackage(new File(from));
				} catch (Exception e) {
					System.out.println(e);
					continue;
				}
				String fromAlg = fromKeys.getAlgorithm();
				if (!alg.equals(fromAlg)) {
					System.err.println("Invalid algorithm!\nIn the \"" + path + "\" file the key(s) use " + alg + " algorithm, but in the \"" + from + "\" file the key(s) use " + fromAlg + "algorithm.");
					continue;
				}
				byte[] pu = fromKeys.getPublicKeyBytes();
				byte[] pr = fromKeys.getPrivateKeyBytes();
				byte[] s = fromKeys.getSecretKeyBytes();
				System.out.print("Set the added key (");
				if (pu != null && pub == null) System.out.print("pub-public key");
				if (pr != null && priv == null) System.out.print((pu != null && pub == null) ? "/priv-private key" : "priv-private key");
				if (s != null && sec == null) System.out.print(((pu != null && pub == null) || (pr != null && priv == null)) ? "/s-secret key" : "s-secret key");
				System.out.print(") ");
				String key = scanner.nextLine();
				if (key.equals("pub") && pub == null) {
					pub = pu;
					System.out.println("Public key added!");
				} else if (key.equals("priv") && priv == null) {
					priv = pr;
					System.out.println("Private key added!");
				} else if (key.equals("s") && sec == null) {
					sec = s;
					System.out.println("Secret key added!");
				} else {
					System.err.println("Invalid key!");
					continue;
				}
			} else if (op.equals("f")) {
				try (RandomAccessFile raf = new RandomAccessFile(path, "rw")) {
					byte[] algorithmb = alg.getBytes(StandardCharsets.UTF_8);
					int first = (algorithmb.length << 3);
					if (pub != null) first |= 0x01;
					if (priv != null) first |= 0x02;
					if (sec != null) first |= 0x04;
					if (first > 255) {
						System.err.println("Can't save!\nThe algorithm name is too long!");
						raf.close();
						return;
					}
					raf.seek(0);
					raf.write((byte) first & 0xFF);
					byte[] intb = new byte[4];
					if (pub != null) raf.write(intb);
					if (priv != null) raf.write(intb);
					if (sec != null) raf.write(intb);
					raf.write(algorithmb);
					//Public key
					int pubStart = pub != null ? ((int) raf.getFilePointer()) : -1;
					if (pub != null) {
						writeInt(intb, pub.length);
						raf.write(intb);
						raf.write(pub);
					}
					//Private key
					int privateStart = priv != null ? ((int) raf.getFilePointer()) : -1;
					if (priv != null) {
						writeInt(intb, priv.length);
						raf.write(intb);
						raf.write(priv);
					}
					//Secret key
					int secretStart = sec != null ? ((int) raf.getFilePointer()) : -1;
					if (sec != null) {
						writeInt(intb, sec.length);
						raf.write(intb);
						raf.write(sec);
					}
					//Linking
					raf.seek(1);
					if (pub != null) {
						writeInt(intb, pubStart);
						raf.write(intb);
					}
					if (priv != null) {
						writeInt(intb, privateStart);
						raf.write(intb);
					}
					if (sec != null) {
						writeInt(intb, secretStart);
						raf.write(intb);
					}
				}
				return;
			} else {
				System.err.println("Invalid operation!");
				continue;
			}
		}
	}

	private static void print(Scanner scanner) throws Exception {
		System.out.print("Path to the keys file: ");
		String path = scanner.nextLine();
		KeyPackage keys = new KeyPackage(new File(path));
		while  (true) {
			System.out.print("Key to print (pub-public key/priv-private key/s-secret): ");
			String key = scanner.nextLine();
			byte[] bytes;
			if (key.equals("pub")) {
				bytes = keys.getPublicKeyBytes();
			} else if (key.equals("priv")) {
				bytes = keys.getPrivateKeyBytes();
			} else if (key.equals("s")) {
				bytes = keys.getSecretKeyBytes();
			} else {
				System.out.println("Invalid key!\nSupported keys:\npub - public key\npriv - private key\ns - secret key");
				continue;
			}
			if (bytes != null) {
				System.out.println(keys.getAlgorithm() + " " + key + " key bytes:");
				for (int i = 0; i < bytes.length; i++) {
					System.out.print(bytes[i]);
					if ((i + 1) != bytes.length) System.out.print(", ");
				}
				System.out.println();
				break;
			} else {
				System.err.println("The keys file don't have this key!");
			}
		}
	}


	private static void writeInt(byte[] to, int from) {
		for (int i = 0; i < 4; i++) to[i] = (byte) ((from >>> (24 - (i * 8))) & 0xFF);
	}

}
