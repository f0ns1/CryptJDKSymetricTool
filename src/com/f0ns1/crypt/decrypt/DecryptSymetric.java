package com.f0ns1.crypt.decrypt;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class DecryptSymetric {

	private String type;
	private String privateKey;

	public DecryptSymetric(String type, String privatekey) {
		this.type = type;
		this.privateKey = privatekey;
	}

	public String decrypt(String data, String output) {
		String encData = null;
		switch (type) {
		case "3DES":
			encData = decrypt3DES(data, output);
			break;
		case "AES":
			encData = decryptAES(data, output);
			break;
		case "RC2":
			encData = decryptRC2(data, output);
			break;
		case "RC4":
			encData = decryptRC4(data, output);
			break;
		case "Blowfish":
			encData = decryptBlowfish(data, output);
			break;
		}
		return encData;
	}

	private String decryptBlowfish(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptRC4(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC4");
			Cipher cipher = Cipher.getInstance("RC4");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptRC2(String data, String input) {
		byte[] decData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC2");
			Cipher cipher = Cipher.getInstance("RC2");
			cipher.init(Cipher.DECRYPT_MODE, key);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(decData);
	}

	private String decryptAES(String data, String input) {
		byte[] decData = null;
		try {
			byte[] key = this.privateKey.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secretKey);
			decData = cipher.doFinal((input.equals("B64") ? Base64.getDecoder().decode(data) : Hex.decodeHex(data)));
		} catch (Exception e) {
			System.out.println("Error while decrypting : " + e.toString());
		}
		return new String(decData);
	}

	private String decrypt3DES(String data, String input) {
		byte[] plainText = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(this.privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
			final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			decipher.init(Cipher.DECRYPT_MODE, key, iv);
			plainText = decipher
					.doFinal((input.equals(("Hex")) ? Hex.decodeHex(data) : Base64.getDecoder().decode(data)));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return new String(plainText);
	}

}
