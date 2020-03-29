package com.f0ns1.crypt.encrypt;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;

public class EncryptSymetric {
	private String type;
	private String privateKey;

	public EncryptSymetric(String type, String privatekey) {
		this.type = type;
		this.privateKey = privatekey;
	}

	public String encrypt(String data, String output) {
		String encData = null;
		switch (type) {
		case "3DES":
			encData = encrypt3DES(data, output);
			break;
		case "AES":
			encData = encryptAES(data, output);
			break;
		case "RC2":
			encData = encryptRC2(data, output);
			break;
		case "RC4":
			encData = encryptRC4(data, output);
			break;
		case "Blowfish":
			encData = encryptBlowfish(data, output);
			break;
		}
		return encData;
	}

	private String encryptBlowfish(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "Blowfish");
			Cipher cipher = Cipher.getInstance("Blowfish");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return outputFormat(encData, output);
	}

	private String encryptRC4(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC4");
			Cipher cipher = Cipher.getInstance("RC4");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return outputFormat(encData, output);
	}

	private String encryptRC2(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "RC2");
			Cipher cipher = Cipher.getInstance("RC2");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			byte[] inputBytes = data.getBytes();
			encData = cipher.doFinal(inputBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return outputFormat(encData, output);
	}

	private String encryptAES(String data, String output) {
		byte[] encData = null;
		try {
			byte[] key = this.privateKey.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			key = sha.digest(key);
			key = Arrays.copyOf(key, 16);
			SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey);
			encData = cipher.doFinal(data.getBytes("UTF-8"));
		} catch (Exception e) {
			System.out.println("Error while encrypting: " + e.toString());
		}
		return outputFormat(encData, output);
	}

	private String encrypt3DES(String data, String output) {
		byte[] encData = null;
		try {
			final MessageDigest md = MessageDigest.getInstance("md5");
			final byte[] digestOfPassword = md.digest(privateKey.getBytes("utf-8"));
			final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
			for (int j = 0, k = 16; j < 8;) {
				keyBytes[k++] = keyBytes[j++];
			}

			final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
			final IvParameterSpec iv = new IvParameterSpec(new byte[8]);
			final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			final byte[] plainTextBytes = data.getBytes("utf-8");
			encData = cipher.doFinal(plainTextBytes);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return outputFormat(encData, output);
	}

	private String outputFormat(byte[] data, String output) {
		String out = null;
		switch (output) {
		case "B64":
			out = (data != null) ? Base64.getEncoder().encodeToString(data) : "Void Encryption";
			break;
		case "Hex":
			out = (data != null) ? Hex.encodeHexString(data) : "Void Encryption";
			break;
		default:

			break;
		}
		return out;
	}

}
