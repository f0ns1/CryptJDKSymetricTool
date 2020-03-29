package com.f0ns1.crypt;

import java.util.ArrayList;
import java.util.List;

import com.f0ns1.crypt.decrypt.DecryptSymetric;
import com.f0ns1.crypt.encrypt.EncryptSymetric;

public class Main {

	public static void main(String[] args) {
		// global
		String privateKey = "My Random private key on plaintext format";

		//test a single algorithm
		//testAlg("3DES", privateKey);

		// test all
		for (String alg : getAlgList()) {
			testAlg(alg, privateKey);
		}

	}

	private static List<String> getAlgList() {
		List<String> list = new ArrayList<String>();
		list.add("3DES");
		list.add("AES");
		list.add("Blowfish");
		list.add("RC2");
		list.add("RC4");
		return list;
	}

	private static void testAlg(String alg, String privateKey) {
		String input="Data to encrypt..." + alg + "";
		EncryptSymetric enc = new EncryptSymetric(alg, privateKey);
		String dataEnc1 = enc.encrypt(input, "B64");
		System.out.println("\n\n============================SYMETRIC ENCRYPTION JDK ========================");
		System.out.println("|| Alg = "+alg);
		System.out.println("|| privateKey = "+privateKey);
		System.out.println("|| \t input = "+input+" \t outputformat= "+"B64");
		System.out.println("|| \t encryptedData = "+dataEnc1);
		System.out.println("============================SYMETRIC ENCRYPTION JDK========================\n");
		String dataEnc2 = enc.encrypt(input, "Hex");
		System.out.println("============================SYMETRIC ENCRYPTION JDK ========================");
		System.out.println("|| Alg = "+alg);
		System.out.println("|| privateKey = "+privateKey);
		System.out.println("|| \t input = "+input+" \t outputformat= "+"Hex");
		System.out.println("|| \t encryptedData = "+dataEnc2);
		System.out.println("============================SYMETRIC ENCRYPTION JDK========================\n\n");

		DecryptSymetric dec = new DecryptSymetric(alg, privateKey);
		String output = dec.decrypt(dataEnc1, "B64");
		System.out.println("============================SYMETRIC DECRYPTION JDK ========================");
		System.out.println("|| Alg = "+alg);
		System.out.println("|| privateKey = "+privateKey);
		System.out.println("|| \t input = "+dataEnc1+" \t inputFormat= "+"B64");
		System.out.println("|| \t decryptedData = "+output);
		System.out.println("============================SYMETRIC DECRYPTION JDK========================\n");
		String output2 = dec.decrypt(dataEnc2, "Hex");
		System.out.println("============================SYMETRIC DECRYPTION JDK ========================");
		System.out.println("|| Alg = "+alg);
		System.out.println("|| privateKey = "+privateKey);
		System.out.println("|| \t input = "+dataEnc2+" \t inputFormat= "+"Hex");
		System.out.println("|| \t decryptedData = "+output2);
		System.out.println("============================SYMETRIC DECRYPTION JDK========================\n\n");
		

	}

}
