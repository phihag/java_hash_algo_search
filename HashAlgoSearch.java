package hash_algo_search;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class HashAlgoSearch {

	public static void main(String[] args) throws Exception {
		String password = "abc";
		byte[] left = Base64.getDecoder().decode("gWKZt2Al7uomFS/CTSSeN1WMqsYX3fnU+TBkON9JlOo=");
		byte[] right = Base64.getDecoder().decode("VOnYNY4McJIxJsyGmhH55qwz/1cjWiG2S0ervg3SyeQ=");

		tryDecoding(password, left, right);
		tryDecoding(password, right, left);
	}

	private static List<String> listAlgos() {
		Set<String> res = new HashSet<>();
		res.add("PBKDF2WithHmacSHA1");
		for (Provider provider: Security.getProviders()) {
		  for (String key: provider.stringPropertyNames()) {
		    String name = provider.getProperty(key);
		    if ((name.contains("SHA") || name.contains("ith")) && !name.contains(".") && !name.contains("|")) {
		    	res.add(name);
		    }
		  }
		}
		List<String> list = new ArrayList<>(res);
		java.util.Collections.sort(list);
		return list;
	}

	private static int[] allIterations() {
		// {256, 1000, 1024, 2000, 2048, 4096, 20*1000, 65536}
		int NUM = 100000;
		int res[] = new int[NUM];
		for (int i = 0;i < NUM;i++) {
			res[i] = i+1;
		}
		return res;
	}
	
	private static void tryDecoding(String password, byte[] salt, byte[] target) throws GeneralSecurityException {
		int[] ITERATIONS = allIterations();
		for (String algo : listAlgos()) {
			SecretKeyFactory skf;
			try {
				skf = SecretKeyFactory.getInstance(algo);
			} catch (NoSuchAlgorithmException e) {
				continue;
			}
			
			System.out.print(algo);
			for (int iterations : ITERATIONS) {
				KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, 256);
				SecretKey key = skf.generateSecret(spec);
				byte[] hash = key.getEncoded();
				
				if (Arrays.equals(hash, target)) {
					System.out.println("\nFound match!: algo=" + algo + ", iterations=" + iterations);
				}
			}
			System.out.println();
		}
	}

}
