package com.java.rocketchat.crypto;


import java.security.SecureRandom;
import java.util.Map;
import java.util.Base64;
import java.util.HashMap;

class RandomBytesModule  {
  private static final String SEED_KEY = "seed";

  public RandomBytesModule( ) {
    System.out.println("RandomBytesModule constructor");
  }



  public String randomBytes(int size) {
      return getRandomBytes(size);
    
  }

  public Map<String, Object> getConstants() {
    final Map<String, Object> constants = new HashMap<>();
    constants.put(SEED_KEY, getRandomBytes(4096));
    return constants;
  }

  private String getRandomBytes(int size) {
    SecureRandom sr = new SecureRandom();
    byte[] output = new byte[size];
    sr.nextBytes(output);
    return Base64.getEncoder().encodeToString(output);
  }
}
