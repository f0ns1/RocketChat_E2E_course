package com.java.rocketchat.crypto;

public class CryptoService{
    public CryptoService(){
        System.out.println("Constructor");
    }

    public String  getRandomBytes(int size){
        RandomBytesModule random = new RandomBytesModule();
        return random.randomBytes(size);
    }

    


}