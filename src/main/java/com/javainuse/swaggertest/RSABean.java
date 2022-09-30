package com.javainuse.swaggertest;

public class RSABean {
    public String message= null;
    public String signature = null;
    public String hash = null;
    public String publicKey = null;
    public String privateKey = null;

    //getters && setters

    public String getMessage(){
        return this.message;
    }
    public void setMessage(String messsage){
        this.message= messsage;
    }

    public String getSignature(){
        return this.signature;
    }
    public void setSignature(String signature){
        this.signature= signature;
    }
    
    public String getHash(){
        return this.hash;
    }
    public void setHash(String hash){
        this.hash= hash;
    }

    public String getPublicKey(){
        return this.publicKey;
    }
    public void setPublicKey(String publicKey){
        this.publicKey= publicKey;
    }
    
    public String getPrivateKey(){
        return this.privateKey;
    }
    public void setPrivateKey(String privateKey){
        this.privateKey= privateKey;
    } 

}
