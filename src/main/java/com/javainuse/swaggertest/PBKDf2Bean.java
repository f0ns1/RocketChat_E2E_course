package com.javainuse.swaggertest;

public class PBKDf2Bean {
    String pwdBase64= null;
    String saltBase64= null;
    Integer iterations= null;
    Integer keyLength= null;
    String hash= null;

    //getters and setters

    public String getPwdBase64(){
        return this.pwdBase64;
    }
    public void setPwdBase64(String pwdBase64){
        this.pwdBase64=pwdBase64;
    }
    
    public String getSaltBase64(){
        return this.saltBase64;
    }
    public void setSaltBase64(String saltBase64){
        this.saltBase64=saltBase64;
    }
    
    public Integer getIterations(){
        return this.iterations;
    }
    public void setIterations(Integer iterations){
        this.iterations=iterations;
    }

    public Integer getKeyLength(){
        return this.keyLength;
    }
    public void setKeyLength(Integer keyLength){
        this.keyLength=keyLength;
    }

    public String getHash(){
        return this.hash;
    }
    public void setHash(String hash){
        this.hash=hash;
    }
}
