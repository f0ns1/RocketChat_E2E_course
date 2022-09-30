package com.javainuse.swaggertest;

import java.util.Base64;
import java.util.HashMap;

import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.java.rocketchat.crypto.CryptoService;
import com.java.rocketchat.crypto.RCTAes;
import com.java.rocketchat.crypto.RCTHmac;
import com.java.rocketchat.crypto.RCTPbkdf2;
import com.java.rocketchat.crypto.RCTRsa;

@RestController
public class cryptoController {
	private static final String CONTEXT= "/api/v1";
	private static final String RANDOM_BYTES=CONTEXT+"/randomBytes";
	private static final String AES_ENCRYPT=CONTEXT+"/aes-encrypt";
	private static final String AES_DECRYPT=CONTEXT+"/aes-decrypt";
	private static final String RSA_GENERATE_KEYS=CONTEXT+"/rsa-generate-keys";
	private static final String RSA_ENCRYPT=CONTEXT+"/rsa-encrypt";
	private static final String RSA_DECRYPT=CONTEXT+"/rsa-decrypt";
	private static final String RSA_SIGN=CONTEXT+"/rsa-sign";
	private static final String RSA_VERIFY=CONTEXT+"/rsa-verify";
	private static final String HMAC=CONTEXT+"/hmac";
	private static final String PBKDF2=CONTEXT+"/pbkdf2";


	@RequestMapping(method = RequestMethod.POST, value = RANDOM_BYTES)
	public String randomBytes(@RequestBody RandomBytesBean bean) {
		CryptoService service = new CryptoService();
		Integer size = Integer.parseInt(bean.getSize());
		String  output = service.getRandomBytes(size);
		System.out.println("randomBytes: "+output);
		return output;
	}
	/**
	 * @param bean
	 * @return
	 */
	@RequestMapping(method = RequestMethod.POST, value = AES_ENCRYPT)
	public String AESencrypt(@RequestBody AESBean bean) {
		RCTAes aes = new RCTAes();

		String textBase64=bean.getTextBase64();
		String hexKey=bean.getHexKey();
		String hexIv=bean.getHexKey();
		String output="";
		try{
			output = aes.encrypt(textBase64, hexKey, hexIv);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("AESencrypt: "+output);
		return output;
	}
	@RequestMapping(method = RequestMethod.POST, value = AES_DECRYPT)
	public String AESDecrypt(@RequestBody AESBean bean) {
		RCTAes aes = new RCTAes();
		String  output="";
		try{
			String ciphertext=bean.getCipherText();
			//ciphertext="X/o1IvAYHJPkVggJ3nnkk7ot03N97VBIdyD9tfGGZfi3QtoTelRS8y9VEQnJwdf0mwO8fGj9v/tFT1R/X1kPCEIfh7MnfacsUtNDztbIEAJhCIWZrpXxxTkJSCqVZrk12ZDQmQxk5B6YIbuWcREPlA==";
			String hexKey=bean.getHexKey();
			//hexKey="5c8db182c7f3edf9575c3a181acbbbbc";
			String hexIv=bean.getHexIv();
			//hexIv="2bd319ff7d7463298dc12f0e38a5bc6a";
			output = aes.decrypt(ciphertext, hexKey, hexIv);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("AESdecrypt: "+output);
		return new String(Base64.getDecoder().decode(output));
	}
	
	@RequestMapping(method = RequestMethod.POST, value = HMAC)
	public String hmac(@RequestBody HMACBean bean) {
		RCTHmac hmac = new RCTHmac();
		String output="";
		try{
			String text=bean.getText();
			String key=bean.getKey();
			output = hmac.hmac256(text, key);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("hmac: "+output);
		return output;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = RSA_GENERATE_KEYS)
	public String RSAgenerateKeys(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		HashMap<String,Object> output = null;
		try{
			int keys= 2048;
			output = rsa.generateKeys(keys);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("RSAgenerateKeys: "+output);
		return output.toString();
	}
	
	@RequestMapping(method = RequestMethod.POST, value = RSA_ENCRYPT)
	public String RSAencrypt(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		String output = null;
		try{
			String message=bean.getMessage();
			String publicKey=bean.getPublicKey();
			output = rsa.encrypt(message, publicKey);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("RSAEncrypt: "+output);
		return output;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = RSA_DECRYPT)
	public String RSAdecrypt(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		String output = null;
		try{
			String message=bean.getMessage();
			String privateKey=bean.getPrivateKey();
			output = rsa.decrypt(message, privateKey);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("RSAEncrypt: "+output);
		return output;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = RSA_SIGN)
	public String RSASign(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		String output = null;
		try{
			String message=bean.getMessage();
			String privateKey=bean.getPrivateKey();
			String hash =bean.getHash();
			output = rsa.sign(message, privateKey, hash);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("RSASign: "+output);
		return output;
	}
	
	@RequestMapping(method = RequestMethod.POST, value = RSA_VERIFY)
	public String RSAVerify(@RequestBody RSABean bean) {
		RCTRsa rsa = new RCTRsa();
		boolean output = false;
		try{
			String signature = bean.getSignature();
			String message = bean.getMessage();
			String publicKey = bean.getPublicKey();
			String hash = bean.getHash();
			output = rsa.verify(signature, message, publicKey, hash);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("RSAVerify: "+output);
		return (output)?"true":"false";
	}
	
	@RequestMapping(method = RequestMethod.POST, value = PBKDF2)
	public String pbkdf2(@RequestBody PBKDf2Bean bean) {
		RCTPbkdf2 pbkdf2 = new RCTPbkdf2();
		String output = null;
		try{
			String pwdBase64=bean.getPwdBase64();
			String saltBase64=bean.getSaltBase64();
			Integer iterations=bean.getIterations();
			Integer keyLen=bean.getKeyLength();
			String hash = bean.getHash();
			byte[] out = pbkdf2.hash(pwdBase64, saltBase64, iterations, keyLen, hash);
			output = Base64.getEncoder().encodeToString(out);
		}catch(Exception e){
			e.printStackTrace();
		}
		System.out.println("Pbkdf2: "+output);
		return output;
	}
}
