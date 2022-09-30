package com.java.rocketchat.crypto;

import java.util.Base64;
import java.util.Calendar;
import java.math.BigInteger;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;

import java.io.IOException;

import org.spongycastle.asn1.ASN1InputStream;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.asn1.pkcs.RSAPrivateKey;
import org.spongycastle.asn1.x509.SubjectPublicKeyInfo;
import org.spongycastle.asn1.x509.RSAPublicKeyStructure;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;
import org.spongycastle.util.io.pem.PemReader;
import org.spongycastle.asn1.pkcs.RSAPublicKey;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.util.io.pem.PemObject;


import static java.nio.charset.StandardCharsets.UTF_8;
import java.nio.charset.Charset;

public class RSA {
    public static Charset CharsetUTF_8;

    public static final String ALGORITHM = "RSA";

    private static final String PUBLIC_HEADER = "RSA PUBLIC KEY";
    private static final String PRIVATE_HEADER = "RSA PRIVATE KEY";

    private String keyTag;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    public RSA() {
        this.setupCharset();
    }

    public RSA(String keyTag) throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        this.setupCharset();
        this.keyTag = keyTag;
        this.loadFromKeystore();
    }

    private void setupCharset() {

            CharsetUTF_8 = Charset.forName("UTF-8");
    }

    public String getPublicKey() throws IOException {
        byte[] pkcs1PublicKey = publicKeyToPkcs1(this.publicKey);

        return dataToPem(PUBLIC_HEADER, pkcs1PublicKey);
    }

    public String getPrivateKey() throws IOException {
        byte[] pkcs1PrivateKey = privateKeyToPkcs1(this.privateKey);

        return dataToPem(PRIVATE_HEADER, pkcs1PrivateKey);
    }

    public void setPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        this.publicKey = pkcs1ToPublicKey(publicKey);
    }

    public void setPrivateKey(String privateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] pkcs1PrivateKey = pemToData(privateKey);
        this.privateKey = pkcs1ToPrivateKey(pkcs1PrivateKey);
    }


    // This function will be called by encrypt and encrypt64
    private byte[] encrypt(byte[] data) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String encodedMessage = null;
        final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        byte[] cipherBytes = cipher.doFinal(data);
        return cipherBytes;
    }

    // Base64 input
    public String encrypt64(String b64Message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = Base64.getDecoder().decode(b64Message);
        byte[] cipherBytes = encrypt(data);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    // UTF-8 input
    public String encrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] data = message.getBytes(CharsetUTF_8);
        byte[] cipherBytes = encrypt(data);
        return Base64.getEncoder().encodeToString(cipherBytes);
    }

    private byte[] decrypt(byte[] cipherBytes) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        String message = null;
        final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        byte[] data = cipher.doFinal(cipherBytes);
        return data;
    }

    // UTF-8 input
    public String decrypt(String message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.getDecoder().decode(message);
        byte[] data = decrypt(cipherBytes);
        return new String(data, CharsetUTF_8);
    }

    // Base64 input
    public String decrypt64(String b64message) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException {
        byte[] cipherBytes = Base64.getDecoder().decode(b64message);
        byte[] data = decrypt(cipherBytes);
        return Base64.getEncoder().encodeToString(data);
    }

    private String sign(byte[] messageBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature privateSignature = Signature.getInstance(algorithm);
        privateSignature.initSign(this.privateKey);
        privateSignature.update(messageBytes);
        byte[] signature = privateSignature.sign();
        return Base64.getEncoder().encodeToString(signature);
    }

    // b64 message
    public String sign64(String b64message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = Base64.getDecoder().decode(b64message);
        return sign(messageBytes, algorithm);
    }

    //utf-8 message
    public String sign(String message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        byte[] messageBytes = message.getBytes(CharsetUTF_8);
        return sign(messageBytes, algorithm);
    }

    private boolean verify(byte[] signatureBytes, byte[] messageBytes, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        publicSignature.update(messageBytes);
        return publicSignature.verify(signatureBytes);
    }

    // b64 message
    public boolean verify64(String signature, String message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = Base64.getDecoder().decode(message);
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return verify(signatureBytes, messageBytes, algorithm);
    }

    // utf-8 message
    public boolean verify(String signature, String message, String algorithm) throws NoSuchAlgorithmException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidKeyException, SignatureException {
        Signature publicSignature = Signature.getInstance(algorithm);
        publicSignature.initVerify(this.publicKey);
        byte[] messageBytes = message.getBytes(CharsetUTF_8);
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
        return verify(signatureBytes, messageBytes, algorithm);
    }

    private String dataToPem(String header, byte[] keyData) throws IOException {
        PemObject pemObject = new PemObject(header, keyData);
        StringWriter stringWriter = new StringWriter();
        PemWriter pemWriter = new PemWriter(stringWriter);
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        return stringWriter.toString();
    }

    private byte[] pemToData(String pemKey) throws IOException {
        Reader keyReader = new StringReader(pemKey);
        PemReader pemReader = new PemReader(keyReader);
        PemObject pemObject = pemReader.readPemObject();
        return pemObject.getContent();
    }

    private PublicKey pkcs1ToPublicKey(String publicKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Reader keyReader = null;
        try {
            keyReader = new StringReader(publicKey);
            PEMParser pemParser = new PEMParser(keyReader);
            SubjectPublicKeyInfo subjectPublicKeyInfo = (SubjectPublicKeyInfo) pemParser.readObject();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(subjectPublicKeyInfo.getEncoded());
            return KeyFactory.getInstance("RSA").generatePublic(spec);
               } finally {
            if (keyReader != null) {
                keyReader.close();
            }
        }
    }

    private PrivateKey pkcs1ToPrivateKey(byte[] pkcs1PrivateKey) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        ASN1InputStream in = new ASN1InputStream(pkcs1PrivateKey);
        ASN1Primitive obj = in.readObject();
        RSAPrivateKey keyStruct = RSAPrivateKey.getInstance(obj);
        RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(keyStruct.getModulus(), keyStruct.getPrivateExponent());
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(keySpec);
    }

    private byte[] publicKeyToPkcs1(PublicKey publicKey) throws IOException {
        SubjectPublicKeyInfo spkInfo = SubjectPublicKeyInfo.getInstance(publicKey.getEncoded());
        ASN1Primitive primitive = spkInfo.parsePublicKey();
        return primitive.getEncoded();
    }

    private byte[] privateKeyToPkcs1(PrivateKey privateKey) throws IOException {
        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privateKey.getEncoded());
        ASN1Encodable encodeable = pkInfo.parsePrivateKey();
        ASN1Primitive primitive = encodeable.toASN1Primitive();
        return primitive.getEncoded();
    }

    public void loadFromKeystore() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(this.keyTag, null);
        
        if (privateKeyEntry != null) {
            this.privateKey = privateKeyEntry.getPrivateKey();
            this.publicKey = privateKeyEntry.getCertificate().getPublicKey();
        }
    }

    public void deletePrivateKey() throws KeyStoreException, UnrecoverableEntryException, NoSuchAlgorithmException, IOException, CertificateException {
        KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        keyStore.deleteEntry(this.keyTag);
        this.privateKey = null;
        this.publicKey = null;
    }

    public void generate() throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
       this.generate(2048);
    }

    public void generate(int keySize) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ALGORITHM);
        kpg.initialize(keySize);

        KeyPair keyPair = kpg.genKeyPair();
        this.publicKey = keyPair.getPublic();
        this.privateKey = keyPair.getPrivate();
    }

    public void generate(String keyTag) throws IOException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
        this.generate(2048);
    }

}

