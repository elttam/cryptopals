package com.cryptopals;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Crypto {

    private final Key key;
    private final GCMParameterSpec gcmParameterSpec;

    public Crypto(String keyValue) {
        byte[] keyBytes = keyValue.getBytes(StandardCharsets.UTF_8);
        key = new SecretKeySpec(keyBytes, "AES");
        gcmParameterSpec = new GCMParameterSpec(128, keyBytes);        
//        gcmParameterSpec = new GCMParameterSpec(128, Arrays.copyOfRange(keyBytes, 0, 12));
    }

    public String encrypt(final String plainText) throws GeneralSecurityException {
        return DatatypeConverter.printHexBinary(transform(plainText.getBytes(StandardCharsets.UTF_8), Cipher.ENCRYPT_MODE));
    }

    public String decrypt(final String data) throws GeneralSecurityException {
        return new String(transform(DatatypeConverter.parseHexBinary(data), Cipher.DECRYPT_MODE), StandardCharsets.UTF_8);
    }

    private synchronized byte[] transform(byte[] data, int mode) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, key, gcmParameterSpec);
        cipher.updateAAD("".getBytes(StandardCharsets.UTF_8));
        return cipher.doFinal(data);
    }
}
