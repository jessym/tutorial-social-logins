package com.jessym.tutorial.security.helpers;

import lombok.NonNull;
import lombok.SneakyThrows;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class EncryptionHelper {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int KEY_ITERATION_COUNT = 100_000; // https://security.stackexchange.com/q/3959
    private static final int KEY_SIZE = 32;
    private static final int IV_SIZE = 16;

    @SneakyThrows
    public static SecretKey generateKey() {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        int keySizeBits = KEY_SIZE * 8;
        generator.init(keySizeBits, RANDOM);
        return generator.generateKey();
    }

    @SneakyThrows
    public static SecretKey generateKey(@NonNull char[] password, @NonNull byte[] salt) {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        int keySizeBits = KEY_SIZE * 8;
        PBEKeySpec keySpec = new PBEKeySpec(password, salt, KEY_ITERATION_COUNT, keySizeBits);
        SecretKey temporaryKey = factory.generateSecret(keySpec);
        keySpec.clearPassword();
        return new SecretKeySpec(temporaryKey.getEncoded(), "AES");
    }

    @SneakyThrows
    public static byte[] encrypt(@NonNull SecretKey key, @NonNull byte[] clearText) {
        byte[] ivBytes = new byte[IV_SIZE];
        RANDOM.nextBytes(ivBytes);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(ivBytes));
        byte[] cipherBytes = cipher.doFinal(clearText);
        return concat(ivBytes, cipherBytes);
    }

    @SneakyThrows
    public static byte[] decrypt(@NonNull SecretKey key, @NonNull byte[] cipherText) {
        byte[][] byteArrays = split(cipherText);
        byte[] ivBytes = byteArrays[0];
        byte[] cipherBytes = byteArrays[1];
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(ivBytes));
        return cipher.doFinal(cipherBytes);
    }

    private static byte[] concat(byte[] ivBytes, byte[] cipherBytes) {
        byte[] concatenatedBytes = new byte[ivBytes.length + cipherBytes.length];
        System.arraycopy(ivBytes, 0, concatenatedBytes, 0, ivBytes.length);
        System.arraycopy(cipherBytes, 0, concatenatedBytes, ivBytes.length, cipherBytes.length);
        return concatenatedBytes;
    }

    private static byte[][] split(byte[] concatenatedBytes) {
        byte[] ivBytes = new byte[IV_SIZE];
        byte[] cipherBytes = new byte[concatenatedBytes.length - IV_SIZE];
        System.arraycopy(concatenatedBytes, 0, ivBytes, 0, IV_SIZE);
        System.arraycopy(concatenatedBytes, IV_SIZE, cipherBytes, 0, concatenatedBytes.length - IV_SIZE);
        return new byte[][]{ivBytes, cipherBytes};
    }

}
