package com.slashmark.internship;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Scanner;

public class PasswordGenerator {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Password generation
        String generatedPassword = generatePassword();
        System.out.println("Generated Password: " + generatedPassword);

        // Password encryption and decryption example
        System.out.print("\nEnter a master password for encryption: ");
        String masterPassword = scanner.nextLine();

        // Encrypt the generated password
        String encryptedPassword = encryptPassword(generatedPassword, masterPassword);
        System.out.println("Encrypted Password: " + encryptedPassword);

        // Decrypt the encrypted password
        String decryptedPassword = decryptPassword(encryptedPassword, masterPassword);
        System.out.println("Decrypted Password: " + decryptedPassword);

        scanner.close();
    }

    private static String generatePassword() {
        // Define the characters that can be used in the password
        String passwordChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";

        // Define the length of the password
        int passwordLength = 12;

        // Generate a secure random password
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder password = new StringBuilder(passwordLength);
        for (int i = 0; i < passwordLength; i++) {
            int randomIndex = secureRandom.nextInt(passwordChars.length());
            password.append(passwordChars.charAt(randomIndex));
        }

        return password.toString();
    }

    private static String encryptPassword(String password, String masterPassword) {
        try {
            // Use PBKDF2 for key derivation
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), masterPassword.getBytes(), 65536, 256);
            byte[] secretKey = factory.generateSecret(spec).getEncoded();

            // Encrypt the password using XOR operation
            byte[] passwordBytes = password.getBytes();
            for (int i = 0; i < passwordBytes.length; i++) {
                passwordBytes[i] ^= secretKey[i % secretKey.length];
            }

            return Base64.getEncoder().encodeToString(passwordBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String decryptPassword(String encryptedPassword, String masterPassword) {
        try {
            // Use PBKDF2 for key derivation
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(masterPassword.toCharArray(), masterPassword.getBytes(), 65536, 256);
            byte[] secretKey = factory.generateSecret(spec).getEncoded();

            // Decrypt the password using XOR operation
            byte[] encryptedBytes = Base64.getDecoder().decode(encryptedPassword);
            for (int i = 0; i < encryptedBytes.length; i++) {
                encryptedBytes[i] ^= secretKey[i % secretKey.length];
            }

            return new String(encryptedBytes);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
}
