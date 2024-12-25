package org.yozoradevelopment;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Do you want to encrypt (1) or decrypt (2) with AES?");
        int choice = scanner.nextInt();
        scanner.nextLine();

        if (choice == 1) {
            System.out.println("Enter the message you want to encrypt:");
            String message = scanner.nextLine();


            SecretKey secretKey = generateAESKey();

            try {

                byte[] encryptedMessage = encryptAES(message, secretKey);
                System.out.println("Encrypted message (Base64): " + base64Encode(encryptedMessage));
                System.out.println("AES Key: " + bytesToHex(secretKey.getEncoded()));
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                System.err.println("Encryption failed: " + e.getMessage());
            }
        } else if (choice == 2) {
            System.out.println("Enter the encrypted message:");
            String encryptedMessage = scanner.nextLine();

            System.out.println("Enter the AES key:");
            String hexEncodedKey = scanner.nextLine();

            byte[] encryptedBytes = base64Decode(encryptedMessage);
            SecretKey secretKey = new SecretKeySpec(hexToBytes(hexEncodedKey), "AES");

            try {

                String decryptedMessage = decryptAES(encryptedBytes, secretKey);
                System.out.println("Decrypted message: " + decryptedMessage);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                System.err.println("Decryption failed: " + e.getMessage());
            }
        } else {
            System.out.println("Invalid choice.");
        }

        scanner.close();
    }

    private static SecretKey generateAESKey() {
        try {

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");


            keyGen.init(128);

            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            System.err.println("AES algorithm not available: " + e.getMessage());
            return null;
        }
    }

    private static byte[] encryptAES(String message, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        return cipher.doFinal(message.getBytes());
    }

    private static String decryptAES(byte[] encryptedMessage, SecretKey secretKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(encryptedMessage);
        return new String(decryptedBytes);
    }

    private static String base64Encode(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] base64Decode(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}
