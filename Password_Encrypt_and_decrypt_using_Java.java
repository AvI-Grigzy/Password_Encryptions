import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

public class PasswordFortress {

    private static final String PASSWORD_FILE = "password_store.txt";
    private static final SecureRandom secureRandom = new SecureRandom();

    //Generate a random password
    public static String generatePassword(int length, int specialCharCount) {
        String lettersAndDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        String specialCharacters = "!@#$%^&*()-_+=<>?";

        if (specialCharCount > length) {
            throw new IllegalArgumentException("Special character count cannot exceed total password length");
        }

        Random random = new Random();
        StringBuilder password = new StringBuilder(length);

        //Generate password with letters and digits
        for (int i = 0; i < length - specialCharCount; i++) {
            password.append(lettersAndDigits.charAt(random.nextInt(lettersAndDigits.length())));
        }

        //Add special characters
        for (int i = 0; i < specialCharCount; i++) {
            password.append(specialCharacters.charAt(random.nextInt(specialCharacters.length())));
        }

        //Shuffle the password
        return shuffleString(password.toString());
    }

    // Shuffle string
    private static String shuffleString(String input) {
        char[] a = input.toCharArray();
        for (int i = a.length - 1; i > 0; i--) {
            int j = secureRandom.nextInt(i + 1);
            char tmp = a[i];
            a[i] = a[j];
            a[j] = tmp;
        }
        return new String(a);
    }

    //Derive key from main password and salt
    public static SecretKey deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 16384, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES");
    }

    //Encrypt the password
    public static String encryptPassword(String password, SecretKey key) throws Exception {
        byte[] iv = new byte[16];
        secureRandom.nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(password.getBytes());
        byte[] encryptedWithIv = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, encryptedWithIv, 0, iv.length);
        System.arraycopy(encrypted, 0, encryptedWithIv, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(encryptedWithIv);
    }

    //Decrypt the password
    public static String decryptPassword(String encryptedPassword, SecretKey key) throws Exception {
        byte[] encryptedData = Base64.getDecoder().decode(encryptedPassword);
        byte[] iv = new byte[16];
        System.arraycopy(encryptedData, 0, iv, 0, iv.length);

        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        byte[] decrypted = cipher.doFinal(encryptedData, iv.length, encryptedData.length - iv.length);
        return new String(decrypted);
    }

    //Store the password in a file
    public static void storePassword(String website, String encryptedPassword, byte[] salt) throws IOException {
        BufferedWriter writer = new BufferedWriter(new FileWriter(PASSWORD_FILE, true));
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        writer.write(website + "," + encryptedPassword + "," + saltBase64);
        writer.newLine();
        writer.close();
    }

    //Load and decrypt the password from file
    public static String loadPassword(String website, String mainPassword) throws Exception {
        BufferedReader reader = new BufferedReader(new FileReader(PASSWORD_FILE));
        String line;
        while ((line = reader.readLine()) != null) {
            String[] data = line.split(",");
            if (data[0].equals(website)) {
                String encryptedPassword = data[1];
                byte[] salt = Base64.getDecoder().decode(data[2]);

                SecretKey key = deriveKey(mainPassword, salt);
                return decryptPassword(encryptedPassword, key);
            }
        }
        reader.close();
        return null;
    }

    //Main function
    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Do you want to (G)enerate a new password or (A)ccess stored password? [G/A]: ");
        String choice = scanner.nextLine().toUpperCase();

        if (choice.equals("G")) {
            System.out.print("Enter the website name: ");
            String website = scanner.nextLine();

            System.out.print("Enter the desired length of the password: ");
            int length = scanner.nextInt();

            System.out.print("Do you want to include special characters? (Y/N): ");
            String specialCharOption = scanner.next().toUpperCase();
            int specialCharCount = 0;
            if (specialCharOption.equals("Y")) {
                System.out.print("How many special characters do you want to include?: ");
                specialCharCount = scanner.nextInt();
            }

            String password = generatePassword(length, specialCharCount);
            System.out.println("Generated password for " + website + ": " + password);

            System.out.print("Enter a main password to secure your passwords: ");
            String mainPassword = new String(System.console().readPassword());

            byte[] salt = new byte[16];
            secureRandom.nextBytes(salt);
            SecretKey key = deriveKey(mainPassword, salt);

            String encryptedPassword = encryptPassword(password, key);
            storePassword(website, encryptedPassword, salt);

            System.out.println("Password stored securely in " + PASSWORD_FILE + ".");
        } else if (choice.equals("A")) {
            System.out.print("Enter the website name to retrieve the password: ");
            String website = scanner.nextLine();

            System.out.print("Enter your main password to access stored passwords: ");
            String mainPassword = new String(System.console().readPassword());

            String password = loadPassword(website, mainPassword);
            if (password != null) {
                System.out.println("Your stored password for " + website + " is: " + password);
            } else {
                System.out.println("Could not retrieve the password.");
            }
        } else {
            System.out.println("Invalid option. Please choose either G or A.");
        }
    }
}
