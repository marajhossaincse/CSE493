import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.util.Scanner;

public class AES_CYPHER{

    // encryption function
    public static String encrypt(String ct, Key key) throws Exception{
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(ct.getBytes());
        String encString = java.util.Base64.getEncoder().encodeToString(encVal);
        return encString;
    }

    // decryption library function
    public static String decrypt(String pt, Key key) throws Exception{
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decodeVal = java.util.Base64.getDecoder().decode(pt);
        byte[] decVal = c.doFinal(decodeVal);
        String decString = new String(decVal);
        return decString;
    }


    //main
    private static final String ALGO = "aes";
    public static void main(String[] args) throws Exception {

        // created 128 bit key
        String sKey = "123456789qwertyu"; // 128 bit value
        Key key = new SecretKeySpec(sKey.getBytes(), ALGO);


        String pt = "";

        // accessing arguments from commandline and taking it as a file
        File file = new File(args[0]);


        // Reading plaintext file from command line argument
        try {
            Scanner myReader = new Scanner(file);
            while (myReader.hasNextLine()) {
                pt = myReader.nextLine();
                System.out.println(pt);
            }
            myReader.close();
        } catch (FileNotFoundException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // Creating crypto.txt file
        try {
            File myObj = new File("crypto.txt");
            if (myObj.createNewFile()) {
                System.out.println("File created: " + myObj.getName());
            } else {
                System.out.println("File already exists.");
            }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // Creating cleartext.txt file
        try {
            File myObj = new File("cleartext.txt");
            if (myObj.createNewFile()) {
                System.out.println("File created: " + myObj.getName());
            } else {
                System.out.println("File already exists.");
            }
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        // using the encrypt decrypt functions
        String encryptedString   = encrypt(pt, key);
        String decryptString  = decrypt(encryptedString, key);

        System.out.println("Plain   String  : " + pt);
        System.out.println("Encrypt String  : " + encryptedString);
        System.out.println("Decrypt String  : " + decryptString);

        // writing encrypted string in crypto.txt
        try {
            FileWriter myWriter = new FileWriter("crypto.txt");
            myWriter.write(encryptedString);
            myWriter.close();
            System.out.println("Crypto Text Written in Designated File");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        //writing decrypted string in cleartext.txt
        try {
            FileWriter myWriter = new FileWriter("cleartext.txt");
            myWriter.write(decryptString);
            myWriter.close();
            System.out.println("Clear Text Written in Designated File");
        } catch (IOException e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }
}
