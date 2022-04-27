import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.Path;
public class Main {

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static void main(String[] args) throws IOException {
//        encryption("text","key", "enc");
//        decryption("enc", "key", "dec");
        if(args.length == 4 ){
            if(args[0].equals("-e")){
                encryption(args[1], args[2], args[3]);

            }
            else if(args[0].equals("-d")){
                decryption(args[1], args[2], args[3]);
            }
        }
        else{
            System.out.println("Arguments not found. \n" +
                    "Arguments list: \n" +

                    "java Main -e textFile keyFile encryptionFile\n Encryption mode with paths to text file and key file. The last argument is encrypted text filename\n" +
                    "java Main -d encryptionFile keyFile outputFile\n Decryption mode with paths to encrypted text file and key file. The last argument is decryption output\n"+
                    "----------------------------------------------------------------------------------------\n"+
                    "Example:\n"+
                    "Encryption: java Main -e text key enc\n"+
                    "Decryption: java Main -d enc key output"
            );


        }
    }

    private static void encryption(String textFile, String keyFile, String outputFile){
        try{
            Path plainText_file = Paths.get(textFile);
            Path key_file = Paths.get(keyFile);

            byte[] text_byte = Files.readAllBytes(plainText_file);
            byte[] key_byte =  Files.readAllBytes(key_file);


            if(key_byte.length > 3){
                byte[] enc = rc6.encrypt(text_byte, key_byte);
                System.out.println(bytesToHex(enc));
                PrintWriter decryptFile = new PrintWriter("Encrypted_files/"+outputFile);
                decryptFile.write(bytesToHex(enc));
                decryptFile.close();
//                FileOutputStream encryptFile = new FileOutputStream("Encrypted_files/"+outputFile);
//                encryptFile.write(enc);
//                encryptFile.close();

                System.out.println("*********** Encryption is completed. Encrypted text is saved in Encrypted_files/"+outputFile + " file ******************");
            }
            else{
                System.out.println("Key symbols length should be >= 4\n");
            }
        }
        catch (Exception e){
            System.out.println("Check if plain text file or key file exists.");
            return;
        }
    }

    private static void decryption(String encryptedFile, String keyFile, String outputFile){
        try{
            Path key_file = Paths.get(keyFile);
            BufferedReader text = new BufferedReader(new FileReader("Encrypted_files/"+encryptedFile));

            byte[] encrypt_byte = hexStringToByteArray(text.readLine());
            byte[] key_byte =  Files.readAllBytes(key_file);
            if(key_byte.length > 3){
                byte[] dec = rc6.decrypt(encrypt_byte, key_byte);
                PrintWriter decryptFile = new PrintWriter("Decrypted_files/"+outputFile);
                decryptFile.write(bytesToHex(dec));
                decryptFile.close();
//                PrintWriter decryptFile = new PrintWriter("Decrypted_files/"+outputFile);
//                decryptFile.write(decimalToHex(dec));
//                decryptFile.close();

                System.out.println("-----------------------DECRYPTED TEXT--------------------------\n\n"+new String(dec)+"\n");
                System.out.println("*********** "+encryptedFile+" File decryption is done. Encrypted text is saved in Decrypted_files/"+outputFile + " file ******************");
            }
           else{
                System.out.println("Key symbols length should be >= 4\n");
            }
        }
        catch(Exception e){
            System.out.println("Check if encrypted file or key file exists.");
            return;
        }
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}

