package etf.openpgp.mn170085d_dm170084d.messaging;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.*;
import java.util.Date;

public class MessagingUtils {
    /**
     * Metoda koja salje PGP poruku koristeci prosledjene parametre.
     * @param srcPath putanja do fajla koji se salje
     * @param dstPath putanje u kojoj se cuva enkriptovana poruka
     * @param isSigned flag koji predstavlja da li treba potpisati poruku
     * @param signingKey privatni kljuc posiljaoca kojim treba potpisati poruku (null ako ne treba potpisati poruku)
     * @param signingAlgorithm algoritam koji se koristi prilikom potpisivanja poruke
     * @param isEncrypted flag koji predstavlja da li treba enkriptovati poruku
     * @param encryptionPublicKey javni kljuc primaoca kojim se sifruje sesijski kljuc kojim se sifruje poruka
     * @param encryptionAlgorithm SymmetricKeyAlgorithmTags koji predstavlja kojim simetricnim algoritmom treba da se sifruje poruka
     * @param isZipped flag koji predstavlja da li treba zipovati poruku
     * @param isEncodedBase64 flag koji predstavlja da li treba konvertovati poruku u radix64 format
     */
    public static void sendMessage(String srcPath, String dstPath, boolean isSigned, PGPPrivateKey signingKey,
                                   int signingAlgorithm, boolean isEncrypted, PGPPublicKey encryptionPublicKey,
                                   int encryptionAlgorithm, boolean isZipped, boolean isEncodedBase64)
    {
        try {
            FileInputStream inputStream = new FileInputStream(srcPath);
            byte[] data = inputStream.readAllBytes();
            inputStream.close();

            if(isSigned)
            {
                data = MessagingService.sign(data, signingKey, signingAlgorithm);
            }
            if(isZipped)
            {
                data = MessagingService.zip(data);
            }
            if(isEncrypted)
            {
                data = MessagingService.encrypt(data, encryptionPublicKey, encryptionAlgorithm);
            }
            if(isEncodedBase64)
            {
                data = MessagingService.encodeArmoredStream(data);
            }

            String fileName= "sentMessage_" + (new Date()).getTime() + ".gpg";
//            String fileName = "encrypted.gpg";
            File exportFile = new File(dstPath, fileName);

            FileOutputStream fileStream = new FileOutputStream(exportFile);
            fileStream.write(data);

            fileStream.close();
        } catch (FileNotFoundException e) {
            System.out.println("Nema fajla");
            e.printStackTrace();
        } catch (IOException e) {
            System.out.println("Greska pri citanju poruke");
            e.printStackTrace();
        } catch (PGPException e) {
            System.out.println("Greska pri potpisivanju");
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("Greska pri enkripciji poruke");
            e.printStackTrace();
        }
    }
}
