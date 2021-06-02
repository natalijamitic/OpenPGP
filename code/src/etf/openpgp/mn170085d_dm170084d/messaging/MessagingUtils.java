package etf.openpgp.mn170085d_dm170084d.messaging;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.*;
import java.util.Date;

public class MessagingUtils {

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
                data = MessagingService.sign(data, signingKey, 3);
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
                data = MessagingService.encodeBase64(data);
            }

            String fileName= "sentMessage_" + (new Date()).getTime() + ".dat";
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
            System.out.println("Greska pri enkripciji");
            e.printStackTrace();
        }
    }
}
