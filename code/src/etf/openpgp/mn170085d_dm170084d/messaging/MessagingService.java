package etf.openpgp.mn170085d_dm170084d.messaging;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.encoders.Base64;

import java.io.*;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

public class MessagingService {
    /**
     * Metoda zipuje podatke koji joj se proslede
     * @param data niz bajtova koji se zipuju
     * @return niz bajtova koji predstavljaju zipovane podatke
     * @throws IOException
     */
    public static byte[] zip(byte[] data) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cdg = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream compressedOutputStream = cdg.open(byteOutputStream);
        compressedOutputStream.write(data);
        compressedOutputStream.close();

        byteOutputStream.close();

        return byteOutputStream.toByteArray();
    }

    /**
     * Metoda unzipuje podatke koji joj se proslede
     * @param data niz bajtova koji se unzipuju
     * @return niz bajtova koji predstavljaju unzipovane podatke
     * @throws Exception
     */
    public static byte[] unzip(byte[] data) throws Exception {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object o = objectFactory.nextObject();
        if(!(o instanceof PGPCompressedData))
            throw new Exception("Unable to unzip data");
        PGPCompressedData cdata = (PGPCompressedData) o;

        return cdata.getDataStream().readAllBytes();
    }

    /**
     * Metoda konvertuje podatke u radix64 format
     * @param data niz bajtova koji se konvertuju u radix64 format
     * @return niz bajtova koji predstavljaju podatke enkodirane u radix64 formatu
     * @throws IOException
     */
    public static byte[] encodeArmoredStream(byte[] data) throws IOException {
        ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(byteArray);
        armoredOutputStream.write(data);
        armoredOutputStream.close();
        byteArray.close();
        return byteArray.toByteArray();
    }

    /**
     * Metoda koji dekoduje podatke iz radix64 formata
     * @param data niz bajtova koji se dekoduju
     * @return niz bajtova koji predstavljaju podatke dekodovane iz radix64 formata
     * @throws IOException
     */
    public static byte[] decodeArmoredStream(byte[] data) throws IOException {
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(data)).readAllBytes();
    }

    /**
     * Metoda koja enkriptuje podatke i sifruje sesijski kljuc javnim kljucem primaoca
     * @param data podaci koji se enkriptuju
     * @param publicKey javni kljuc primaoca poruke
     * @param algorithm SymmetricKeyAlgorithmTags vrednost koja oznacava simetricni algoritam kojim se enkriptuje poruka
     * @return niz bajtova koji predstavljaju enkriptovanu poruku
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, PGPPublicKey publicKey, int algorithm) throws Exception {
        OutputStream outputStream = new ByteArrayOutputStream();
        if(publicKey == null)
            throw new Exception("No public key was provided for encryption");
        if(data == null)
            throw new Exception("No data was provided for encryption");

        PGPEncryptedDataGenerator encryptionGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(algorithm).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
        encryptionGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        OutputStream encryptedOutputStream = encryptionGenerator.open(outputStream, data.length);

        encryptedOutputStream.write(data);
        encryptedOutputStream.close();

        return ((ByteArrayOutputStream)outputStream).toByteArray();
    }

    /**
     * Metoda koja proverava da li niz bajtova predstavlja enkriptovanu poruku
     * @param data niz bajtova koji se proveravaju
     * @return boolean koji oznacava da li bajtovi predstavljaju enkriptovane podatke ili ne
     */
    public static boolean isDataEncrypted(byte[] data) {
        try {
            JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
            Object o = objectFactory.nextObject();

            if (o instanceof PGPEncryptedDataList)
                return true;
            else
                return false;
        } catch (Exception e)
        {
            return false;
        }
    }

    /**
     * Metoda koja dekriptuje podatke
     * @param data podaci koji se dekriptuju
     * @param privateKey privatni kljuc primaoca kojim se desifruje sesijski kljuc
     * @return niz bajtova koji predstavljaju dekriptovane podatke
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, PGPPrivateKey privateKey) throws Exception {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object o = objectFactory.nextObject();

        if(o instanceof PGPEncryptedDataList)
        {
            PGPEncryptedDataList edl = (PGPEncryptedDataList) o;
            Iterator<PGPEncryptedData> encryptedDataObjects = edl.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData encryptedData = (PGPPublicKeyEncryptedData) encryptedDataObjects.next();
            PublicKeyDataDecryptorFactory dataDecryptorFactory =
                    new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey);
            byte[] decryptedBytes = encryptedData.getDataStream(dataDecryptorFactory).readAllBytes();
            return decryptedBytes;
        }
        throw new Exception("Provided data is not encrypted");
    }

    /**
     * Metoda koja potpisuje podatke privatnim kljucem posiljaoca
     * @param data podaci koji se potpisuju
     * @param signingKey privatni kljuc posiljaoca kojim se potpisuju podaci
     * @param signingAlg algoritam kojim se potpisuju podaci
     * @return niz bajtova koji predstavljaju potpisanu poruku
     * @throws PGPException
     * @throws IOException
     */
    public static byte[] sign(byte[] data, PGPPrivateKey signingKey, int signingAlg) throws PGPException, IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        BCPGOutputStream bcpgos = new BCPGOutputStream(byteStream);

        PGPSignatureGenerator sg = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(signingAlg, PGPUtil.SHA1).setProvider("BC"));
        sg.init(PGPSignature.BINARY_DOCUMENT, signingKey);
        sg.generateOnePassVersion(false).encode(bcpgos);

        PGPLiteralDataGenerator ldg = new PGPLiteralDataGenerator();
        OutputStream os = ldg.open(bcpgos, PGPLiteralData.BINARY, "_CONSOLE", data.length, new Date());

        for(int i = 0; i < data.length; i++)
        {
            os.write(data[i]);
            sg.update(data[i]);
        }

        ldg.close();
        sg.generate().encode(bcpgos);
        byteStream.close();
        bcpgos.close();
        return byteStream.toByteArray();
    }

    /**
     * Metoda koja proverava da li su podaci potpisani
     * @param data podaci za koje se proverava da li su potpisani
     * @return boolean koji predstavlja da li su podaci potpisani ili ne
     */
    public static boolean isDataSigned(byte[] data)
    {
        try {
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(data);
            Object o = null;
            o = pgpFact.nextObject();
            if(o instanceof PGPOnePassSignatureList)
                return true;
            else
                return false;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Metoda koja verifikuje potpis poruke
     * @param pgpSignedData potpisani podaci
     * @param verifyingKey javni kljuc posiljaoca poruke kojim se proverava njegov potpis
     * @return boolean koji predstavlja da li je potpis verifikovan ili ne
     * @throws IOException
     * @throws PGPException
     */
    public static boolean verifySignature(byte[] pgpSignedData, PGPPublicKey verifyingKey) throws IOException, PGPException {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);

        PGPOnePassSignatureList opl = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = opl.get(0);

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
        InputStream is = literalData.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), verifyingKey);

        byte[] data = is.readAllBytes();
        for(byte i : data)
            ops.update(i);

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }

    public static byte[] readSignedMessage(byte[] pgpSignedData) throws IOException {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);
        pgpFact.nextObject();
        PGPLiteralData literalData = (PGPLiteralData) pgpFact.nextObject();

        return literalData.getInputStream().readAllBytes();
    }
}
