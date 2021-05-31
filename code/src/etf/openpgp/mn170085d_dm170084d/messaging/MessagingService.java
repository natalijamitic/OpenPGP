package etf.openpgp.mn170085d_dm170084d.messaging;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Iterator;

public class MessagingService {
    public static byte[] zip(byte[] data) throws IOException {
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator cdg = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
        OutputStream compressedOutputStream = cdg.open(byteOutputStream);
        compressedOutputStream.write(data);
        compressedOutputStream.close();

        byteOutputStream.close();

        return byteOutputStream.toByteArray();
    }

    public static byte[] unzip(byte[] data) throws Exception {
        JcaPGPObjectFactory objectFactory = new JcaPGPObjectFactory(data);
        Object o = objectFactory.nextObject();
        if(!(o instanceof PGPCompressedData))
            throw new Exception("Unable to unzip data");
        PGPCompressedData cdata = (PGPCompressedData) o;

        return cdata.getDataStream().readAllBytes();
    }

    public static byte[] toRadix64(byte[] data) throws IOException {
        ByteArrayOutputStream byteArray = new ByteArrayOutputStream();
        ArmoredOutputStream armoredOutputStream = new ArmoredOutputStream(byteArray);
        armoredOutputStream.write(data);
        armoredOutputStream.close();
        byteArray.close();
        return byteArray.toByteArray();
    }

    public static byte[] fromRadix64(byte[] data) throws IOException {
        return PGPUtil.getDecoderStream(new ByteArrayInputStream(data)).readAllBytes();
    }

    public static byte[] encrypt(byte[] data, PGPPublicKey publicKey, int algorithm) throws Exception {
        OutputStream outputStream = new ByteArrayOutputStream();
        if(publicKey == null)
            throw new Exception("No public key was provided for encryption");
        if(data == null)
            throw new Exception("No data was provided for encryption");

        PGPEncryptedDataGenerator encryptionGenerator = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(algorithm).setSecureRandom(new SecureRandom()).setProvider("BC"));
        encryptionGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));

        OutputStream encryptedOutputStream = encryptionGenerator.open(outputStream, data.length);

        encryptedOutputStream.write(data);
        encryptedOutputStream.close();

        return ((ByteArrayOutputStream)outputStream).toByteArray();
    }

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
}
