package etf.openpgp.mn170085d_dm170084d;

import etf.openpgp.mn170085d_dm170084d.messaging.MessagingService;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;
import java.util.Iterator;

public class PGPTest {

    public static KeyPair generateRSAKeyPair(int bits) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(new RSAKeyGenParameterSpec(bits, RSAKeyGenParameterSpec.F4));
        return kpg.generateKeyPair();
    }

    public static SecretKey generateAESKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
        kg.init(128);
        return kg.generateKey();
    }

    public static SecretKey generate3DESKey() throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator kg = KeyGenerator.getInstance("TripleDES" );
        kg.init(112);
        return kg.generateKey();
    }

    public static byte[] createSignedObject(int signingAlg, PGPPrivateKey signingKey, byte[] data) throws PGPException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        BCPGOutputStream bcpgos = new BCPGOutputStream(baos);

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
        return baos.toByteArray();
    }

    public static boolean verifySignedObject(PGPPublicKey verifyingKey, byte[] pgpSignedData) throws IOException, PGPException {
        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(pgpSignedData);

        PGPOnePassSignatureList opl = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = opl.get(0);

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();
        InputStream is = literalData.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), verifyingKey);

        int ch;
        while((ch = is.read()) >= 0)
        {
            ops.update((byte) ch);
        }

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }

    public static void potpisivanje() throws NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidAlgorithmParameterException, PGPException {
        int keySize = 1024;
        String name = "marko";
        String mail = "mdivjak98@gmail.com";
        String password = "tajnasifra";

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(keySize);
        KeyPair rsaKp = rsaKpg.generateKeyPair();

        KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA");
        dsaKpg.initialize(1024);
        KeyPair dsaKp = dsaKpg.generateKeyPair();

        PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
        PGPKeyPair rsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKp, new Date());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                .build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair, name+"#"+mail, sha1Calc, null, null,
                new JcaPGPContentSignerBuilder(
                        dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, sha1Calc)
                        .setProvider("BC").build(password.toCharArray()));

        keyRingGen.addSubKey(rsaKeyPair);

        PGPSecretKeyRing privateKeyRing = keyRingGen.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = keyRingGen.generatePublicKeyRing();
        Iterator<PGPSecretKey> iter = privateKeyRing.getSecretKeys();
        PGPSecretKey masterKey = iter.next();
        PGPSecretKey secretKey = iter.next();
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
        PGPPrivateKey masterPrivateKey = masterKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(password.toCharArray()));
        PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(privateKeyRing.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        BCPGOutputStream helperStream = new BCPGOutputStream(byteStream);

        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, masterPrivateKey);
        signatureGenerator.generateOnePassVersion(false).encode(helperStream);

        PGPLiteralDataGenerator ldg = new PGPLiteralDataGenerator();

        byte[] data = {0x1, 0x2, 0x3, 0x4};

        OutputStream os = ldg.open(helperStream, PGPLiteralData.BINARY, "_CONSOLE", data.length, new Date());

        for(int i = 0; i < data.length; i++)
        {
            os.write(data[i]);
            signatureGenerator.update(data[i]);
        }

        ldg.close();
        signatureGenerator.generate().encode(helperStream);

        System.out.println(byteStream.toByteArray());
        for(byte i : byteStream.toByteArray())
            System.out.print((char)i);
    }



    public static PGPSecretKeyRing getSecretKeyRing() throws NoSuchAlgorithmException, PGPException {
        int keySize = 1024;
        String name = "marko";
        String mail = "mdivjak98@gmail.com";
        String password = "tajnasifra";

        KeyPairGenerator rsaKpg = KeyPairGenerator.getInstance("RSA");
        rsaKpg.initialize(keySize);
        KeyPair rsa1 = rsaKpg.generateKeyPair();
        KeyPair rsa2 = rsaKpg.generateKeyPair();

        PGPKeyPair rsa1Kp = new JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, rsa1, new Date());
        PGPKeyPair rsa2Kp = new JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsa2, new Date());

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder()
                .build().get(HashAlgorithmTags.SHA1);

        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, rsa1Kp, name+"#"+mail, sha1Calc, null, null,
                new JcaPGPContentSignerBuilder(
                        rsa1Kp.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, sha1Calc)
                        .setProvider("BC").build(password.toCharArray()));

        keyRingGen.addSubKey(rsa2Kp);

        return keyRingGen.generateSecretKeyRing();
    }

    public static PGPPublicKey extractPublicKey(PGPSecretKeyRing skr)
    {
        Iterator<PGPPublicKey> publicKeys = skr.getPublicKeys();
        PGPPublicKey publicKey = publicKeys.next();
        publicKey = publicKeys.next();
        return publicKey;
    }

    public static PGPPrivateKey extractPrivateKey(PGPSecretKeyRing skr) throws PGPException {
        Iterator<PGPSecretKey> secretKeys = skr.getSecretKeys();
        PGPSecretKey sk = secretKeys.next();
        sk = secretKeys.next();
        PGPPrivateKey privateKey = sk.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build("tajnasifra".toCharArray()));
        return privateKey;
    }
    public static void main(String args[]) throws Exception {
        Security.addProvider(new BouncyCastleProvider());


        PGPSecretKeyRing skr1 = getSecretKeyRing();
        PGPSecretKeyRing skr2 = getSecretKeyRing();

        PGPPublicKey pk1 = extractPublicKey(skr1);
        PGPPublicKey pk2 = extractPublicKey(skr2);

        PGPPrivateKey priv1 = extractPrivateKey(skr1);
        PGPPrivateKey priv2 = extractPrivateKey(skr2);

        byte[] data = {0x1, 0x2, 0x3};

        byte[] encrypted = MessagingService.encrypt(data, pk1, SymmetricKeyAlgorithmTags.AES_128);

        System.out.println("Original Data");
        for (byte i : data)
            System.out.print(i);
        System.out.println();

        System.out.println("Encrypted data");
        for (byte i : encrypted)
            System.out.print((char) i);

        byte[] decrypted = MessagingService.decrypt(encrypted, priv1);

        System.out.println("\nDecrypted data");
        for (byte i : decrypted)
            System.out.print(i);
    }
}