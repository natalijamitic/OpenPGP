package etf.openpgp.mn170085d_dm170084d;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.*;
import java.util.Date;
import java.util.LinkedList;

public class KeyGenerator {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private PGPSecretKeyRingCollection privateKeys;
    private PGPPublicKeyRingCollection publicKeys;

    public KeyGenerator() {
        readKeys();
    }

    private void readKeys() {
        try {
            File publicKeysFile = new File(Globals.publicKeysPath);
            if (publicKeysFile.exists()) {
                InputStream inputStream = new ArmoredInputStream(new FileInputStream(publicKeysFile));
                publicKeys = new PGPPublicKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
            } else {
                publicKeys = new PGPPublicKeyRingCollection(new LinkedList<>());
            }

            File privateKeysFile = new File(Globals.privateKeysPath);
            if (privateKeysFile.exists()) {
                InputStream inputStream = new ArmoredInputStream(new FileInputStream(privateKeysFile));
                privateKeys = new PGPSecretKeyRingCollection(inputStream, new JcaKeyFingerprintCalculator());
            } else {
                privateKeys = new PGPSecretKeyRingCollection(new LinkedList());
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    public void generateRSAKey(String name, String mail, String passphrase, int keySize) {
        String identity = name + "~" + mail;
        try {
            PGPKeyPair rsaKeyPairMaster = this.getRSAPGPKeyPair(keySize, PGPPublicKey.RSA_SIGN);
            PGPKeyPair rsaKeyPairSub = this.getRSAPGPKeyPair(keySize, PGPPublicKey.RSA_ENCRYPT);
            PGPKeyRingGenerator pgpKeyRingGenerator = this.getPGPKeyRingGenerator(rsaKeyPairMaster, rsaKeyPairSub, identity, passphrase);

            PGPSecretKeyRing secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
            this.savePGPSecretKeyRing(secretKeyRing);

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }
    }

    private PGPKeyPair getRSAPGPKeyPair(int keySize, int mode) throws NoSuchAlgorithmException, PGPException {
        KeyPairGenerator rsaKPG = KeyPairGenerator.getInstance("RSA");
        rsaKPG.initialize(keySize);

        KeyPair rsaKeyPair = rsaKPG.generateKeyPair();
        PGPKeyPair rsaPGPKeyPair = new JcaPGPKeyPair(mode, rsaKeyPair, new Date());

        return rsaPGPKeyPair;
    }

    private PGPKeyRingGenerator getPGPKeyRingGenerator(PGPKeyPair master, PGPKeyPair sub, String identity, String passphrase) throws PGPException {
        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION, master, identity, sha1Calc, null, null,
                new JcaPGPContentSignerBuilder(master.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, sha1Calc)
                        .setProvider("BC")
                        .build(passphrase.toCharArray()));

        keyRingGen.addSubKey(sub);
        return keyRingGen;
    }

    private void savePGPSecretKeyRing(PGPSecretKeyRing secretKeyRing) {
        try {
            OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.privateKeysPath));
            this.privateKeys = PGPSecretKeyRingCollection.addSecretKeyRing(this.privateKeys, secretKeyRing);
            this.privateKeys.encode(secretOut);
            secretOut.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void savePGPPublicKeyRing(PGPPublicKeyRing publicKeyRing) {
        try {
            OutputStream secretOut = new ArmoredOutputStream(new FileOutputStream(Globals.publicKeysPath));
            this.publicKeys = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeys, publicKeyRing);
            this.publicKeys.encode(secretOut);
            secretOut.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public PGPSecretKeyRingCollection getPrivateKeys() {
        return privateKeys;
    }

    public PGPPublicKeyRingCollection getPublicKeys() {
        return publicKeys;
    }

    public static void main(String[] args) {
        KeyGenerator keyGen = new KeyGenerator();

        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", 1024);
        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", 2048);
        keyGen.generateRSAKey("naca", "naca@ntec.ch", "naca123", 4096);
    }
}
