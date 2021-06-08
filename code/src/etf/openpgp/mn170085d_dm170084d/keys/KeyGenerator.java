package etf.openpgp.mn170085d_dm170084d.keys;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Date;

/**
 * Klasa zaduzena za kreiranje kljuceva.
 */
public class KeyGenerator {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * Generisanje 2 para kljuceva (master + sub-key) koristeci RSA algoritam.
     * @param identity Identitet osobe za koju se pravi par kljuceva.
     * @param passphrase Sifra pod kojom se cuva par kljuceva.
     * @param keySize Velicina kljuca koriscenog u RSA algoritmu.
     * @return novonapravljeni tajni key ring
     */
    public PGPSecretKeyRing generateRSAPGPSecretKeyRing(String identity, String passphrase, int keySize) {
        PGPSecretKeyRing secretKeyRing = null;
        try {
            PGPKeyPair rsaKeyPairMaster = this.getRSAPGPKeyPair(keySize, PGPPublicKey.RSA_SIGN);
            PGPKeyPair rsaKeyPairSub = this.getRSAPGPKeyPair(keySize, PGPPublicKey.RSA_ENCRYPT);
            PGPKeyRingGenerator pgpKeyRingGenerator = this.getPGPKeyRingGenerator(rsaKeyPairMaster, rsaKeyPairSub, identity, passphrase);

            secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (PGPException e) {
            e.printStackTrace();
        }

        return secretKeyRing;
    }

    /**
     * Generisanje jednog para kljuceva RSA algoritmom.
     * @param keySize Velicina kljuca koriscenog u RSA algoritmu.
     * @param mode Mod moze biti za potpis i za enkripciju.
     * @return vraca novokreirani par kljuceva
     * @throws NoSuchAlgorithmException
     * @throws PGPException
     */
    private PGPKeyPair getRSAPGPKeyPair(int keySize, int mode) throws NoSuchAlgorithmException, PGPException {
        KeyPairGenerator rsaKPG = KeyPairGenerator.getInstance("RSA");
        rsaKPG.initialize(keySize);

        KeyPair rsaKeyPair = rsaKPG.generateKeyPair();
        PGPKeyPair rsaPGPKeyPair = new JcaPGPKeyPair(mode, rsaKeyPair, new Date());

        return rsaPGPKeyPair;
    }

    /**
     * Pravi generator prstena kljuceva na osnovu master i sub kljuca
     * @param master Master kljuc
     * @param sub Sub kljuc
     * @param identity Identitet korisnika za kog se pravi par kljuceva
     * @param passphrase Sifra pod kojom se cuvaju kljucevi
     * @return generator prstena kljuceva
     * @throws PGPException
     */
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

}
