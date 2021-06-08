package etf.openpgp.mn170085d_dm170084d.keys;

import java.util.Date;

/**
 * Usluzna klasa koriscena za vizuelnu reprezentaciju kljuca.
 */
public class KeyGuiVisualisation {
    private String id;
    private String owner;
    private String date;

    /**
     * Kljuc se inicijalizuje id-ijem, imenom vlasnika i datumom kreiranja.
     * @param id
     * @param owner
     * @param date
     */
    public KeyGuiVisualisation(long id, String owner, Date date) {
        this.id = String.format("%016x", id).toUpperCase();
        this.owner = owner;
        this.date = date.toString();
    }

    public String getId() {
        return id;
    }
    public void setId(String id) {
        this.id = id;
    }

    public String getOwner() {
        return owner;
    }
    public void setOwner(String owner) {
        this.owner = owner;
    }

    public String getDate() {
        return date;
    }
    public void setDate(String date) {
        this.date = date;
    }

    public String toString() {
        return owner + " - " + id;
    }

    /**
     * Parsiranje stringovske reprezentacije IDija u Long vrednost.
     * @param keyId Stringovska reprezentacija IDija
     * @return odgovarajucu Long vrednost
     */
    public long stringKeyIdToLong(String keyId) {
        return Long.parseUnsignedLong(keyId, 16);
    }
}
