package etf.openpgp.mn170085d_dm170084d.keys;

import java.math.BigInteger;
import java.util.Date;

public class KeyGuiVisualisation {
    private String id;
    private String owner;
    private String date;

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
}
