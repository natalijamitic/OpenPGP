package etf.openpgp.mn170085d;

import java.util.Date;

public class DummyObject {
    private String id;
    private String owner;
    private String date;
    public DummyObject(int id, String owner) {
        this.id = id + "!";
        this.owner = owner;
        Date d = new Date();
        date =d.toString();
    }
    public void setId(String fName) {
        this.id = fName;
    }
    public String getId() { return id;}

    public void setOwner(String fName) {
        this.owner = fName;
    }
    public String getOwner() {return owner;}

    public void setDate(String fName) {
        this.date = fName;
    }
    public String getDate() {return date;}

}