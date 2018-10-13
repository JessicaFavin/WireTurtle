import java.nio.file.*;
import java.util.*;
import java.io.*;

public class DNS extends Layer7 {

  private static final String[] fields_name = {"id", "flags", "questions", "answer RRs",
  "authority RRs", "addiditonal RRs", "data"};
  private int[] fields_size = {2, 2, 2, 2, 2, 2, 0};
  private static int header_total = 12;
  private HashMap<String, String> header;
  private byte[] raw_data;
  private HashMap<String, Integer> flags;
  private final String[] flags_name = {"response", "opcode", "authoritative",
  "truncated", "recursion desired", "recursion available", "Z", "answer authenticated",
  "non-authenticated data", "reply code"};
  private final int[] flags_mask = {0x8000, 0x7800, 0x0400, 0x0200, 0x0100,
    0x0080, 0x0040, 0x0020, 0X0010, 0x000f};
  private final int[] flags_shift = {15, 11, 10, 9, 8, 7, 6, 5, 4, 0};
  private int queries_nb;
  private int answers_nb;
  private ArrayList<DNSquery> queries;
  private ArrayList<DNSanswer> answers;

  public DNS(byte[] packet) {
    this.raw_data = null;
    this.header = new HashMap<String, String>();
    this.flags = new HashMap<String, Integer>();
    this.queries = new ArrayList<DNSquery>();
    this.answers = new ArrayList<DNSanswer>();
    this.setPacket(packet);
    this.setFlags();
    this.setData();
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==0) {
        //à adapter
        size = (packet.length-header_total);
        fields_size[i] = size;
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        this.raw_data = buffer;
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
      }
      header.put(fields_name[i], Tools.hexToString(buffer));
      offset += size;
    }
  }

  public void setData() {
    queries_nb =  Integer.parseInt(header.get("questions"),16);
    answers_nb =  Integer.parseInt(header.get("answer RRs"),16);
    //queries
    String data_hex = header.get("data");
    int offset = 0;
    String next;
    String str = "";

    for(int i=0; i<queries_nb; i++) {
      //System.out.println("Query n°"+i);
      //read bytes until 00 -> name + name length for answers maybe
      //System.out.print("\t");
      while(!(next = data_hex.substring(offset, offset+2)).equals("00")){
        str += next;
        offset += 2;
        //System.out.print(next);
      }
      offset += 2;
      //System.out.println("");
      // read 2 bytes for type then 2 bytes for class
      String type = data_hex.substring(offset, offset+4);
      offset += 4;
      //System.out.println("\tType "+type);
      String dnsClass = data_hex.substring(offset, offset+4);
      offset += 4;
      //System.out.println("\tClass "+dnsClass);
      queries.add(new DNSquery(str,type,dnsClass));
    }
    //answers
    for(int i=0; i<answers_nb; i++) {
      //System.out.println("Answer n°"+i);
      //read bytes until 00 -> name or name length if set
      str = "";
      String beginning = data_hex.substring(offset, offset+4);
      offset += 4;
      //System.out.println("\t"+beginning);
      // read 2 bytes for type then 2 bytes for class
      String type = data_hex.substring(offset, offset+4);
      offset += 4;
      //System.out.println("\tType "+type);
      String dnsClass = data_hex.substring(offset, offset+4);
      offset += 4;
      //System.out.println("\tClass "+dnsClass);
      // 4 bytes for ttl
      String ttl = data_hex.substring(offset, offset+8);
      offset += 8;
      // 2 bytes for data length + data length bytes for address
      int data_length = Integer.parseInt(data_hex.substring(offset, offset+4) ,16) * 2;
      offset += 4;
      //System.out.println("\tdata length "+data_length);
      // 16 bytes for IPv6 4 bytes for IPv4
      String dnsData = data_hex.substring(offset, offset+data_length);
      offset += data_length;
      //System.out.println("\tdata "+dnsData);
      answers.add(new DNSanswer(type,dnsClass,ttl, dnsData));
    }
  }

  private void setFlags() {
    int flags_hex = Integer.parseInt(header.get("flags"), 16);
    for(int i=0; i<flags_name.length; i++) {
      int value = (flags_hex & flags_mask[i])>> flags_shift[i];
      flags.put(flags_name[i], value);
    }
  }

  @Override
  public String toString() {
    String res = "Domain Name System\n";
    res += "Transaction ID : \t0x"+header.get("id")+"\n";
    res += "Reply code : \t"+Tools.dnsReplyCode(flags.get("reply code"))+"\n";
    //res += "Looking for :\t"+Tools.dnsResolution(header.get("data"))+"\n";
    res+="\n";
    if(queries_nb!=0){
      res += "Query\n";
      for(DNSquery q : queries) {
        res += q.toString();
      }
      res+="\n";
    }

    if(answers_nb!=0){
      res += "Answer(s)\n";
      for(DNSanswer a : answers) {
        res += a.toString();
      }
      res+="\n";
    }
    return res;
  }

  @Override
  public boolean isARP(){
    return false;
  }

  @Override
  public boolean isICMP(){
    return false;
  }

  @Override
  public boolean isIP(){
    return false;
  }

  @Override
  public boolean isUDP(){
    return false;
  }

  @Override
  public boolean isTCP(){
    return false;
  }

  @Override
  public boolean isDNS(){
    return true;
  }

  @Override
  public boolean isDHCP(){
    return false;
  }

  @Override
  public boolean isHTTP(){
    return false;
  }

  @Override
  public boolean isFTP(){
    return false;
  }


}
