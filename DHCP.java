import java.nio.file.*;
import java.util.*;
import java.io.*;
import java.math.BigInteger;

public class DHCP extends Layer7 {


  private static String[] fields_name = {"op code", "hardware type", "hardware len",
  "hops", "transaction id", "seconds", "flags", "client IP", "your IP", "server IP", "gateway IP",
  "client hardware address", "server name", "boot filename", "options"};
  private int[] fields_size = {1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 16, 64, 128, -1};
  private static int header_total = 236;
  private HashMap<String, Integer> flags;
  private final String[] flags_name = {"broadcast"};
  private final int[] flags_mask = {0x8000};
  private final int[] flags_shift = {15};
  private HashMap<String, String> header;
  private HashMap<Integer, String> options;
  private Layer7 encapsulated_packet;
  private byte[] raw_data;
  private int source_port;
  private int destination_port;

  public DHCP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.options = new HashMap<Integer, String>();
    this.flags = new HashMap<String, Integer>();
    this.raw_data = null;
    this.encapsulated_packet = null;
    this.setPacket(packet);
    this.setOptions();
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    packet: for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==-1) {
        //data length including padding
        if(header_total == packet.length){
          size = 0;
          header.put(fields_name[i], "");
        } else {
          size = (packet.length-header_total);
          buffer = new byte[size];
          buffer = Arrays.copyOfRange(packet, offset, offset+size);
          this.raw_data = buffer;
          header.put(fields_name[i], Tools.hexToString(buffer));
        }
      } else if( size == 0){
        header.put(fields_name[i], "");
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
    this.setFlags();
  }

  private void setFlags() {
    int flags_hex = Integer.parseInt(header.get("flags"), 16);
    for(int i=0; i<flags_name.length; i++) {
      int value = (flags_hex & flags_mask[i])>> flags_shift[i];
      flags.put(flags_name[i], value);
    }
  }

  public void setOptions() {
    String op = header.get("options");
    int offset = 8;
    byte[] buffer;
    int size;
    Integer opCode, opLength;
    String opData;
    boolean stop = false;
    while(!stop || offset<op.length()) {
      //read opcode
      size = 2;
      opCode = Integer.parseInt(op.substring(offset, offset+=size), 16);

      //read op lengnth
      opLength = Integer.parseInt(op.substring(offset, offset+=size), 16);
      if(opLength==0) {
        stop = true;
        break;
      }
      //read option data
      opData = op.substring(offset, offset+=(opLength*2));
      options.put(opCode, opData);
    }
  }

  @Override
  public String toString() {
    String dhcp;
    String res = "Dynamic Host Configuration Protocol (DHCP) \n";
    //broadcast/unicast
    Integer broadcast = flags.get("broadcast");
    if(broadcast != null && broadcast==1){
      res += "- Broadcast -\n";
    } else {
      res += "- Unicast -\n";
    }

    //Req/Reply
    if((dhcp = options.get(53))!=null) {
      res += "Message type:         "+Tools.dhcpOpcode(Integer.parseInt(dhcp,16))+"\n";
    }
    //xID
    res += "Transaction ID :      Ox"+header.get("transaction id")+"\n";

    //addresses
    res += "Client IP address :   "+Tools.ipAddress(header.get("client IP"))+"\n";
    res += "Your address :        "+Tools.ipAddress(header.get("your IP"))+"\n";
    res += "Next server :         "+Tools.ipAddress(header.get("server IP"))+"\n";
    res += "Client MAC address :  "+Tools.macAddress(header.get("client hardware address").substring(0,12))+"\n";
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

    return false;
  }

  @Override
  public boolean isDHCP(){

    return true;
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
