import java.nio.file.*;
import java.util.*;
import java.io.*;

public class TCP extends Layer4 {


  private static String[] fields_name = {"src port", "dst port", "sequence number",
  "ack", "offset flags", "window size", "checksum", "urgent pointer", "options", "segment data"};
  private int[] fields_size = {2, 2, 4, 4, 2, 2, 2, 2, 0, -1};
  private static int header_total = 20;
  private HashMap<String, String> header;

  private HashMap<String, Integer> flags;
  private final String[] flags_name = {"RSRVD", "NONCE", "CWR",
  "ECN", "URG", "ACK", "PSH", "RST", "SYN",
  "FIN"};
  private final int[] flags_mask = {0xe00, 0x100, 0x080, 0x040, 0x020, 0x010,
    0x008, 0x004, 0x002, 0X001};
  private final int[] flags_shift = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0};

  private Layer7 encapsulated_packet;
  private byte[] raw_data;
  private int source_port;
  private int destination_port;

  public TCP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.flags = new HashMap<String, Integer>();
    this.raw_data = null;
    this.setPacket(packet);
    this.source_port = Integer.parseInt(header.get("src port"), 16);
    this.destination_port = Integer.parseInt(header.get("dst port"), 16);
    this.encapsulated_packet = null;
    try{
      this.encapsulated_packet = new DNS(raw_data);
    } catch (NotADNSPacketException nadnse) {
      this.encapsulated_packet = null;
    }
    if(this.containsDHCPmagicCookie()){
      this.encapsulated_packet = new DHCP(raw_data);
    }
    switch(source_port) {
      case 80:
      case 8080:
      if(this.raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
          this.encapsulated_packet = new HTTP(raw_data);
        }
        break;
      case 21:
      case 22:
      if(this.raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
          this.encapsulated_packet = new FTP(raw_data);
        }
        break;
      default:
        break;
    }
    //no protocol found from source port
    if(this.encapsulated_packet == null) {
      switch(destination_port) {
        case 80:
        case 8080:
        if(this.raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
            this.encapsulated_packet = new HTTP(raw_data);
          }
          break;
        case 21:
        case 22:
        if(this.raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
            this.encapsulated_packet = new FTP(raw_data);
          }
          break;
        default:
          this.encapsulated_packet = null;
          break;
      }
    }
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    packet: for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==-1) {
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
        if(fields_name[i].equals("offset flags")){
          this.setLengthAndFlags(Tools.hexToString(buffer));
        }
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
  }

  public void setLengthAndFlags(String hex) {
    int header_length = Integer.parseInt(hex.substring(0,1),16)*4;
    if(header_length!=header_total){
      //set  options size
      int option_size = header_length - header_total;
      if(option_size<0){
        fields_size[8] = 0;
      } else {
        fields_size[8] = option_size;
      }
      //update header_total
      header_total = header_length;
    }
    //configure flags
    header.put("flags", hex.substring(1,hex.length()));
    setFlags();
  }

  private void setFlags() {
    int flags_hex = Integer.parseInt(header.get("flags"), 16);
    for(int i=0; i<flags_name.length; i++) {
      int value = (flags_hex & flags_mask[i])>> flags_shift[i];
      flags.put(flags_name[i], value);
    }
  }

  public String flagsToString() {
    String res = "";
    for(int i=0; i<flags_name.length; i++){
      if(flags.get(flags_name[i])!=null && flags.get(flags_name[i])!=0){
        res += flags_name[i]+" ";
      }
    }
    return res+"\n";
  }

  public void constructFTP(){
    if(raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
      this.encapsulated_packet = new FTP(raw_data);
    }
  }

  public void constructHTTP(){
    if(raw_data!=null && !Tools.hexToAscii(Tools.hexToString(raw_data)).trim().equals("")){
      this.encapsulated_packet = new HTTP(raw_data);
    }
  }

  public boolean containsDHCPmagicCookie(){
    if(raw_data!=null){
      String hexData = Tools.hexToString(raw_data);
      if(!hexData.trim().equals("")) {
        return hexData.contains("63825363");
      }
    }
    return false;
  }

  @Override
  public String toString() {

    String res = "Transmission Control Protocol (TCP)\n";
    res += ("Source Port \t\t"+Tools.udpPort(source_port)+"\n");
    res += ("Destination Port \t"+Tools.udpPort(destination_port)+"\n");
    res += "Flags: "+flagsToString();
    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    } else if(header.get("segment data")!=null && !header.get("segment data").trim().equals("")){
      res += "Data :\n"+Tools.hexToAscii(header.get("segment data"));
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
    return true;
  }

  @Override
  public boolean isDNS(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isDNS();
    }
    return false;
  }

  @Override
  public boolean isDHCP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isDHCP();
    }
    return false;
  }

  @Override
  public boolean isHTTP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isHTTP();
    }
    return false;
  }

  @Override
  public boolean isFTP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isFTP();
    }
    return false;
  }

  @Override
  public boolean hasSyn(){
    if(flags.get("SYN")!=null && flags.get("SYN")!=0){
      return true;
    }
    return false;
  }

  @Override
  public boolean hasAck(){
    if(flags.get("ACK")!=null && flags.get("ACK")!=0){
      return true;
    }
    return false;
  }

  public String getPortSrc() {
    return Integer.toString(source_port);
  }

  public String getPortDst() {
    return Integer.toString(destination_port);
  }

  public String getTcpSeq() {
    String res = this.header.get("sequence number");
    if(res!=null) {
      return res;
    }
    return "";
  }

  public String getTcpData() {
    String res = this.header.get("segment data");
    if(res!=null) {
      return res;
    }
    return "";
  }

}
