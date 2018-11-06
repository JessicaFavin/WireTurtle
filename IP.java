import java.nio.file.*;
import java.util.*;
import java.io.*;

public class IP extends Layer3 {


  private static String[] fields_name = {"version header length", "DSCP ECN",
  "total length", "identification", "flags", "ttl", "protocol", "header checksum",
  "src ip", "dst ip"};
  private int[] fields_size = {1,1,2,2,2,1,1,2,4,4};
  private static int header_total = 20;
  private HashMap<String, Integer> flags;
  private final String[] flags_name = {"Reserved", "Don't Fragment (DF)", "More Fragment (MF)",};
  private final int[] flags_mask = {0x8000, 0x4000, 0x2000};
  private final int[] flags_shift = {15, 14, 13};
  private HashMap<String, String> header;
  private Layer4 encapsulated_packet;
  private byte[] raw_data;

  public IP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.flags = new HashMap<String, Integer>();
    this.setPacket(packet);
    switch(Integer.parseInt(header.get("protocol"), 16)) {
      case 1:
        this.encapsulated_packet = new ICMP(raw_data);
        break;
      case 6:
        this.encapsulated_packet = new TCP(raw_data);
        break;
      case 17:
        this.encapsulated_packet = new UDP(raw_data);
        break;
      default:
        break;
    }
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      buffer = new byte[size];
      buffer = Arrays.copyOfRange(packet, offset, offset+size);
      header.put(fields_name[i], Tools.hexToString(buffer));
      offset += size;
    }
    raw_data = Arrays.copyOfRange(packet, offset, packet.length);
    this.setFlags();
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

  @Override
  public String toString() {

    String res = "IP Paquet\n";

    res += ("Source \t\t"+Tools.ipAddress(header.get("src ip"))+"\n");
    res += ("Destination \t"+Tools.ipAddress(header.get("dst ip"))+"\n");
    res += ("Type \t\t"+Tools.ipProtocol(header.get("protocol"))+"\n");
    res += ("Time to live \t"+Integer.parseInt(header.get("ttl"),16)+"\n");
    res += "Flags: "+flagsToString();

    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    }
    return res;
  }

  @Override
  public boolean isARP(){
    return false;
  }

  @Override
  public boolean isICMP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isICMP();
    }
    return false;
  }

  @Override
  public boolean isIP(){
    return true;
  }

  @Override
  public boolean isUDP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isUDP();
    }
    return false;
  }

  @Override
  public boolean isTCP(){
    if(encapsulated_packet!=null){
      return this.encapsulated_packet.isTCP();
    }
    return false;
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
    if(this.isTCP()) {
      return this.encapsulated_packet.hasSyn();
    }
    return false;
  }

  @Override
  public boolean hasAck(){
    if(this.isTCP()) {
      return this.encapsulated_packet.hasAck();
    }
    return false;
  }

  public String getIpSrc() {
    String ip = header.get("src ip");
    if(ip!=null){
      return ip;
    }
    return "";
  }

  public String getIpDst() {
    String ip = header.get("dst ip");
    if(ip!=null){
      return ip;
    }
    return "";
  }

  public String getPortSrc() {
    if(this.isTCP()) {
      return ((TCP) this.encapsulated_packet).getPortSrc();
    }
    return "";
  }

  public String getPortDst() {
    if(this.isTCP()) {
      return ((TCP) this.encapsulated_packet).getPortDst();
    }
    return "";
  }

  public String getTcpSeq() {
    if(this.isTCP()) {
      return ((TCP) this.encapsulated_packet).getTcpSeq();
    }
    return "";
  }

  public String getTcpData() {
    if(this.isTCP()) {
      return ((TCP) this.encapsulated_packet).getTcpData();
    }
    return "";
  }


    public void constructHTTP() {
      if(this.isTCP()) {
        ((TCP) this.encapsulated_packet).constructHTTP();
      }
    }

    public void constructFTP() {
      if(this.isTCP()) {
        ((TCP) this.encapsulated_packet).constructFTP();
      }
    }

}
