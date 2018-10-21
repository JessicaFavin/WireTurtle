import java.nio.file.*;
import java.util.*;
import java.io.*;

public class TCP extends Layer4 {


  private static String[] fields_name = {"src port", "dst port", "sequence number",
  "ack", "length flags", "window size", "checksum", "urgent pointer", "options", "segment data"};
  private int[] fields_size = {2, 2, 4, 4, 2, 2, 2, 2, 0, -1};
  private static int header_total = 20;
  private HashMap<String, String> header;
  private Layer7 encapsulated_packet;
  private byte[] raw_data;
  private int source_port;
  private int destination_port;

  public TCP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.raw_data = null;
    this.setPacket(packet);
    this.source_port = Integer.parseInt(header.get("src port"), 16);
    this.destination_port = Integer.parseInt(header.get("dst port"), 16);
    this.encapsulated_packet = null;
    switch(source_port) {
      case 53:
        this.encapsulated_packet = new DNS(raw_data);
        break;
      case 80:
        if(raw_data!=null){
          this.encapsulated_packet = new HTTP(raw_data);
          //System.out.println("HTTP raw data : "+Tools.hexToString(this.raw_data));
        }
        break;
      default:
        this.encapsulated_packet = null;
        break;
    }
    if(this.encapsulated_packet == null) {
      switch(destination_port) {
        case 53:
          this.encapsulated_packet = new DNS(raw_data);
          break;
        case 80:
          if(raw_data!=null){
            this.encapsulated_packet = new HTTP(raw_data);
            //System.out.println("HTTP raw data : "+Tools.hexToString(this.raw_data));
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
    //System.out.println(Tools.hexToString(packet));
    packet: for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      //System.out.println(fields_name[i]);
      if(size==-1) {
        //data length including padding
        if(header_total == packet.length){
          size = 0;
          header.put(fields_name[i], "");
        } else {
          //System.out.println(Integer.parseInt(header.get("src port"), 16));
          //System.out.println(Integer.parseInt(header.get("dst port"), 16));
          //System.out.println("------------Set raw data "+fields_name[i]);
          //System.out.println("packet length : "+packet.length);
          //System.out.println("header total : "+this.header_total);
          size = (packet.length-header_total);
          //fields_size[i] = size;
          buffer = new byte[size];
          buffer = Arrays.copyOfRange(packet, offset, offset+size);
          //System.out.println("buffer : "+Tools.hexToString(buffer));
          //need to differentiate data from options ??
          this.raw_data = buffer;
          header.put(fields_name[i], Tools.hexToString(buffer));
        }
      } else if( size == 0){
        //System.out.println("empty");
        header.put(fields_name[i], "");
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        if(fields_name[i].equals("length flags")){
          this.setLengthFlags(Tools.hexToString(buffer));
        }
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
  }

  public void setLengthFlags(String hex) {
    //System.out.println("length flags : "+hex);
    int header_length = Integer.parseInt(hex.substring(0,1),16)*4;
    //System.out.println("header length="+header_length);
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
    setFlags(hex.substring(1,hex.length()));
  }

  public void setFlags(String hex) {
    return;
  }
  @Override
  public String toString() {

    String res = "Transmission Control Protocol (TCP)\n";
    res += ("Source Port \t\t"+source_port+"\n");
    res += ("Destination Port \t"+Tools.udpPort(destination_port)+"\n");
    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    } else if(header.get("segment data")!=null){
      res += "Data \t\t\t"+Tools.hexToAscii(header.get("segment data"));
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

}
