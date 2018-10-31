import java.nio.file.*;
import java.util.*;
import java.io.*;

public class UDP extends Layer4 {


  private static String[] fields_name = {"src port", "dst port", "length", "checksum", "data"};
  private int[] fields_size = {2, 2, 2, 2, 0};
  private static int header_total = 8;
  private HashMap<String, String> header;
  private Layer7 encapsulated_packet;
  private byte[] raw_data;
  private int source_port;
  private int destination_port;

  public UDP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    this.source_port = Integer.parseInt(header.get("src port"), 16);
    this.destination_port = Integer.parseInt(header.get("dst port"), 16);
    switch(source_port) {
      case 21:
        if(raw_data!=null){
          this.encapsulated_packet = new FTP(raw_data);
        }
        break;
      case 53:
        this.encapsulated_packet = new DNS(raw_data);
        break;
      case 80:
        if(raw_data!=null){
          this.encapsulated_packet = new HTTP(raw_data);
        }
        break;
      case 67:
      case 68:
        this.encapsulated_packet = new DHCP(raw_data);
        break;
      default:
        this.encapsulated_packet = null;
        break;
    }
    if(this.encapsulated_packet == null) {
      switch(destination_port) {
        case 21:
          if(raw_data!=null){
            this.encapsulated_packet = new FTP(raw_data);
          }
          break;
        case 53:
          this.encapsulated_packet = new DNS(raw_data);
          break;
        case 80:
          if(raw_data!=null){
            this.encapsulated_packet = new HTTP(raw_data);
          }
          break;
        case 67:
        case 68:
          this.encapsulated_packet = new DHCP(raw_data);
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
    for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==0) {
        //data length including padding
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

  @Override
  public String toString() {

    String res = "User Datagram Protocol (UDP)\n";
    res += ("Source Port \t\t"+Tools.udpPort(source_port)+"\n");
    res += ("Destination Port \t"+Tools.udpPort(destination_port)+"\n");
    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    } else {
      res += "Data \t\t\t"+Tools.displayRawData(header.get("data"));
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
    return true;
  }

  @Override
  public boolean isTCP(){
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

}
