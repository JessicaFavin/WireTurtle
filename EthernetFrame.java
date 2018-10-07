import java.nio.file.*;
import java.util.*;
import java.io.*;

public class EthernetFrame extends Packet {


  private static String[] fields_name = {"dst", "src", "type", "data"};
  private int[] fields_size = {6, 6, 2, 0};
  private static int header_total = 14;
  private HashMap<String, String> header;
  private Packet encapsulated_packet;
  private byte[] raw_data;

  public EthernetFrame(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    switch(header.get("type")) {
      case "0806":
        //ARP packet -> setData
        this.encapsulated_packet = new ARPPacket(raw_data);
        break;
      case "0800":
        //IPv4 packet
        this.encapsulated_packet = new IPPacket(raw_data);
        break;
      default:
        break;
    }
    //ARP doesn't encapsulate other protocols
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
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
  }

  @Override
  public String toString() {

    String res = "Ethernet Frame\n";
    res += ("Source \t\t"+Tools.macAddress(header.get("src"))+"\n");
    res += ("Destination \t"+Tools.macAddress(header.get("dst"))+"\n");
    res += ("Type \t\t"+Tools.ethProtocol(header.get("type"))+"\n");
    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    }
    res += "\n\n";
    return res;
  }

}
