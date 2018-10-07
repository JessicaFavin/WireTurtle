import java.nio.file.*;
import java.util.*;
import java.io.*;

public class EthernetFrame extends Packet {


  private static String[] fields_name = {"dst", "src", "type", "data", "crc"};
  private int[] fields_size = {6, 6, 2, 0, 4};
  private static int[] arp_fields_size = {2, 2, };
  private static int header_total = 18;
  private HashMap<String, byte[]> header;
  private byte[] raw_packet;
  private byte[] raw_data;
  private Packet encapsulated_packet;

  public EthernetFrame(byte[] packet) {
    this.header = new HashMap<String, byte[]>();
    this.raw_packet = packet;
    this.setPacket(packet);
    switch(Tools.hexToString(header.get("type"))) {
      case "0806":
        //ARP packet -> setData
        encapsulated_packet = new ARPPacket(raw_data);
        break;
      case "0800":
        //IPv4 packet
        break;
      default:
        break;
    }
    //ARP doesn't encapsulate other protocols
  }

  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    for(int i=0; i< fields_size.length; i++) {

      size = fields_size[i];
      if(size==0) {
        //data length including padding
        size = (packet.length-header_total);
        fields_size[i] = size;
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet,offset, offset+size);
        this.raw_data = buffer;
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        header.put(fields_name[i], buffer);
      }
      offset += size;
    }
  }

  @Override
  public String toString() {

    String res = "Ethernet Frame\n";
    res += ("Destination \t"+Tools.hexToMAC(header.get("dst"))+"\n");
    res += ("Source \t\t"+Tools.hexToMAC(header.get("src"))+"\n");
    res += ("Type \t\t"+Tools.findProtocol(Tools.hexToString(header.get("type")))+"\n");
    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    }
    res += "\n\n";
    return res;
  }

  @Override
  public HashMap<String, byte[]> getHeader() {
    return header;
  }

}
