import java.nio.file.*;
import java.util.*;
import java.io.*;

public class ARPPacket extends Packet {

  // 0 means the rest of it
  private static String[] fields_name = {"hardware type", "protocol type",
    "hardware address length", "protocol address length", "operation code",
    "src MAC","src IP","dst MAC","dst IP"};
  private static int[] fields_size = {2, 2, 1, 1, 2, 6, 4, 6, 4};
  private static int header_total = 8;
  private HashMap<String, byte[]> header;
  private byte[] raw_packet;
  private byte[] raw_data;
  private Packet encapsulated_packet;

  public ARPPacket(byte[] packet) {
    System.out.println("creating ARP packet");
    this.header = new HashMap<String, byte[]>();
    this.raw_packet = packet;
    this.setPacket(packet);
    this.encapsulated_packet = null;
    System.out.println("created");
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
        buffer = Arrays.copyOfRange(packet,offset, offset+size);

      }
      offset += size;
    }
  }

  @Override
  public String toString() {
    String res = "";
    res += "OpCode \t"+Tools.arpOpCode(header.get("operation code"));
    res += "MAC src \t"+Tools.hexToMAC(header.get("src mac"));
    res += "IP src \t"+Tools.hexToIP(header.get("src ip"));
    res += "MAC dst \t"+Tools.hexToMAC(header.get("dst mac"));
    res += "IP dst \t"+Tools.hexToIP(header.get("dst ip"));
    System.out.println(res);
    return res;
  }

  @Override
  public HashMap<String, byte[]> getHeader() {
    return header;
  }

}
