import java.nio.file.*;
import java.util.*;
import java.io.*;

public class ARPPacket extends Packet {

  private static String[] fields_name = {"hardware type", "protocol type",
    "hardware address length", "protocol address length", "operation code",
    "src mac","src ip","dst mac","dst ip"};
  private int[] fields_size = {2, 2, 1, 1, 2, 6, 4, 6, 4};
  private static int header_total = 8;
  private HashMap<String, String> header;
  private Packet encapsulated_packet;
  private byte[] raw_data;

  public ARPPacket(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    this.encapsulated_packet = null;
    this.raw_data = null;
  }

  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      buffer = new byte[size];
      buffer = Arrays.copyOfRange(packet,offset, offset+size);
      header.put(fields_name[i], Tools.hexToString(buffer));
      offset += size;
    }
  }

  @Override
  public String toString() {
    String res = "ARP Protocol\n";
    res += "OpCode \t\t"+Tools.arpOpCode(header.get("operation code"))+"\n";
    res += "MAC src \t"+Tools.macAddress(header.get("src mac"))+"\n";
    res += "IP src \t\t"+Tools.ipAddress(header.get("src ip"))+"\n";
    res += "MAC dst \t"+Tools.macAddress(header.get("dst mac"))+"\n";
    res += "IP dst \t\t"+Tools.ipAddress(header.get("dst ip"))+"\n";
    return res;
  }

}
