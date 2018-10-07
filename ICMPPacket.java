import java.nio.file.*;
import java.util.*;
import java.io.*;

public class ICMPPacket extends Packet {

  private static String[] fields_name = {"type", "code", "checksum", "id", "seq",
  "timestamp", "data"};
  private int[] fields_size = {1,1,2,2,2,8,0};
  private static int header_total = 16;
  private HashMap<String, String> header;
  private Packet encapsulated_packet;
  private byte[] raw_data;

  public ICMPPacket(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    this.encapsulated_packet = null;
    this.raw_data = null;
  }

  @Override
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
        header.put(fields_name[i], Tools.hexToString(buffer));
      } else {
        buffer = new byte[size];
        buffer = Arrays.copyOfRange(packet, offset, offset+size);
        //to do reverse seq and id to get the LE version
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
  }

  @Override
  public String toString() {
    String res = "ICMP Protocol\n";
    res += "type \t"+Tools.icmpProtocol(header.get("type"), header.get("code"))+"\n";
    res += "id \t0x"+header.get("id")+"\n";
    res += "seq \t"+Integer.parseInt(header.get("seq"),16)+"\n";
    res += "data \t"+Tools.hexToAscii(header.get("data"))+"\n";
    return res;
  }

}
