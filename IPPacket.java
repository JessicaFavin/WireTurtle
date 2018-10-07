import java.nio.file.*;
import java.util.*;
import java.io.*;

public class IPPacket extends Packet {


  private static String[] fields_name = {"version header length", "DSCP ECN",
  "total length", "identification", "flags", "ttl", "protocol", "header checksum",
  "src ip", "dst ip"};
  private int[] fields_size = {1,1,2,2,2,1,1,2,4,4};
  private static int header_total = 20;
  private HashMap<String, String> header;
  private Packet encapsulated_packet;
  private byte[] raw_data;

  public IPPacket(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    switch(header.get("protocol")) {
      case "01":
        //this.encapsulated_packet = new ICMPPacket(raw_data);
        break;
      default:
        break;
    }
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
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
  }

  @Override
  public String toString() {

    String res = "IP Paquet\n";

    res += ("Source \t\t"+Tools.ipAddress(header.get("src ip"))+"\n");
    res += ("Destination \t"+Tools.ipAddress(header.get("dst ip"))+"\n");
    res += ("Type \t\t"+Tools.ipProtocol(header.get("protocol"))+"\n");

    if(encapsulated_packet!=null){
      res += "\n";
      res += encapsulated_packet.toString();
    }
    res += "\n\n";
    return res;
  }

}
