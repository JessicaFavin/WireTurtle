import java.nio.file.*;
import java.util.*;
import java.io.*;

public class HTTP extends Layer7 {
  private HashMap<String, String> header;
  private byte[] raw_data;
  protected Packet encapsulated_packet;

  public HTTP(byte[] packet) {
    this.raw_data = packet;
    this.header = new HashMap<String, String>();
    this.setPacket(packet);
    this.encapsulated_packet = null;
  }

  @Override
  public void setPacket(byte[] packet) {
    if(packet!=null) {
      header.put("http content", Tools.hexToString(packet));
    }
  }

  @Override
  public String toString() {
    String res = "Hypertext Transfer Protocol (HTTP)\n";
    if(header.get("http content")!=null){
      res += Tools.hexToAscii(header.get("http content"));
    }
    res += "\n";
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
    return false;
  }

  @Override
  public boolean isDNS(){
    return false;
  }

  @Override
  public boolean isDHCP(){
    return false;
  }

  @Override
  public boolean isHTTP(){
    return true;
  }

  @Override
  public boolean isFTP(){
    return false;
  }

}
