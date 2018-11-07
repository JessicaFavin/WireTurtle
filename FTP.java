import java.nio.file.*;
import java.util.*;
import java.io.*;

public class FTP extends Layer7 {

  private HashMap<String, String> header;
  private byte[] raw_data;

  public FTP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.raw_data = packet;
    this.setPacket(packet);
    this.encapsulated_packet = null;
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    if(packet!=null) {
      header.put("ftp command", Tools.hexToString(packet));
    }
  }

  public void setOptions() {

  }

  @Override
  public String toString() {
    String ftpCommand = header.get("ftp command");
    String res = "File Transfer Protocol (FTP) \n";
    if(ftpCommand!=null) {
      res += Tools.hexToAscii(ftpCommand)+"\n";
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
    return false;
  }

  @Override
  public boolean isFTP(){
    return true;
  }

}
