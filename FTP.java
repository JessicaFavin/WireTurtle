import java.nio.file.*;
import java.util.*;
import java.io.*;

public class FTP extends Layer7 {


  private static String[] fields_name = {"op code", "hardware type", "hardware len",
  "hops", "transaction id", "seconds", "flags", "client IP", "your IP", "server IP", "gateway IP",
  "client hardware address", "server name", "boot filename", "options"};
  private int[] fields_size = {1, 1, 1, 1, 4, 2, 2, 4, 4, 4, 4, 16, 64, 128, -1};
  private static int header_total = 236;
  private HashMap<String, String> header;
  private HashMap<Integer, String> options;
  private Layer7 encapsulated_packet;
  private byte[] raw_data;
  private int source_port;
  private int destination_port;

  public FTP(byte[] packet) {
    this.header = new HashMap<String, String>();
    this.options = new HashMap<Integer, String>();
    this.raw_data = null;
    this.encapsulated_packet = null;
    this.setPacket(packet);
  }

  @Override
  public void setPacket(byte[] packet) {
    int offset = 0;
    byte[] buffer;
    int size;
    header.put("ftp command", Tools.hexToString(packet));
    /*
    //System.out.println(Tools.hexToString(packet));
    packet: for(int i=0; i< fields_size.length; i++) {
      size = fields_size[i];
      if(size==-1) {
        //data length including padding
        if(header_total == packet.length){
          size = 0;
          header.put(fields_name[i], "");
        } else {
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
        header.put(fields_name[i], Tools.hexToString(buffer));
      }
      offset += size;
    }
    */
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
