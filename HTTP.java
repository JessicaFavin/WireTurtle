import java.nio.file.*;
import java.util.*;
import java.io.*;

public class HTTP extends Layer7 {
  //private static final String[] fields_name = {"id", "flags", "questions", "answer RRs",
  //"authority RRs", "addiditonal RRs", "data"};
  //private int[] fields_size = {2, 2, 2, 2, 2, 2, 0};
  //private static int header_total = 12;
  private HashMap<String, String> header;
  private byte[] raw_data;


/*
HTTP/1.1 200 OK\r\n
P3P: policyref="http://www.googleadservices.com/pagead/p3p.xml", CP="NOI DEV PSA PSD IVA PVD OTP OUR OTR IND OTC"\r\n
Content-Type: text/html; charset=ISO-8859-1\r\n
Content-Encoding: gzip\r\n
Server: CAFE/1.0\r\n
Cache-control: private, x-gzip-ok=""\r\n
Content-length: 1272\r\n
Date: Thu, 13 May 2004 10:17:14 GMT\r\n
\r\n
...........W.s.8..\r\n
\r\n
*/

  public HTTP(byte[] packet) {
    this.raw_data = packet;
    //System.out.println("HTTP");
    //System.out.println("Raw data set");
    //System.out.println("RD : "+Tools.hexToString(this.raw_data));
    this.header = new HashMap<String, String>();
    //this.setPacket(packet);
  }

  @Override
  public void setPacket(byte[] packet) {

  }

  @Override
  public String toString() {
    String res = "Hypertext Transfer Protocol (HTTP)\n";
    if(this.raw_data!=null){
      res += Tools.hexToAscii(Tools.hexToString(this.raw_data));
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
