public class Tools {

  public static String hexToString(byte[] byteArray) {
    String st = "";
    for (int i=0; i<byteArray.length; i++) {
      st += String.format("%02X", byteArray[i]);
    }
    return st.toLowerCase();
  }

  public static String hexToString(byte[] byteArray, int value) {
    String st = "";
    for (int i=0; i<value; i++) {
      st += String.format("%02X", byteArray[i]);
    }
    return st.toLowerCase();
  }

  public static String hexToStringReversed(byte[] byteArray) {
    String st = "";
    for (int i=0; i<byteArray.length; i++) {
      String reverse = new StringBuilder(String.format("%02X", byteArray[i])).reverse().toString();
      st += reverse;
    }
    return (new StringBuilder(st).reverse().toString()).toLowerCase();
  }

  public static String hexToStringReversed(byte[] byteArray, int value) {
    String st = "";
    for (int i=0; i<value; i++) {
      String reverse = new StringBuilder(String.format("%02X", byteArray[i])).reverse().toString();
      st += reverse;
    }

    return (new StringBuilder(st).reverse().toString()).toLowerCase();
  }

  public static int hexToInt(byte[] byteArray) {
    return Integer.parseInt(hexToString(byteArray),16);
  }

  public static int hexToInt(byte[] byteArray, int value) {
    return Integer.parseInt(hexToString(byteArray, value),16);
  }

  public static int hexToIntReversed(byte[] byteArray) {
    return Integer.parseInt(hexToStringReversed(byteArray),16);
  }

  public static int hexToIntReversed(byte[] byteArray, int value) {
    return Integer.parseInt(hexToStringReversed(byteArray, value),16);
  }

  public static String ethProtocol(String hex) {
    String res = hex;
    switch(hex) {
      case "0806":
        res += " (ARP)";
        break;
      case "0800":
        res += " (IPv4)";
        break;
      default:
        break;
    }
    return res;
  }

  public static String ipProtocol(String hex) {
    String res =  hex;
    switch(hex) {
      case "01":
        res += " (ICMP)";
        break;
      default:
        break;
    }
    return res;
  }

  public static String icmpProtocol(String hex_type, String code) {
    int type = Integer.parseInt(hex_type, 16);
    String res = String.valueOf(type);
    switch(type) {
      case 0:
        res += " Echo reply (ping)";
        break;
      case 3:
        res += " Destination unreacheable";
        break;
      case 5:
        res += " Redirect message";
        break;
      case 8:
        res += " Echo request (ping)";
        break;
      case 11:
        res += " Time exceeded";
        break;
      case 30:
        res += " Traceroute ";
        break;
      default:
        break;
    }
    return res;
  }

  public static String arpOpCode(String opcode) {
    String res = opcode;
    switch(opcode) {
      case "0001":
        res += " (request)";
        break;
      case "0002":
        res += " (reply)";
        break;
      default:
        break;
    }
    return res;
  }

  public static String sllProtocol(String hex) {
    String res = hex;
    switch(hex) {
      case "0800":
        res += " (IPv4)";
        break;
      case "86dd":
        res += " (IPv6)";
        break;
      default:
        break;
    }
    return res;
  }

  public static String udpPort(int dst_port) {
    String res = String.valueOf(dst_port);
    switch(dst_port){
      case 53:
        res += " (DNS)";
        break;
      case 67:
        res += " DHCP (server)";
        break;
      case 68:
        res += " DHCP (client)";
        break;
      default:
        break;
    }
    return res;
  }

  public static String macAddress(String st) {
    String res = "";
    if(st.length() != 12) {
      return st;
    }
    for(int i=0; i< st.length(); i++){
      res += st.charAt(i);
      if(i%2==1){
        res+= (i!=st.length()-1)?":":"";
      }
    }
    return res;
  }

    public static String hexToMAC(byte[] byteArray) {
      return macAddress(hexToString(byteArray));
    }

    public static String ipAddress(String st) {
      String res = "", tmp = "";
      for(int i=0; i< st.length(); i+=2){
        tmp += ""+st.charAt(i)+st.charAt(i+1);
        int ip = Integer.parseInt(tmp, 16);
        res += String.valueOf(ip);
        res+= (i!=st.length()-2)?".":"";
        tmp = "";
      }
      return res;
    }

    public static String hexToIP(byte[] byteArray) {
      return ipAddress(hexToString(byteArray));
    }

    /**
     * code based on https://stackoverflow.com/questions/4785654/convert-a-string-of-hex-into-ascii-in-java#4785776
    **/
    public static String hexToAscii(String hex) {
      StringBuilder output = new StringBuilder();
      for (int i = 0; i < hex.length(); i+=2) {
          String str = hex.substring(i, i+2);
          int ascii = Integer.parseInt(str, 16);
          //readable ascii only
          if(ascii>=32&&ascii<=126){
            output.append((char) ascii);
          } else if (ascii == 0) {
            break;
          }
      }
      return output.toString();
    }

    public static String dnsType(String type){
      String res = Integer.parseInt(type,16)+" ";
      switch(type){
        case "0001":
          res += "A (host Address)";
          break;
        case "0002":
          res += "NS (authoritative Name Server)";
          break;
        case "0005":
          res += "CNAME (Canonical Name)";
          break;
        case "000c":
          res += "PTR (domain name PoinTeR)";
          break;
        case "000f":
          res += "MX (Mail eXchange)";
          break;
        case "0010":
          res += "TXT (Text)";
          break;
        case "0021":
          res+= "SRV (Server Selection)";
          break;
        case "00ff":
          res+= "* (all records available)";
          break;
        case "001c":
          res += "AAAA (IPv6 address)";
          break;
        default:
          break;
      }
      return res;
    }

    public static String dnsClass(String dnsclass){
      String res = "0x"+dnsclass+" ";
      switch(dnsclass){
        case "0001":
          res += "IN (internet)";
          break;
        case "0002":
          res += "CS (csnet)";
          break;
        case "0003":
          res += "CH (chaos)";
          break;
        case "0004":
          res += "HS (hesiod)";
          break;
        default:
          break;
      }
      return res;
    }

    public static String dnsReplyCode(Integer replyCode){
      String res = String.valueOf(replyCode)+" ";
      switch(replyCode) {
        case 0:
          res += "No error";
          break;
        case 1:
          res += "Format error";
          break;
        case 2:
          res += "Server fail";
          break;
        case 3:
          res += "No such name";
          break;
        case 5:
          res += "Refused";
          break;
        default:
          break;
      }
      return res;
    }

    public static String dnsResolution(String hex) {
      String url = hex.substring(0, hex.length()-8);
      String type = hex.substring(hex.length()-8, hex.length()-4);
      String dnsclass = hex.substring(hex.length()-4, hex.length());
      String res = hexToAscii(url);
      res += "\n\t\t"+Tools.dnsType(type);
      res += "\n\t\t"+Tools.dnsClass(dnsclass);
      return res;
    }

    public static String displayRawData(String hex) {
      String res = "";
      for(int i=0; i<hex.length(); i++){
        res += hex.charAt(i);
        if(i%2==1){
          res+=" ";
        }
        if(i%16==15){
          res+=" ";
        }
        if(i%32==31) {
          res += "\n\t\t\t";
        }
      }
      return res;
    }

}
