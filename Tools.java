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
    String res;
    switch(hex) {
      case "0806":
        res = hex+" (ARP)";
        break;
      case "0800":
        res = hex+" (IPv4)";
        break;
      default:
        res = hex;
        break;
    }
    return res;
  }

  public static String ipProtocol(String hex) {
    String res;
    switch(hex) {
      case "01":
        res = hex+" (ICMP)";
        break;
      default:
        res = hex;
        break;
    }
    return res;
  }

  public static String icmpProtocol(String hex_type, String code) {
    int type = Integer.parseInt(hex_type, 16);
    String res;
    switch(type) {
      case 0:
        res = type+" Echo reply (ping)";
        break;
      case 3:
        res = type+" Destination unreacheable";
        break;
      case 5:
        res = type+" Redirect message";
        break;
      case 8:
        res = type+" Echo request (ping)";
        break;
      case 11:
        res = type+" Time exceeded";
        break;
      case 30:
        res = type+" traceroute ";
        break;
      default:
        res = String.valueOf(type);
        break;
    }
    return res;
  }

  public static String arpOpCode(String opcode) {
    String res = "";
    switch(opcode) {
      case "0001":
        res = opcode+" (request)";
        break;
      case "0002":
        res = opcode+" (reply)";
        break;
      default:
        res = opcode;
        break;
    }
    return res;
  }

  public static String macAddress(String st) {
    String res = "";
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
          }
      }
      return output.toString();
    }
}
