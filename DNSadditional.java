public class DNSadditional {
  private String type;
  private String dnsClass;
  private String ttl;
  private String dnsData;

  public DNSadditional(String type, String dnsClass, String ttl, String dnsData) {
    this.type = type;
    this.dnsClass = dnsClass;
    this.ttl = ttl;
    this.dnsData = dnsData;
  }

  @Override
  public String toString() {
    String res = "Type : \t\t"+Tools.dnsType(this.type)+"\n";
    res += "Class : \t"+Tools.dnsClass(this.dnsClass)+"\n";
    if(type.equals("001c")){
      res += "Address \t"+Tools.hexToIPv6(this.dnsData)+"\n";
    } else if (this.type.equals("0001")){
      res += "Address \t"+Tools.ipAddress(this.dnsData)+"\n";
    } else if (this.type.equals("000f")){
      String domain = this.dnsData.substring(4, this.dnsData.length()-4);
      res += "Mail exchange \t\t"+Tools.hexToAscii(domain)+"\n";
    } else {
      res += "Data \t\t"+Tools.hexToAscii(this.dnsData)+"\n";
    }
    return res;
  }
}
