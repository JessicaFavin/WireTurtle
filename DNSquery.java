public class DNSquery {
  private String name;
  private String type;
  private String dnsClass;

  public DNSquery(String name, String type, String dnsClass) {
    this.name = name;
    this.type = type;
    this.dnsClass = dnsClass;
  }

  @Override
  public String toString() {
    String res = Tools.hexToAscii(this.name)+"\n";
    res += "Type : \t\t"+Tools.dnsType(this.type)+"\n";
    res += "Class : \t\t"+Tools.dnsClass(this.dnsClass);
    return res;
  }
}
