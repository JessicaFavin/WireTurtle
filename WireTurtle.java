
public class WireTurtle {
	public static void main(String[] args) {
		//verify pcap + ethernet protocol
		PCAP pcap = new PCAP(args[0]);
		System.out.println(pcap);
	}
}
