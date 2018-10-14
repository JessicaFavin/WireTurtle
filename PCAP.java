import java.nio.file.*;
import java.util.*;
import java.io.*;

public class PCAP {

  private static int[] global_header_size = {4, 2, 2, 4, 4, 4, 4};
	private static String[] global_header_tag = {"magic number", "version major",
		"version minor", "timezone", "timestamp accuracy", "snaplen", "network"};
	private static HashMap<String, String> global_header;
	private static int[] packet_header_size = {4, 4, 4, 4};
	private static int[] packet_header_tag = {4, 4, 4, 4};
	private static ArrayList<Ethernet> snapshot;

  public PCAP(String filename) {
    File file = new File(filename);
		int bytes_to_read = (int) file.length();
		byte[] fileArray;
		snapshot = new ArrayList<Ethernet>();
		try{
			byte[] byteArray = new byte[2048];
			int value = 0;
			String hex_data = "";
			FileInputStream fis = new FileInputStream(file);
			global_header = new HashMap<String, String>();
			for(int i = 0; i<global_header_size.length; i++) {
				value = fis.read(byteArray, 0, global_header_size[i]);
				bytes_to_read -= value;
				hex_data = Tools.hexToString(Arrays.copyOfRange(byteArray,0,value));
				global_header.put(global_header_tag[i],hex_data);
			}
			int packet_size = 0;
			while(bytes_to_read>0){
				//reads all packets in the snapshot
				for(int i = 0; i<packet_header_size.length; i++) {
					value = fis.read(byteArray, 0, packet_header_size[i]);
					bytes_to_read -= value;
					if(i==2) {
						packet_size = Tools.hexToIntReversed(byteArray, value);
					}
				}
				//Ethernet
				value = fis.read(byteArray, 0, packet_size);
				bytes_to_read -= value;
				snapshot.add(new Ethernet(Arrays.copyOfRange(byteArray, 0, value)));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
  }

  @Override
  public String toString() {
    String res = "";
    for(Ethernet ef : snapshot) {
      res += ef.toString();
    }
    return res;
  }

  public void filter(String protocol) {
    ArrayList<Ethernet> res = new ArrayList<Ethernet>();
    switch(protocol) {
      case "ARP":
        for(Ethernet ef : snapshot) {
          if(ef.isARP()){
            res.add(ef);
          }
        }
        break;
      case "ICMP":
        for(Ethernet ef : snapshot) {
          if(ef.isICMP()){
            res.add(ef);
          }
        }
        break;
      case "IP":
        for(Ethernet ef : snapshot) {
          if(ef.isIP()){
            res.add(ef);
          }
        }
        break;

      case "UDP":
        for(Ethernet ef : snapshot) {
          if(ef.isUDP()){
            res.add(ef);
          }
        }
        break;
      case "TCP":
        for(Ethernet ef : snapshot) {
          if(ef.isTCP()){
            res.add(ef);
          }
        }
        break;
      case "DNS":
        for(Ethernet ef : snapshot) {
          if(ef.isDNS()){
            res.add(ef);
          }
        }
        break;
        case "DHCP":
        for(Ethernet ef : snapshot) {
          if(ef.isDHCP()){
            res.add(ef);
          }
        }
        break;
      case "HTTP":
        for(Ethernet ef : snapshot) {
          if(ef.isHTTP()){
            res.add(ef);
          }
        }
        break;
      case "FTP":
        for(Ethernet ef : snapshot) {
          if(ef.isFTP()){
            res.add(ef);
          }
        }
        break;
      default:
        res = snapshot;
    }
    snapshot = res;
  }

}
