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
  private String filterProtocol;

  public PCAP(String filename, String filter) {
    this(filename);
    this.filterProtocol = filter;
  }

  public PCAP(String filename) {
    File file = new File(filename);
		int bytes_to_read = (int) file.length();
		byte[] fileArray;
		snapshot = new ArrayList<Ethernet>();
    filterProtocol = "";
		try{
			byte[] byteArray = new byte[8192];
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
      int packet_count = 1;
			while(bytes_to_read>0){
        //System.out.println("-------------Packet n° "+ packet_count+" --------------");
        //System.out.println("bytes to read "+ bytes_to_read);
				//reads all packets in the snapshot
				for(int i = 0; i<packet_header_size.length; i++) {
					value = fis.read(byteArray, 0, packet_header_size[i]);
					bytes_to_read -= value;
					if(i==2) {
						packet_size = Tools.hexToIntReversed(byteArray, value);
					}
				}
				//Ethernet
        //System.out.println("packet size "+ packet_size);
				value = fis.read(byteArray, 0, packet_size);
				bytes_to_read -= value;
				snapshot.add(new Ethernet(Arrays.copyOfRange(byteArray, 0, value)));
        packet_count++;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
  }

  private String color(Ethernet ef) {
    String res = "";
    if(ef.isFTP()){
      res += "\u001B[30m";
    } else if(ef.isHTTP()) {
      res += "\u001B[32m";
    } else if(ef.isDHCP()) {
      res += "\u001B[33m";
    } else if(ef.isDNS()) {
      res += "\u001B[34m";
    } else if(ef.isTCP()) {
      res += "\u001B[35m";
    } else if(ef.isUDP()) {
      res += "\u001B[36m";
    } else if(ef.isIP()) {
      res += "\u001B[37m";
    } else if(ef.isICMP()) {
      res += "\u001B[38m";
    } else if(ef.isARP()) {
      res += "\u001B[39m";
    }
    return res;
  }

  @Override
  public String toString() {
    String res = "";
    for(Ethernet ef : snapshot) {
      switch(filterProtocol) {
        case "ARP":
            if(ef.isARP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "ICMP":
            if(ef.isICMP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "IP":
            if(ef.isIP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;

        case "UDP":
            if(ef.isUDP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "TCP":
            if(ef.isTCP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "DNS":
            if(ef.isDNS()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
          case "DHCP":
            if(ef.isDHCP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "HTTP":
            if(ef.isHTTP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "FTP":
            if(ef.isFTP()){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        default:
          res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
          res += color(ef)+ef.toString();
          break;
      }

      res += "\u001B[0m";
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
