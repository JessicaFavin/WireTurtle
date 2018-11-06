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
	private ArrayList<Ethernet> snapshot;
  private String filterProtocol;
  private int convNumber;
  private HashMap<String,ConversationTCP> conversations;

  public PCAP(String filename, String filter) {
    this(filename);
    this.filterProtocol = filter;
  }

  public PCAP(String filename, int convNumber) {
    this(filename);
    this.convNumber = convNumber;
  }

  public PCAP(String filename) {
    File file = new File(filename);
		int bytes_to_read = (int) file.length();
		byte[] fileArray;
		this.snapshot = new ArrayList<Ethernet>();
    this.conversations = new HashMap<String,ConversationTCP>();
    this.filterProtocol = "";
    this.convNumber = -1;
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
      recomposeConversations();
		} catch (Exception e) {
			e.printStackTrace();
		}
  }

  private void recomposeConversations() {
    int inHandshake = 0;// outHandshake = 0;
    String id = "", idReversed = "";

    loop: for(Ethernet ef : snapshot) {
      if(ef.isTCP()){
        id = (ef.getIpSrc()+ef.getPortSrc()+ef.getIpDst()+ef.getPortDst());
        idReversed = (ef.getIpDst()+ef.getPortDst()+ef.getIpSrc()+ef.getPortSrc());
        //System.out.println("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
        //System.out.println("ID: "+id+" "+idReversed);
        if(inHandshake==0){
          if(ef.hasSyn()) {
            //System.out.println("Syn");
            inHandshake++;
            continue;
          } else {
            inHandshake = 0;
          }
        } else if(inHandshake==1){
          if(ef.hasSyn() && ef.hasAck()) {
            //System.out.println("Syn Ack");
            inHandshake++;
            continue;
          } else {
            inHandshake = 0;
          }
        } else if(inHandshake==2){
          if(ef.hasAck()) {
            //System.out.println("Ack");
            inHandshake++;
            //add couple in conv
            conversations.put(id, new ConversationTCP(id));
            //System.out.println("Contains : "+conversations.containsKey(id));
            inHandshake = 0;
            continue;
          } else {
            inHandshake = 0;
          }
        }
        //------------Not a handshake message--------------
        if(conversations.containsKey(id)){
          conversations.get(id).addPaquet(ef);
          //System.out.println("Added");
        } else if(conversations.containsKey(idReversed)){
          conversations.get(idReversed).addPaquet(ef);
          //System.out.println("Added");
        }
      }
    }
    for(Map.Entry conv : conversations.entrySet()) {
      ((ConversationTCP)conv.getValue()).recompose();
    }
  }

  private String color(Ethernet ef) {
    String res = "";
    if(ef.isDHCP()) {
      res += "\u001B[33m";
    } else if(ef.isDNS()) {
      res += "\u001B[34m";
    } else if(ef.isFTP() || this.containedInConversation(ef)){
      res += "\u001B[92m";
    } else if(ef.isHTTP() || this.containedInConversation(ef)) {
      res += "\u001B[32m";
    } else if(ef.isTCP()) {
      res += "\u001B[35m";
    } else if(ef.isUDP()) {
      res += "\u001B[36m";
    } else if(ef.isIP()) {
      res += "\u001B[93m";
    } else if(ef.isICMP()) {
      res += "\u001B[94m";
    } else if(ef.isARP()) {
      res += "\u001B[95m";
    }
    return res;
  }

  private boolean containedInConversation(Ethernet ef) {
    boolean contained = false;
    for (Map.Entry entry : conversations.entrySet()) {
      if(((ConversationTCP) entry.getValue()).contains(ef)) {
        contained = true;
      }
    }
    return contained;
  }

  public String displayProtocolPackets() {
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
            if(ef.isHTTP() || this.containedInConversation(ef)){
              res += ("--------- Packet #"+(snapshot.indexOf(ef)+1)+" ---------\n");
              res += color(ef)+ef.toString();
            }
          break;
        case "FTP":
            if(ef.isFTP() || this.containedInConversation(ef)){
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
    res += conversations.size()+" conversations were found.";
    return res;
  }

  public String displayConversation(int which) {
    int i = 1;
    String res = "";
    for (Map.Entry entry : conversations.entrySet()) {
      if(which==0 || i==which){
        res += "--------- Conversation #"+i+" ---------\n";
        res += entry.getValue().toString();
      }
      i++;
    }
    return res;
  }

  @Override
  public String toString() {
    String res = "";
    if(convNumber>=0) {
      res += displayConversation(this.convNumber);
    } else {
      res += displayProtocolPackets();
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
