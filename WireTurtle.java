import java.nio.file.*;
import java.util.*;
import java.io.*;

public class WireTurtle {
	public static void displayUse() {
		System.out.println("WireTurtle [-f protocol_filter | -c conversation_number] file.pcap");
		System.out.println("protocol_filter : ARP ICMP IP TCP UDP HTTP FTP DHCP DNS");
		System.out.println("conversation_number : 0 for all conversation");
	}
	public static void main(String[] args) {
		PCAP pcap;
		switch(args.length) {
			case 0:
				displayUse();
				break;
			case 1:
				pcap = new PCAP(args[0]);
				System.out.println(pcap);
				break;
			case 3:
				if(args[0].equals("-c")){
					try{
						pcap = new PCAP(args[2], Integer.parseInt(args[1]));
						System.out.println(pcap);
					} catch(NumberFormatException e) {
						displayUse();
					}
				} else if (args[0].equals("-f")){
					pcap = new PCAP(args[2], args[1].toUpperCase());
					System.out.println(pcap);
				} else {
					displayUse();
				}
				break;
			default:
				displayUse();
				break;
		}
	}
}
