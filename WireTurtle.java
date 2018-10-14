import java.nio.file.*;
import java.util.*;
import java.io.*;

public class WireTurtle {
	public static void main(String[] args) {
		//verify pcap + ethernet protocol
		PCAP pcap;
		switch(args.length) {
			case 0:
				System.out.println("WireTurtle [-f protocol_filter] file.pcap");
				break;
			case 1:
				pcap = new PCAP(args[0]);
				System.out.println(pcap);
				break;
			case 3:
				pcap = new PCAP(args[2], args[1].toUpperCase());
				//pcap.filter(args[1].toUpperCase());
				System.out.println(pcap);
				break;
			default:
				System.out.println("WireTurtle [-f protocol_filter] file.pcap");
				break;
		}
	}
}
