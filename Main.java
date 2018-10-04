import java.nio.file.*;
import java.io.*;
public class Main {
	private static int[] global_header = {4, 2, 2, 4, 4, 4, 4};
	private static int[] packet_header = {4, 4, 4, 4};
	private static int data_size = 0;

	private static void printHex(byte[] byteArray, int value) {
		for (int i=0; i<value; i++) {
			String st = String.format("%02X", byteArray[i]);
			System.out.print(st);
		}
		System.out.println("");
	}

	private static String toHexReversed(byte[] byteArray, int value) {
		String st = "";
		for (int i=0; i<value; i++) {
			String reverse = new StringBuilder(String.format("%02X", byteArray[i])).reverse().toString();
			st += reverse;
		}

		return (new StringBuilder(st).reverse().toString());
	}

	private static String toHex(byte[] byteArray, int value) {
		String st = "";
		for (int i=0; i<value; i++) {
			st += String.format("%02X", byteArray[i]);
		}
		return st;
	}

	public static void main(String[] args) {
		//Path file = Paths.get("/home/user/arp.pcap");
		File file = new File("/home/user/arp.pcap");
		byte[] fileArray;
		try{
			byte[] byteArray = new byte[800];
			int value = 0;
			FileInputStream fis = new FileInputStream(file);
			for(int i: global_header) {
				value = fis.read(byteArray, 0, i);
				System.out.println(toHexReversed(byteArray, value));
			}
			for(int i :	packet_header) {
				value = fis.read(byteArray, 0, i);
				System.out.println(toHexReversed(byteArray, value));
			}
			data_size = Integer.parseInt(toHexReversed(byteArray, value),16);
			System.out.println(data_size);
			value = fis.read(byteArray, 0, data_size);
			printHex(byteArray, value);
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("");
	}
}
