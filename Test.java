import java.nio.file.*;
import java.io.*;
import java.util.Arrays;

public class Test {
		private static String toHex(byte[] byteArray) {
				String st = "";
				for (int i=0; i<byteArray.length; i++) {
						st += String.format("%02X", byteArray[i]);
				}
				return st.toUpperCase();
		}

		public static void main(String[] args){
				File file = new File(args[0]);
				try {
						FileInputStream fis = new FileInputStream(file);
						byte[] byteArray = new byte[800];
						int value = fis.read(byteArray);
						byte[] b = Arrays.copyOfRange(byteArray, 0, value);
						System.out.println("byte array "+b);
						String hex = toHex(b);
						if(hex.equals("A1B2C3D4")) {
								System.out.println("decimal int okay");
						}
				} catch (Exception e) {
						e.printStackTrace();
				}
		}
}
