
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Func {
	 /*public static void main(String[] args) {
		try {
			System.out.println("ttt");
			System.out.println("ttt");
			boolean flag = true;
			String[] o2 = new String[3];
			o2[0] = "./a.out";
			o2[1] = "-i";
			o2[2] = "enp1s0";
			ProcessBuilder pb = new ProcessBuilder(o2);
			Process p2 = pb.start();
			BufferedReader br = new BufferedReader(new InputStreamReader(p2.getInputStream()));
			//HelloJNI hello= new HelloJNI();
			//hello.hello();
		} catch (Exception e) {
			System.out.println(e);
		}
	}*/
	static String device;

	public static BufferedReader getProcess() {
		try {
			System.out.println("ttt");
			System.out.println("ttt");
			boolean flag = true;
			String[] o2 = new String[3];
			o2[0] = "./a.out";
			o2[1] = "-i";
			o2[2] = device;
			//o2[2]="ens33";
			ProcessBuilder pb = new ProcessBuilder(o2);
			Process p2 = pb.start();
			BufferedReader br = new BufferedReader(new InputStreamReader(p2.getInputStream()));
			return br;
		} catch (Exception e) {
			System.out.println(e);
		}
		return null;
	}

	public static BufferedReader FindDevice() {
		try {
			String[] o1 = new String[2];
			o1[0] = "ls";
			o1[1] = "/sys/class/net/";
			ProcessBuilder pb = new ProcessBuilder(o1);
			Process p1 = pb.start();
			BufferedReader de = new BufferedReader(new InputStreamReader(p1.getInputStream()));
			return de;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
