
import java.io.BufferedReader;
import java.io.IOException;
import java.util.ArrayList;

public class Create  {
	static String preStr="";
	static String sm="";
	/*
	 *統計用変数の設定 
	 */
	static int p_count = 0; //パケットの個数	
	static int per_count = 0; //1秒ごとのパケット数
	static long start = System.currentTimeMillis(); //開始時間
	static long cu_time = 0; //現在時間
	static Statistics st = new Statistics();
	
	static int no=1;
	
	public static void analyze() throws IOException {
		BufferedReader br=Func.getProcess();
//		if(br==null)System.out.print("null exe");
//		else System.out.print("not null");
//		System.out.print("tttttttttttttttttttttttttttttttttttttttttttt");
		try {
			String str="";
			while(!str.matches("([0-9a-z][0-9a-z]:){5}[0-9a-z][0-9a-z] -> ([0-9a-z][0-9a-z]:){5}[0-9a-z][0-9a-z]")) str=br.readLine();
			while(!(Run_Thread.stop)) {		//stop = false のとき動作する
				boolean flag=str!=null;
				if(flag) {
//					System.out.println(str);
					if(str.matches("([0-9a-z][0-9a-z]:){5}[0-9a-z][0-9a-z] -> ([0-9a-z][0-9a-z]:){5}[0-9a-z][0-9a-z]")){
						Packet p=new Packet();
						p.summary=str;
						while((str=br.readLine()).matches("[0-9a-z]{4} :( [0-9a-z][0-9a-z])* *: .*")){
							String[] s1=str.split(" ",0);
							for(int i=0;i<s1.length-4;i++) {
//								System.out.print(s[i]+" ");
								p.content.add(s1[i+2]);
							}
							System.out.println();
						}
						System.out.println("sum:"+p.summary);
						String s="";
						for(int i=0;i<p.content.size();i++) {
							s+=p.content.get(i);
						}
						for(int i=0;i<s.length()/2;i+=2) {
							System.out.print(s.substring(i,i+2)+" "+i/2);
							if(i%2==0)System.out.println();
						}
						p.analyze();
						Main_window.Data_Initialize(String.valueOf(Main_window.id++), p.win[1], p.win[2], p.win[3], p.win[4], p.win[5], p.win[6]);
						Main_window.Packet_Detail(p.content,p.exp);
						p_count++; //パケット数
					}
					
					//現在時間
					cu_time = System.currentTimeMillis() - start;
					cu_time = (long) Math.round(cu_time / 1000);
					per_count = (int)Math.round(p_count / cu_time);
					System.out.println("----------------------------------");
					System.out.println("経過時間："+cu_time);
					System.out.println("パケット数："+p_count);
					System.out.println("パケット/sec："+per_count);
					
					//if(d_time != cu_time) {
						st.Set(Create.per_count,(int)Create.cu_time);
					//}
					//d_time=(int)cu_time;
				
					System.out.println("----------------------------------");
					
					/*st.cpanel.removeAll();
					st.cpanel.setSize(st.cpanel.getPreferredSize());
					//st.add();
					st.cpanel.validate();
					st.cpanel.repaint();*/
					//mysql
					Con_DB db=new Con_DB();
					Encryption en= new Encryption();
					int len=0;
					String from="";
					String to="";
					String info="";
					db.Open();
				/*	System.out.println(Integer.parseInt(Packet.win[0])
							+Packet.win[1]
							+Packet.win[2]
							+Packet.win[3]
							+Packet.win[4]
							+Integer.parseInt(Packet.win[5])
							+Packet.win[6]);*/
					from=en.encrypto(Packet.win[2]);
					to=en.encrypto(Packet.win[3]);
					len=Integer.parseInt(Packet.win[5]);
					info=en.encrypto(Packet.win[6]);
					System.out.println("暗号化されたパケット");
					System.out.println("No. "+no+"\n"
							+"Time    "+Packet.win[1]+"\n"
							+"From    "+from+"\n"
							+"To      "+to+"\n"
							+"Protocol"+Packet.win[4]+"\n"
							+"Length  "+len+"\n"
							+"Info    "+info);
					db.Sql_In(no,Packet.win[1],from,to,Packet.win[4],len,info);
					db.Fin();
					no++;
					
				}
				else System.out.print("no str");
					
			}
		}
		catch(Exception e) {
			System.out.println(e);
		}
	}
	static Bin getContent(BufferedReader br){
		ArrayList<ArrayList<String>> contents=new ArrayList<ArrayList<String>>();
		ArrayList<String> tran=new ArrayList<String>();
		int a=0;
		Bin b=new Bin();
		try{
			while(true) {
				String content=br.readLine();
				if(content!=null) {
//					System.out.println("split");
					String[] cstr=content.split(" ",0);
					if(cstr[0].trim().startsWith("0x")) {
//						System.out.println("Line:"+cstr[0].trim());
						contents.add(new ArrayList<String>());
						for (int i=2;i<cstr.length-1;i++) {
							if(!cstr[i].trim().equals("")) {
//								System.out.println(cstr[i].trim());
								contents.get(a).add(cstr[i].trim());
							}
						}
						a++;
//						System.out.println("traa "+cstr[cstr.length-1]);
						tran.add(cstr[cstr.length-1]);
//						System.out.println("null check");
					}
					else {
//						System.out.println("else "+cstr[0].trim());
						preStr=content;
//						System.out.println("get pre "+preStr);
						b.contents=contents;
						b.trans=tran;
						break;
					}
				}
				else {
					System.out.println("str null");
					if(br.readLine()==null)
						System.exit(-1);
				}
				
			}
		}
		catch(Exception e) {
			System.out.println(e);
		}
			
		return b;
	}
	public static String bin2hex(byte[] data) {
	    StringBuffer sb = new StringBuffer();
	    for (byte b : data) {
	        String s = Integer.toHexString(0xff & b);
	        if (s.length() == 1) {
	            sb.append("0");
	        }
	        sb.append(s);
	    }
	    return sb.toString();
	}

	public static byte[] hex2bin(String hex) {
	    byte[] bytes = new byte[hex.length() / 2];
	    for (int index = 0; index < bytes.length; index++) {
	        bytes[index] = (byte) Integer.parseInt(hex.substring(index * 2, (index + 1) * 2), 16);
	    }
	    return bytes;
	}
	public static int bin2int(byte[] data) {
		int sum=0;
	    for (byte b : data) {
	        sum += (int)(0xff & b);
	        
	    }
	    return sum;
	}
	public static int hex2int(String hex) {
		return bin2int(hex2bin(hex));
	}
}
