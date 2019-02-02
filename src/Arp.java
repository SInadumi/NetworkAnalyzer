public class Arp {
	String len;
	String htype;
	String ptype;
	String hsize;
	String psize;
	String opcode;
	String smac;
	String dmac;
	String sip;
	String dip;
	String makeString() {
		String s="";
		s+="\n\nAdress resolution protocol\n"
				+ "Lnegth:"+len
					+ "Hardware type:"+htype+"\n"
							+ "Protocol type:"+ptype+"\n"
									+ "Hardware size:"+hsize+"\n"
											+ "Protocol size:"+psize+"\n"
													+ "Opcode:"+opcode+"\n"
															+ "Sender Mac Adress:"+smac+"\n"
																	+ "Target Mac Adress:"+dmac+"\n"
																		+ "Sender IP Adress:"+sip+"\n"
																			+ "Target IP Adress:"+dip+"\n";
		return s;
		}
}
