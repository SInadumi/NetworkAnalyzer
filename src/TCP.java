public class TCP {
	String sport,dport,snum,anum,ack,wsize,csum,upoint;
	String makeString() {
		return "\n\nTransmission Control Protocol"
				+ "\nSource port:"+sport
					+"\nDestination port:"+dport
						+"\nSequence number:"+snum
							+"\nAcknowledgment number:"+anum
							 	+"\nACK:0x"+ack
							 		+"\nWindow size value:"+wsize
							 			+"\nCheck sum:0x"+csum
							 				+"\nUrgent pointer:"+upoint;
	}
}
