
import java.awt.GridLayout;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;



public class Filter extends JFrame{
	public static JCheckBox[] ckbox;
	public static int[] plb;
	public static JTextField inputADR1;
	
	int [] Protocol= new int[7] ;
	Action fil =new Action();
	void P_fil() {
		Filter frame_p = new Filter();
		
		frame_p.setBounds(10, 10, 750, 300);
		frame_p.setTitle("フィルタ指定");
		frame_p.setVisible(true);
		frame_p.setResizable(false);	
		frame_p.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);//閉じるボタン無効化
		
	}
	Filter(){
		getContentPane().setLayout(new GridLayout(1,2));
		
		inputADR1 = new JTextField(20);

		JPanel pl = new JPanel();
		pl.setLayout(new GridLayout(3, 3));
		
		JPanel pr = new JPanel();
		pr.setLayout(new GridLayout(2, 1));
		JPanel pr1 = new JPanel();
		JPanel pr2 = new JPanel();
		
		ckbox = new JCheckBox[15];
		ckbox[0] =new JCheckBox("TCP",true);
		ckbox[1] =new JCheckBox("ARP",true);
		ckbox[2] =new JCheckBox("IPv6",true);
		ckbox[3] =new JCheckBox("UDP",true);
		ckbox[4] =new JCheckBox("ICMP",true);
		ckbox[5] =new JCheckBox("8899",true);
		ckbox[6] =new JCheckBox("EAP",true);
		
		pl.add(ckbox[0]);
		pl.add(ckbox[1]);
		pl.add(ckbox[2]);
		pl.add(ckbox[3]);
		pl.add(ckbox[4]);
		pl.add(ckbox[5]);
		pl.add(ckbox[6]);
		/*pl.add(ckbox[7]);
		pl.add(ckbox[8]);
		pl.add(ckbox[9]);
		pl.add(ckbox[10]);
		pl.add(ckbox[11]);
		pl.add(ckbox[12]);
		pl.add(ckbox[13]);
		pl.add(ckbox[14]);*/
		
		JLabel label1=new JLabel("アドレス入力欄");
		JButton button = new JButton("適用");
		JButton button2 = new JButton("一括取消");
		JButton button3 = new JButton("全選択");
		button.addActionListener(fil);
		button3.addActionListener(fil);
		button2.addActionListener(fil);
		
		pr1.add(label1);
		pr1.add(inputADR1);
		pr2.add(button2);
		pr2.add(button3);
		pr2.add(button);
		pr.add(pr1);
		pr.add(pr2);
		
		getContentPane().add(pl);
		getContentPane().add(pr);
	}

/*	void decision() {
		for(int i=0;i<ckbox.length;i++){java.awt.Component
			if(plb[i]==1) {
				Main_window.p=ckbox[i].getText();
			}
			else{

			}
		}
		
	}*/
	
	//public void changeckbox (){
		//for(int i=0;i<15;i++) {
		//		ckbox[i].setState(boolean false);
		//	}
	//}
}