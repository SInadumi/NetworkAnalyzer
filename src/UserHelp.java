import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;


public class UserHelp extends JFrame implements ActionListener{

	JLabel label1;
	JLabel label2;
	
	UserHelp(){
		JPanel p=new JPanel();
		p.setLayout(null);

		JButton button1 = new JButton("    概要    ");
	    button1.setBounds(0,0,220,40);
	    button1.addActionListener(this);
	    
	    JButton button2 = new JButton("よくある質問");
	    button2.setBounds(220,0,220,40);
	    button2.addActionListener(this);
	    
	    label1 = new JLabel("");
	    label1.setBounds(0,40,440,40);
	    label1.setHorizontalAlignment(JLabel.CENTER);
	    label1.setVerticalAlignment(JLabel.TOP);
	    label1.setFont(new Font("Serif", Font.PLAIN, 20));
	    
	    label2 = new JLabel("");
	    label2.setHorizontalAlignment(JLabel.LEFT);
	    label2.setVerticalAlignment(JLabel.TOP);
	    label2.setFont(new Font("Serif", Font.PLAIN, 12));
	    

		JScrollPane scrollpane = new JScrollPane(label2);
		scrollpane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
	    scrollpane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
	    scrollpane.setBounds(0,80,440,320);
		
		p.add(button1);
		p.add(button2);
		p.add(scrollpane);
		p.add(label1);
		//p.add(label2);
		getContentPane().add(p,BorderLayout.CENTER);
	
	}

	public void Paint_UserHelp(){
		UserHelp frame = new UserHelp();

		frame.setBounds(10, 10, 440, 400);
		frame.setTitle("概要");
		frame.setVisible(true);
		frame.setResizable(false);


		frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);

	}
	public void actionPerformed(ActionEvent e){

		 if(e.getActionCommand().equals("    概要    ")) {
			 label1.setText("このソフトの概要");
			 label2.setText("<html><body>ソフトのせつめい"
					+ "<br />ソフト名"
					+ "<br /> Wire Whale"
					+ "<br />製作者"
			 		+ "<br /> 稲積 小野 江藤 栗山 佐藤 本田"
			 		+ "<br />まぁそのあたりです</body></html>");
		 }
		 else if(e.getActionCommand().equals("よくある質問")) {
			 label1.setText("よくある質問");
			 label2.setText("<html><body>Q.このプログラムは動きますか？"
			 		+ "<br />A.時と場合によりけり。"
			 		+ "<br />Q.フィルタの使い方を教えて！"
			 		+ "<br />A.見たいプロトコルにチェックを入れてください。"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />A."
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />A."
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "<br />q"
			 		+ "<br />a"
			 		+ "</body></html>");
		 }
	}
}
