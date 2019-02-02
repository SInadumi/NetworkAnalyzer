
import java.awt.Color;
import java.awt.Font;
import java.awt.GridLayout;

import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.LineBorder;

public class PacketFlow extends JFrame {
	Action flow = new Action();
	Action stat = new Action();
	//static String exp;
	//static String content;
	JPanel p = new JPanel();

	PacketFlow(String exp,String content) {
		setBounds(10, 10, 500, 500);
		setTitle("パケットの詳細");
		setVisible(true);
		setResizable(false);
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);//閉じるボタン無効化

		p.setLayout(new GridLayout(2, 1)); //上下に分割
		//p.setPreferredSize(new Dimension(500,500));
		LineBorder border = new LineBorder(Color.BLACK, 1, true);

		JLabel P_exp = new JLabel(exp);
		//JTextArea P_exp = new JTextArea();
		//P_exp.setPreferredSize(new Dimension(400, 250));
		P_exp.setBorder(border);
		P_exp.setFont(new Font("Arial",Font.BOLD,13));
		JScrollPane p1 = new JScrollPane(P_exp);
		//p1.setPreferredSize(new Dimension(500, 250));
		
		//JLabel P_content = new JLabel(content);
		JTextArea P_content = new JTextArea(content);
		//P_content.setPreferredSize(new Dimension(400, 250));
		P_content.setBorder(border);
		P_content.setEditable(false);
		P_content.setFont(new Font("Arial",Font.BOLD,13));
		JScrollPane p2 = new JScrollPane(P_content);
		//p2.setPreferredSize(new Dimension(500, 250));
		p.add(p1);
		p.add(p2);
		getContentPane().add(p);
	}
}