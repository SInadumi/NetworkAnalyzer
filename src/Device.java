
import java.awt.Component;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.Window;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.SwingUtilities;

public class Device extends JFrame implements ActionListener {
	//device用radiobutton
	static JRadioButton[] radio = new JRadioButton[10]; //radio checkbox
	static JButton cap_btn; //capture button
	static String t_dev; //true device
	String[] device = new String[10]; //temporary device list
	int dev_c = 0;	//count device
	
	public void P_dev() {
		Device dev_frame = new Device();
		dev_frame.setBounds(10, 10, 400, 500);
		dev_frame.setTitle("デバイス選択");
		dev_frame.setVisible(true);
		dev_frame.setResizable(false);
		dev_frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	}

	public void actionPerformed(ActionEvent e) {
		//String ob= (String) e.getSource();
		Component c = (Component)e.getSource();
		Window w = SwingUtilities.getWindowAncestor(c);
		String name = "";
		for (int i = 0; i < dev_c; i++) {
			if (radio[i].isSelected()) {
				name = radio[i].getText();
			}
		}
		System.out.println(name);
		Func.device = name;
		w.dispose();

	}

	public String find() throws Exception {
		/*
		 * deviceの取得
		 */
		BufferedReader de = Func.FindDevice();
		if (de == null){
			System.out.printf("deviceが見つかりませんプログラムを終了します");
			System.exit(0);
		}
		String device_str = "";
		while ((device_str = de.readLine()) != null) {
			device[dev_c] = device_str;
			dev_c++;
			if (dev_c > 9) {
				System.out.println("デバイス取得上限に到達");
				break;
			}
		}
		return t_dev;
	}

	Device() {
		try {
		find();
		}catch(Exception e) {
			e.printStackTrace();
		}
		
		for (int i = 0; i < dev_c; i++) {
			radio[i] = new JRadioButton(device[i]);
			radio[i].setFont(new Font("Arial",Font.BOLD,24));
			radio[i].setHorizontalAlignment(JRadioButton.CENTER);
		}

		radio[0].setSelected(true);
		ButtonGroup group = new ButtonGroup();
		for (int i = 0; i < dev_c; i++) {
			group.add(radio[i]);
		}

		JPanel p = new JPanel();
		p.setLayout(new GridLayout(dev_c + 1, 1));
		for (int i = 0; i < dev_c; i++) {
			p.add(radio[i]);
		}

		cap_btn = new JButton("capture start");
		cap_btn.setFont(new Font("Arial",Font.BOLD,24));
		p.add(cap_btn);

		Action de = new Action();
		cap_btn.addActionListener(de);
		cap_btn.addActionListener(this);
		
		getContentPane().add(p);
	}
}
