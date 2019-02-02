import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.Arrays;

import javax.swing.JFrame;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.axis.TickUnit;
import org.jfree.chart.axis.TickUnits;
import org.jfree.chart.axis.ValueAxis;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.StandardXYItemRenderer;
import org.jfree.chart.renderer.xy.XYItemRenderer;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.RectangleInsets;

public class Statistics extends JFrame {
	JFreeChart IOChart;
	//Graphics g = getGraphics();
	ChartPanel cpanel;
	XYDataset dataset;
	XYItemRenderer renderer = new StandardXYItemRenderer();
	XYPlot xyPlot;
	ValueAxis xAxis = new NumberAxis();
	ValueAxis yAxis = new NumberAxis();

	public static final int IOHeight = 650;
	public static final int IOWidth = 700;

	Statistics() {
		//IOGraph
		xAxis = new NumberAxis("時間[s]");
		yAxis = new NumberAxis("Packet数[個/s]");
		//JPanel ckpanel;

	}

	public void run() throws Exception { //IOGraph run
		Statistics stat = new Statistics();
		dataset = createDataset();
		//xyPlot = new XYPlot(dataset, xAxis, yAxis, renderer);
		//IOChart = new JFreeChart("IO/Graph",(Plot)xyPlot);
		IOChart = ChartFactory.createXYLineChart(
				"I/O Graph",
				"時間[s]",
				"Packet数[個/s]",
				dataset,
				PlotOrientation.VERTICAL,
				true,
				false,
				false);
		
		XYPlot plot = (XYPlot) IOChart.getPlot();
		//plot.setDomainGridlinePaint(DataBase.cl_Line);
		plot.setDomainGridlinesVisible(true);

		//横軸の目盛り間隔の設定
		ValueAxis xAxis = plot.getDomainAxis();
		xAxis.setAutoRange(true);
		TickUnits tickUnits = new TickUnits();
		TickUnit unit = new NumberTickUnit(10);
		tickUnits.add(unit);
		xAxis.setStandardTickUnits(tickUnits);
		//xAxis.setTickLabelsVisible(false); // ﾒﾓﾘ値を隠す
		//xAxis.setRange(0,60);

		NumberAxis rangeAxis = (NumberAxis) plot.getRangeAxis();
		rangeAxis.setStandardTickUnits(NumberAxis.createIntegerTickUnits());
		rangeAxis.setAutoRangeIncludesZero(true);

		plot.setAxisOffset(new RectangleInsets(5, 5, 5, 5));

		/* 縦軸の設定 */
		ValueAxis yAxis = plot.getRangeAxis();
		yAxis.setAutoRange(true);
		//yAxis.setRange(0,20);
		cpanel = new ChartPanel(IOChart);
		cpanel.setPreferredSize(new Dimension(IOWidth, IOHeight));
		stat.setBounds(0, 0, IOWidth, IOHeight);
		stat.setTitle("統計");
		stat.setVisible(true);
		stat.setResizable(false);
		stat.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		stat.add(cpanel, BorderLayout.CENTER);

	}

	static int[] xplot = new int[1000];
	static int[] yplot = new int[1000];
	//static ArrayList<Integer> xplot = new ArrayList<Integer>;
	static int count = 0;
	void DataClear() {
	//https://donsyoku.com/zakki/java-initialization-arrays-fill.html
		/*for(int i=0;i<count;i++) {
			xplot[i]=0;
			yplot[i]=0;
		}*/
		Arrays.fill(xplot, 0);
		Arrays.fill(yplot, 0);
		count=0;
	}
	void Set(int x, int y) {
		xplot[count] = x;
		yplot[count] = y;
		System.out.println("--------Statistics Add Data-----------");
		System.out.println(xplot[count]);
		System.out.println(yplot[count]);
		System.out.println(count);
		System.out.println("----------------------------------------");
		count++;
		if(count==1000) {
			System.out.println("deleteing data ");
			xplot[count-1000]=0;
			yplot[count-1000]=0;
			count=0;
		}
	}

	private static XYDataset createDataset() {
		XYSeries xySeries = new XYSeries("all");

		/*for (int i = 0; i < 10; i++) {
			xySeries.add(i, i + Math.random() * 4.0D);
		}*/
		//System.out.println("パケット:"+yplot+"じかん："+xplot);
		for (int i = 0; i < count; i++) {
			xySeries.add(yplot[i], xplot[i]);
		}
		//count = 0;
		XYSeriesCollection dataset = new XYSeriesCollection(xySeries);
		return dataset;
	}

}