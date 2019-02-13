package sniffer;

import java.awt.Dimension;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;


public class Principal extends JFrame implements ActionListener{
    Dimension dimension;
    int dim;
    
    public JTextArea salida;
    JScrollPane scroll;
    JTabbedPane tabbedPane;
    JLabel l1;
    JButton bSaver, bRegresar;
    JFileChooser fc;
    File file;
    
    
    Captura cap;
    

    public Principal(Captura cap){
        this.cap = cap;
        
        dimension = Toolkit.getDefaultToolkit().getScreenSize();
        dim = Toolkit.getDefaultToolkit().getScreenResolution();
        
        setTitle("Analizador de Tramas");
        setResizable(false);
        setSize(600, 600);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setIconImage(Toolkit.getDefaultToolkit().getImage(getClass().getResource("/Imagenes/icono.png")));
        
        
        salida = new JTextArea("");
        salida.setWrapStyleWord(true);
        salida.setLineWrap(true);
        salida.setEditable(false);
        salida.setBounds(0,0,550,300);
        salida.setOpaque(true);
        scroll = new JScrollPane (salida);
        
        tabbedPane = new JTabbedPane();
        tabbedPane.setBounds(20,20,550,400);
        tabbedPane.setOpaque(true);
        tabbedPane.addTab("Resultados", scroll);
        add(tabbedPane);
        
        bSaver = new JButton("Guardar resultados");
        bSaver.setBounds(100,450,150,40);
        bSaver.addActionListener(this);
        add(bSaver);
        fc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        fc.setSelectedFile(new File("res.pcap"));
        fc.setFileFilter(new FileNameExtensionFilter(null, "pcap"));
        
        bRegresar = new JButton("Regresar");
        bRegresar.setBounds(300,450,150,40);
        bRegresar.addActionListener(this);
        add(bRegresar);
        
        l1 = new JLabel();
        l1.setLocation(0, 0);
        l1.setIcon (new ImageIcon(getClass().getResource("/Imagenes/fondo.jpg")));
        
        add (l1);
        
        setVisible(true);
    }

    

    @Override
    public void actionPerformed(ActionEvent e){
        if(e.getSource().equals(bSaver)){
            if (fc.showSaveDialog(null) == JFileChooser.APPROVE_OPTION)
                cap.dump(fc.getSelectedFile().getPath());
        }
        else if(e.getSource().equals(bRegresar)){
            cap.t.interrupt();
            Inicio in = new Inicio();
            this.dispose();
        }
    }
}
