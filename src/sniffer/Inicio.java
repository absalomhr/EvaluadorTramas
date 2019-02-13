package sniffer;

import java.awt.Color;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ButtonGroup;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JRadioButton;
import javax.swing.JTextArea;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.filechooser.FileSystemView;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;

public class Inicio extends JFrame implements ActionListener{

    JLabel l1, l2, l3;
    JTextArea descripcion, filtro;
    JRadioButton rb1, rb2;
    ButtonGroup bg;
    JComboBox cb;
    JFileChooser fc;
    JButton bChooser, bSubmit;
    File file;
    List<PcapIf> alldevs;
    StringBuilder errbuf;
    
    public Inicio(){
       
        
        setTitle("Analizador de Tramas");
        setResizable(false);
        setSize(400, 500);
        setLocationRelativeTo(null);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setIconImage(Toolkit.getDefaultToolkit().getImage(getClass().getResource("/Imagenes/icono.png")));
        
        
        getDevices();
        
        
        
        l1 = new JLabel("Selecciona una opción");
        l1.setFont(new java.awt.Font("Tahoma", 1, 15)); // NOI18N
        l1.setForeground(Color.WHITE);
        l1.setBounds(50,0,200,40);
        add(l1);
        
        rb1 = new JRadioButton("Dispositivo");
        rb1.setBounds(50,50,150,40);
        rb1.addActionListener(this);
        rb1.setOpaque(false);
        rb1.setForeground(Color.white);
        add(rb1);
        rb2 = new JRadioButton("Archivo");
        rb2.setOpaque(false);
        rb2.setForeground(Color.white);
        rb2.setBounds(200,50,150,40);
        rb2.addActionListener(this);
        add(rb2);
        bg = new ButtonGroup();
        bg.add(rb1);
        bg.add(rb2);
        
        cb = new JComboBox();
        cb.setBounds(50,100,290,40);
        cb.setSelectedIndex(-1);
        if(alldevs.isEmpty())
            rb1.setEnabled(false);
        else{
            for(PcapIf device : alldevs){
                String descrip = device.getDescription() + ": " + device.getName();
                cb.addItem(descrip);
                System.out.println(descrip);
            }
        }
        cb.setEnabled(true);
        cb.setVisible(false);
        cb.addItemListener((ItemEvent e) -> {
            if(e.getStateChange() == ItemEvent.SELECTED){
                if(cb.getSelectedIndex() < 0)
                    descripcion.setText("Selecciona un dispositivo...");
                else
                    descripcion.setText("Detalles:\n\n" + getDeviceInfo(cb.getSelectedIndex()));
            }
        });
        add(cb);
        
        bChooser = new JButton("Seleccionar archivo");
        bChooser.setBounds(125,100,150,40);
        bChooser.addActionListener(this);
        bChooser.setEnabled(true);
        bChooser.setVisible(false);
        add(bChooser);
        fc = new JFileChooser(FileSystemView.getFileSystemView().getHomeDirectory());
        fc.setFileFilter(new FileNameExtensionFilter(null, "pcap"));
        file = new File("");
        
        descripcion = new JTextArea();
        descripcion.setText("");
        descripcion.setWrapStyleWord(true);
        descripcion.setForeground(Color.white);
        descripcion.setLineWrap(true);
        descripcion.setOpaque(false);
        descripcion.setEditable(false);
        descripcion.setFocusable(false);
        descripcion.setBounds(50,150,300,150);
        
        add(descripcion);
        
        l2 = new JLabel("Filtro:");
        l2.setFont(new java.awt.Font("Tahoma", 1, 13));
        l2.setForeground(Color.WHITE);
        l2.setBounds(50,320,150,40);
        add(l2);
        
        filtro = new JTextArea();
        filtro.setText("");
        filtro.setWrapStyleWord(true);
        filtro.setLineWrap(true);
        filtro.setBounds(50,350,300,20);
        add(filtro);
        
        bSubmit = new JButton("Iniciar Captura");
        bSubmit.setBounds(50,400,150,40);
        bSubmit.addActionListener(this);
        add(bSubmit);
        
        
        l3 = new JLabel();
        l3.setLocation(0, 0);
        l3.setIcon (new ImageIcon(getClass().getResource("/Imagenes/fondo.jpg")));
        
        add (l3);
        
        setVisible(true);
    }
    
    public void getDevices(){
        alldevs = new ArrayList<>();
        errbuf = new StringBuilder();
        if(Pcap.findAllDevs(alldevs, errbuf) == Pcap.NOT_OK || alldevs.isEmpty()){
            JOptionPane.showMessageDialog(null, "No puede leerse la lista de dispositivos.\nError: " + errbuf.toString());
            return;
        }
        System.out.println("Dispositivos de red encontrados.");
    }
    
    public String getDeviceInfo(int i){
        try{
            PcapIf device = alldevs.get(i);
            final byte[] mac = device.getHardwareAddress();
            String dirMac = mac == null ? "No tiene direccion MAC" : asString(mac);
            String info = device.getName() + " [" +  device.getDescription() + "], MAC: [" + dirMac + "]";
            return info;
        }
        catch(IOException ex){
            ex.printStackTrace();
            return "";
        }
    }
    
    private static String asString(final byte[] mac) {
        final StringBuilder buf = new StringBuilder();
        for (byte b : mac) {
            if (buf.length() != 0)
                buf.append(':');
            if (b >= 0 && b < 16)
                buf.append('0');
            buf.append(Integer.toHexString((b < 0) ? b + 256 : b).toUpperCase());
        }
        return buf.toString();
    }
    
    @Override
    public void actionPerformed(ActionEvent e){
        if(e.getSource().equals(rb1)){
            cb.setSelectedIndex(-1);
            descripcion.setText("Selecciona un dispositivo...");
            cb.setVisible(true);
            bChooser.setVisible(false);
        }
        if(e.getSource().equals(rb2)){
            descripcion.setText(file.exists() ? file.getPath() : "");
            bChooser.setVisible(true);
            cb.setVisible(false);
        }
        if(e.getSource().equals(bChooser)){
                if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                    file = fc.getSelectedFile();
                    if(file.exists())
                        descripcion.setText(file.getPath());
                    else
                        descripcion.setText("");
                }
        }
        if(e.getSource().equals(bSubmit)){
            if(rb1.isSelected()){
                if(cb.getSelectedIndex() >= 0){
                    PcapIf device = alldevs.get(cb.getSelectedIndex());
                    int snaplen = 64 * 1024, flags = Pcap.MODE_PROMISCUOUS, timeout, numPackets;
                    String[] opcionesCap = {"Por tiempo", "Por numero de paquetes"};
                    Object resp = JOptionPane.showInputDialog(
                        null,
                        "Selecciona una forma de captura:",
                        "Captura al vuelo",
                        JOptionPane.INFORMATION_MESSAGE,
                        null,
                        opcionesCap,
                        opcionesCap[0]);
                    if(resp == null)
                        return;
                    if(resp.toString().equals(opcionesCap[0]))
                        while(true){
                            String timeS = JOptionPane.showInputDialog(
                                    null,
                                    "Ingresa el tiempo de captura:",
                                    "Captura por tiempo",
                                    JOptionPane.INFORMATION_MESSAGE
                            );
                            if(timeS == null)
                                return;
                            try{
                                timeout = Integer.parseInt(timeS);
                                if(timeout <= 0)
                                    JOptionPane.showMessageDialog(null, "El dato ingresado debe ser mayor a cero.");
                                else{
                                    numPackets = -1;
                                    break;
                                }
                            }
                            catch(Exception ex){
                                JOptionPane.showMessageDialog(null, "El dato ingresado debe ser un entero positivo.", "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    else 
                        while(true){
                            Object numS = JOptionPane.showInputDialog(
                                    null,
                                    "Ingresa el numero de paquetes que deseas capturar:",
                                    "Captura por numero de paquetes",
                                    JOptionPane.INFORMATION_MESSAGE
                            );
                            if(numS == null)
                                return;
                            try{
                                numPackets = Integer.parseInt(numS.toString());
                                if(numPackets <= 0)
                                    JOptionPane.showMessageDialog(null, "El dato ingresado debe ser mayor a cero.");
                                else{
                                    timeout = -1;
                                    break;
                                }
                            }
                            catch(Exception ex){
                                JOptionPane.showMessageDialog(null, "El dato ingresado debe ser un entero positivo.", "Error", JOptionPane.ERROR_MESSAGE);
                            }
                        }
                    Captura cap = new Captura(device, snaplen, flags, timeout, numPackets, filtro.getText());
                    this.dispose();
                }
            }
            else if(rb2.isSelected()){
                if(!file.getPath().equals("") && file.exists()){
                    Captura cap = new Captura(file, filtro.getText());
                    this.dispose();
                }
            }
        }
    }
}
