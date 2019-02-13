package sniffer;

import Protocols.*;
import java.io.File;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.swing.JOptionPane;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapBpfProgram;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.PcapPacketHandler;

import org.jnetpcap.protocol.network.Arp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;




public class Captura implements Runnable{
    Principal principal;
    
    Pcap pcap;
    PcapPacketHandler<String> jpacketHandler;
    String[] sType, uType = new String[32];
    StringBuilder errbuf;
    int numPackets, timeout;
    public List<PacketPair> packets;
    public Thread t;
    int counterIP, counterARP, counterICMP, counterIEEE;
    
    public Captura(File file, String filtro){
        this();
        numPackets = -1;
        timeout = -1;
        
        pcap = Pcap.openOffline(file.getPath(), errbuf);
        if (pcap == null) {
            JOptionPane.showMessageDialog(
                null,
                "Error al abrir el archivo " + file.getPath() + ": " + errbuf.toString(),
                "Error",
                JOptionPane.ERROR_MESSAGE
            );
            System.err.printf("Error al abrir el archivo " + file.getPath() + ": " + errbuf.toString());
            principal.dispose();
            Inicio in = new Inicio();
        }
        else{
            crearFiltro(filtro);
            t = new Thread(this);
            t.start();
        }
    }
    
    public Captura(PcapIf device, int snaplen, int flags, int timeout, int numPackets, String filtro){
        this();
        this.numPackets = numPackets;
        this.timeout = timeout;
        
        pcap = Pcap.openLive(device.getName(), snaplen, flags, 10000, errbuf);
        if (pcap == null) {
            JOptionPane.showMessageDialog(
                null,
                "Error al abrir el dispositivo " + device.getName()+ ": " + errbuf.toString(),
                "Error",
                JOptionPane.ERROR_MESSAGE
            );
            System.err.printf("Error al abrir el dispositivo " + device.getName() + ": " + errbuf.toString());
            principal.dispose();
            Inicio in = new Inicio();
        }
        else{
            crearFiltro(filtro);
            t = new Thread(this);
            t.start();
        }
    }
    
    private Captura(){
        principal = new Principal(this);
        
        counterIP = 0;
        counterARP = 0;
        counterICMP = 0;
        counterIEEE = 0;
        
        this.packets = new ArrayList<>();
        errbuf = new StringBuilder();
        
        sType = new String[]{
            "Receive Ready (RR)",
            "Receive Not Ready (RNR)",
            "Reject (REJ)",
            "Selective Reject (SREJ)"
        };
        uType = new String[]{
            "Unnumbered Information (UI)",
            "Set Initialization Mode (SIM)",
            "Nonreserved 0 (NR0)",
            "Set Asynchronous Response (SARM)",
            "Unnumbered Poll (UP)",
            "Request Initialization Mode (RIM)",
            "Disconnect Mode (DM)",
            "Set Asynchronous Balanced Mode(SABM)",
            "Disconnect (DISC)",
            "Request Disconnect (RD)",
            "Nonreserved 2 (NR2)",
            "Set Asynchronous Response Extended Mode (SARME)",
            "Unnumbered Aknowledgement (UA)",
            "Invalido",
            "Invalido",
            "Set Asynchronous Balanced Extended Mode (SABME)",
            "Set Normal Response (SNRM)",
            "Frame Reject (FRMR)",
            "Nonreserved 1 (NR1)",
            "Reset (RSET)",
            "Invalido",
            "Invalido",
            "Invalido",
            "Exchange Identification (XID)",
            "Invalido",
            "Configure For Test (CFGR)",
            "Nonreserved 3 (NR3)",
            "Set Normal Response Extended Mode (SNRME)",
            "Test (TEST)",
            "Invalido",
            "Invalido",
            "Beacon (BCN)"
        };
        
        jpacketHandler = (PcapPacket packet, String user) -> {
            packets.add(new PacketPair(packet, user));
            analizar(packet, user);
        };
    }
    
    private void crearFiltro(String filtro){
        PcapBpfProgram filter = new PcapBpfProgram();
        int optimize = 0;
        int netmask = 0;
        int r2 = pcap.compile(filter, filtro, optimize, netmask);
        if (r2 != Pcap.OK) {
            JOptionPane.showMessageDialog(
                null,
                "Error en el filtro: " + pcap.getErr(),
                "Error",
                JOptionPane.ERROR_MESSAGE
            );
            System.err.printf("Error en el filtro: " + pcap.getErr());
            principal.dispose();
            Inicio in = new Inicio();
        }
        pcap.setFilter(filter);
    }
    
    private void analizar(PcapPacket packet, String user){
        System.out.println("OK");
        principal.salida.append("\n");
        for(int i = 0; i < 100; i++)
            principal.salida.append("*");
        principal.salida.append(
            String.format(
                "\n\nPaquete recibido el %s caplen=%-4d longitud=%-4d %s\n\n",
                new Date(packet.getCaptureHeader().timestampInMillis()),
                packet.getCaptureHeader().caplen(),
                packet.getCaptureHeader().wirelen(),
                user
            )
        );

        for(int i = 0; i < packet.size(); i++){
            principal.salida.append(String.format("%02X ", packet.getUByte(i)));
            if(i % 16 == 15)
                principal.salida.append("\n");
        }
        
        selectProtocol(packet);
    }
    
    private void selectProtocol(PcapPacket packet) {        
        int type = packet.getUByte(12) * 256 + packet.getUByte(13);
        principal.salida.append(String.format("\n\tLongitud: %d (0x%04X)", type, type));
        
        
        if (type > 1500) {
            switch (type) {
                //IPv4
                case 2048:
                    analizarIp4(packet);
                    break;
                //ARP
                case 2054:
                    analizarArp(packet);
                    break;
            }

        }
        else
            analizarIeee(packet);
    }
    
    private void analizarIp4(PcapPacket packet){
        Ip4 ip4 = packet.getHeader(new Ip4());
        if (packet.hasHeader(ip4)) {
            counterIP++;
            try{
                IP ip = new IP(ip4);
                
                principal.salida.append("\n\tTRAMA IPV4");
                principal.salida.append("\n\t\tVersion IPv" + ip4.version());
                principal.salida.append("\n\t\tChecksum: " + ip.getChecksum());
                principal.salida.append("\n\t\tChecksum valido: " + ip.getIsValidChecksum());
                principal.salida.append("\n\t\tVersion: " + ip.getVersion());
                principal.salida.append("\n\t\tTOS: " + ip.getTOS());
                principal.salida.append("\n\t\tLength: " + ip.getlength());
                principal.salida.append("\n\t\tID: " + ip.getID());
                principal.salida.append("\n\t\tOffset: " + ip.getOffset());
                principal.salida.append("\n\t\tTTL: " + ip.getTTL());
                principal.salida.append("\n\t\tIP Origen: " + ip.getIP_O());
                principal.salida.append("\n\t\tIP Destino: " + ip.getIP_D());
                principal.salida.append("\n");
                
                int protocolo = ip4.type();
                switch (protocolo){
                    case (int) 1: //icmp
                        analizarICMP (packet);
                        break;
                    case (int) 2: //igmp
                        analizarIGMP (packet);
                        break;
                    case (int) 17: //udp
                        analizarUDP(packet);
                        break;
                    case (int) 6: //tcp
                        analizarTCP(packet);
                        break;
                }
            }
            catch(Exception ex){
                System.out.println("Error al iniciar la clase IP:\n" + ex.toString());
            }
        }
        else 
            principal.salida.append("\n\tEl paquete no contiene un encabezado IP\n");
    }
    
    private void analizarICMP (PcapPacket packet){
        principal.salida.append("\n\tProtocolo: ICMP");
        Icmp i = packet.getHeader(new Icmp());
        try{
            ICMP icmp = new ICMP (i);
            principal.salida.append("\n\t\tTipo: " + icmp.typeAndCode);
            principal.salida.append("\n\t\tChecksum: " + icmp.checksumString);
        }
        catch (Exception e){
            return;
        }
    }
    
    private void analizarIGMP (PcapPacket packet){
        principal.salida.append("\n\t\tProtocolo: IGMP");
        
    }
    
    private void analizarTCP (PcapPacket packet){
        principal.salida.append("\n\tProtocolo: TCP");
        Tcp tcp = packet.getHeader(new Tcp());
        principal.salida.append("\n\t\tFuente: " + tcp.source());
        principal.salida.append("\n\t\tDestino: " + tcp.destination());
        principal.salida.append("\n\t\tSecuencia: " + tcp.seq());
        principal.salida.append("\n\t\tACK: " + tcp.ack());
        principal.salida.append("\n\t\tBanderas: " + tcp.flagsCompactString());
        principal.salida.append("\n\t\tVentana: " + tcp.window());
        principal.salida.append("\n\t\tChecksum: " + tcp.checksum());
        principal.salida.append("\n\t\tUrgent pointer: " + tcp.urgent());
    }
    
    private void analizarUDP (PcapPacket packet){
        principal.salida.append("\n\t\tProtocolo: UDP");
        Udp u = packet.getHeader(new Udp());
        principal.salida.append("\n\t\tFuente: " + u.source());
        principal.salida.append("\n\t\tDestino: " + u.destination());
        principal.salida.append("\n\t\tChecksum: " + u.length());
        principal.salida.append("\n\t\tChecksum: " + u.checksum());
    }
    
    private void analizarArp(PcapPacket packet){
        Arp arp = packet.getHeader(new Arp());
        if (packet.hasHeader(arp)) {
            counterARP++;
            try{
                //ARP arpI = new ARP(arp);
                
                principal.salida.append("\n\tTRAMA ARP");
                principal.salida.append("\n\t\tTipo de hardware: " + arp.hardwareTypeDescription());
                principal.salida.append("\n\t\tTipo de protocolo: " + arp.protocolTypeDescription());
                principal.salida.append("\n\t\tLongitud de direccion de hardware: " + arp.hlen());
                principal.salida.append("\n\t\tLongitud de direccion de protocolo: " + arp.plen());
                principal.salida.append("\n\t\tCodigo de operacion: " + arp.operation());
                principal.salida.append("\n\t\tOperacion: " + arp.operationDescription());
                principal.salida.append("\n\t\tDireccion del hardware remitente: " + arp.sha());
                principal.salida.append("\n\t\tDireccion del protocolo remitente: " + arp.spa());
                principal.salida.append("\n\t\tDireccion del hardware destinatario: " + arp.tha());
                principal.salida.append("\n\t\tDireccion del protocolo destinatario: " + arp.tpa());
                principal.salida.append("\n");
            }
            catch(Exception ex){
                System.out.println("Error al iniciar la clase ARP:\n" + ex.toString());
            }
        }
        else 
            principal.salida.append("\n\tEl paquete no contiene un encabezado ARP\n");
    }
    
    private void analizarIeee(PcapPacket packet){
        counterIEEE++;
        try{
            IEEE ieee = new IEEE(packet);

            principal.salida.append("\n\tTRAMA IEEE");
            principal.salida.append("\n\t\tMAC Origen: " + ieee.getMac_O());
            principal.salida.append("\n\t\tMAC Destino: " + ieee.getMac_D());
            principal.salida.append("\n\t\tLongitud: " + ieee.getLength());
            principal.salida.append("\n\t\tDSAP: " + ieee.getDSAP());
            principal.salida.append("\n\t\tSSAP: " + ieee.getSSAP());
            principal.salida.append("\n\t\tControl: " + ieee.getControl());
            principal.salida.append("\n\t\tTipo: " + ieee.getTipo());
            principal.salida.append("\n\t\tOrden: " + ieee.getOrden());
            principal.salida.append("\n\t\tRespuesta: " + ieee.getRespuesta());
            principal.salida.append("\n\t\tnR: " + ieee.get_nR() + " - " + ieee.get_nR_dec());
            principal.salida.append("\n\t\tnS: " + ieee.get_nS() + " - " + ieee.get_nS_dec());
            principal.salida.append("\n");
        }
        catch(Exception ex){
            System.out.println("Error al iniciar la clase IEEE:\n" + ex.toString());
        }
    }
    
    
    
    public void dump(String dumpFile){
        Pcap defaultPcap = Pcap.openOffline(".\\src\\sniffer\\default.pcap", errbuf);
        PcapDumper dumper = defaultPcap.dumpOpen(dumpFile);
        packets.stream().forEach((packetPair) -> {
            dumper.dump(packetPair.packet.getCaptureHeader(), packetPair.packet);
        });
        dumper.close();
        defaultPcap.close();
    }
    
    @Override
    public void run(){
        if(timeout != -1){
            timeout *= 1000;
            long startTime = System.currentTimeMillis();
            while(System.currentTimeMillis() - startTime < timeout)
                pcap.loop(1, jpacketHandler, " ");
        }
        else
            pcap.loop(numPackets, jpacketHandler, " ");
        
        
        
        pcap.close();
    }
}
