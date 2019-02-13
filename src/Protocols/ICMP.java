package Protocols;
import org.jnetpcap.protocol.network.Icmp;

public class ICMP {
    private static final int type = 0, code = 1, checksum = 2;
    private String[] Header = new String[16];
    public String typeAndCode;
    public String checksumString;

    private Icmp ICMP;

    public ICMP(Icmp ICMP) throws Exception {
        this.ICMP= ICMP;
        createHeader();
    }
    private void createHeader() throws Exception {
        //Type
        Header[type] = String.valueOf(ICMP.type());
        //Code
        Header[code]=String.valueOf(ICMP.code());
        //Checksum
        int cs=ICMP.checksum();
        Header[checksum] = String.valueOf(Integer.toHexString(cs));  
        checksumString = Header[checksum];
        //Impresiones
        if(Header[type].equals("0") && Header[code].equals("0"))
        {
                typeAndCode = "Echo reply";
        }
        else if (Header[type].equals("3"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0:
                    typeAndCode = "Network unreachable";
                    break;
                case 1:
                    typeAndCode = "Host unreachable";
                    break;
                case 2:
                    typeAndCode = ("Protocol unreachable");
                    break;
                case 3:
                    typeAndCode = ("Port unreachable");
                    break;
                case 4:
                    typeAndCode = ("Fragmentation required, but do not fragment bit set");
                    break;
                case 5:
                    typeAndCode = ("Source route failed");
                    break;
                case 6:
                    typeAndCode = ("Destination network unknown");
                    break;
                case 7:
                    typeAndCode = ("Destination host unknown");
                    break;
                case 8:
                    typeAndCode = ("Source host isolated error (military use only)");
                    break;
                case 9:
                    typeAndCode = ("The destionation network is administratively prohibited");
                    break;
                case 10:
                    typeAndCode = ("The destination host is administartively prohibited");
                    break;
                case 11:
                    typeAndCode = ("The network is unreachable for Type Of Service");
                    break;
                case 12:
                    typeAndCode = ("The host is unreachable for Type Of Service");
                    break;
                case 13:
                    typeAndCode = ("Communication administratively prohibited (administrative filtering prevents packet from being forwarded)");
                    break;
                case 14:
                    typeAndCode = ("Host precedence violation (indicates the requested precedence is not permitted for the combination of host or network and port)");
                    break;
                case 15:
                    typeAndCode = ("Precedence cutoff in effect (precedence of datagram is below the level set by the network administrators)");
                    break;
                    
            }//Fin de switch
        }
        else if (Header[type].equals("4") && Header[code].equals("0"))
        {
            typeAndCode = ("Source Quench");
        }
        else if (Header[type].equals("5"))
        {
            typeAndCode = ("Redirect.");
            switch (Integer.parseInt(Header[code]))
            {
                case 0:
                    typeAndCode = ("Network redirect");
                    break;
                case 1:
                    typeAndCode = ("Host redirect");
                    break;
                case 2:
                    typeAndCode = ("Network redirect for this Type Of Service");
                    break;
                case 3:
                    typeAndCode = ("Host redirect for this Type Of Service");
                    break;
            }
        }
        else if(Header[type].equals("8") && Header[code].equals("0"))
        {
            typeAndCode = ("Echo Request");
        }
        else if(Header[type].equals("11"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0: 
                    typeAndCode = ("transit TTL exceeded");
                    break;
                case 1:
                    typeAndCode = ("reasembly TTL exceeded");
            }
        }
        else if(Header[type].equals("12"))
        {
            switch(Integer.parseInt(Header[code]))
            {
                case 0: 
                    typeAndCode = ("Pointer problem");
                    break;
                case 1:
                    typeAndCode = ("Missing a required operand");
                    break;
                case 2:
                    typeAndCode = ("Bad length");
                    break;
            }
        }
        else if (Header[type].equals("13") && Header[code].equals("0"))
        {
            typeAndCode = ("Timestamp Request");
        }
        else if (Header[type].equals("14") && Header[code].equals("0"))
        {
            typeAndCode = ("Timestamp Reply");
        }
        
    }

}