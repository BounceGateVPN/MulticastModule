package com.github.Mealf.BounceGateVPN.Multicast.TEST;

import com.github.Mealf.BounceGateVPN.Multicast.IGMPAnalysis;
import com.github.smallru8.driver.tuntap.TapDevice;
import java.util.Scanner;

public class TEST2 {
	public static TapDevice td;
	public static void main(String[] args) {
		
		td = new TapDevice();
		td.tap.tuntap_up();
    	//td.startEthernetDev();
    	td.tap.tuntap_set_ip("192.168.87.2", 24);
    	IGMPAnalysis analysis = new IGMPAnalysis();
    	Scanner scanner = new Scanner(System.in);
    	scanner.hasNext();
    	byte[] packet = analysis.generateQuery(0,null,-536870911, 2);
    	td.write(packet);
    	StringBuilder sb = new StringBuilder();
	    sb.append("[ ");
	    for (byte b : packet) {
	        sb.append(String.format("%02X ", b));
	    }
	    sb.append("]");
	    System.out.println(sb);
	    
	    packet = analysis.generateQuery("0.0.0.0",null,"224.0.0.1", 2);
    	td.write(packet);
    	sb = new StringBuilder();
	    sb.append("[ ");
	    for (byte b : packet) {
	        sb.append(String.format("%02X ", b));
	    }
	    sb.append("]");
	    System.out.println(sb);
    	while(true);
	}

}
