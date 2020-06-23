package com.github.Mealf.BounceGateVPN.Multicast.TEST;

import java.util.ArrayList;
import java.util.Scanner;

import com.github.Mealf.BounceGateVPN.Multicast.Multicast;
import com.github.Mealf.BounceGateVPN.Multicast.MulticastType;

public class TEST1 {

	public static void main(String[] args) {
		String str;
		byte[] val;
		Multicast multicast = new Multicast();
		Scanner scanner = new Scanner(System.in);
		System.out.println("輸入封包內容(hex steam)");
		while (true) {
			if (!scanner.hasNextLine())
				continue;
			str = scanner.nextLine();

			val = new byte[str.length() / 2];
			for (int i = 0; i < val.length; i++) {
				int index = i * 2;
				int j = Integer.parseInt(str.substring(index, index + 2), 16);
				val[i] = (byte) j;
			}
			multicast.setPacket(val);
			if (multicast.getType() == MulticastType.IGMP) {
				System.out.println("IGMP");
			}
			if (multicast.getType() == MulticastType.NULL) {
				System.out.println("NULL");
			}
			if (multicast.getType() == MulticastType.MULTICAST) {
				System.out.println("MULTICAST");
				ArrayList<byte[]> list = multicast.getIPinGroup();
				if (list != null) {
					for (int i = 0; i < list.size(); i++) {
						System.out.println(String.format("%x.%x.%x.%x", list.get(i)[0], list.get(i)[1], list.get(i)[2],
								list.get(i)[3]));
					}
				}
			}
			System.out.println("輸入封包內容(hex steam)");
		}
	}
}
