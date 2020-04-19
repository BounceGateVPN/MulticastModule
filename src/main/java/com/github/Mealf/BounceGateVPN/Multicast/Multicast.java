package com.github.Mealf.BounceGateVPN.Multicast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.github.smallru8.driver.tuntap.Analysis;

public class Multicast {
	Map<Integer, ArrayList<host>> group;
	Analysis analysis;
	byte[] packet;
	MulticastType type;

	public Multicast() {
		group = new HashMap<Integer, ArrayList<host>>();
		analysis = new Analysis();
		type = MulticastType.NULL;
	}

	public void setPacket(byte[] packet) {
		this.packet = packet;
		analysis.setFramePacket(packet);

		if (!analysis.compareChecksum()) {
			type = MulticastType.NULL;
			return;
		}
		if (isIGMPPacket()) {
			type = MulticastType.IGMP;
			IGMPhandler();
		} else
			type = MulticastType.MULTICAST;
	}

	public MulticastType getType() {
		return type;
	}

	public ArrayList<byte[]> getIPinGroup() {
		int group_ip = analysis.getDesIPaddress();
		ArrayList<byte[]> IP_in_group = new ArrayList<byte[]>();
		ArrayList<host> hosts = group.get(group_ip);
		if (hosts == null || hosts.size() == 0)
			return null;
		Iterator<host> iterator = hosts.iterator();

		while (iterator.hasNext()) {
			IP_in_group.add(iterator.next().ipaddr);
		}
		if (IP_in_group.isEmpty())
			return null;
		return IP_in_group;
	}

	private void IGMPhandler() {
		if (type != MulticastType.IGMP)
			return;

		int IP_header_length = (packet[14] & 0xF) * 4;
		int IGMP_pos = 14 + IP_header_length;
		byte IGMP_type = packet[IGMP_pos];

		// Membership query
		if (IGMP_type == 0x11) {
			int IGMP_length = packet[16] * 255 + packet[17] - IP_header_length;
			int MaxRespTime = packet[IGMP_pos + 1];

			// Version 1
			if (IGMP_length == 8 && MaxRespTime == 0) {

			}
			// Version 2
			if (IGMP_length == 8 && MaxRespTime != 0) {

			}
			// Version 3
			if (IGMP_length >= 12) {

			}
		}

		// Version 1 Membership Report
		if (IGMP_type == 0x12) {
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			JoinGroup(GroupAddress);
		}

		// Version 2 Membership Report
		if (IGMP_type == 0x16) {
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			JoinGroup(GroupAddress);
		}

		// Version 2 Leave Group
		if (IGMP_type == 0x17) {
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			LeaveGroup(GroupAddress);
		}

		// Version 3 Membership Report
		if (IGMP_type == 0x22) {
			byte recordType = packet[IGMP_pos + 8];
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 12, IGMP_pos + 16);

			// join group
			if (recordType == 0x04) {
				JoinGroup(GroupAddress);
				System.out.println(String.format("join group %x.%x.%x.%x", GroupAddress[0], GroupAddress[1],
						GroupAddress[2], GroupAddress[3]));
			}
			// leave group
			if (recordType == 0x03) {
				LeaveGroup(GroupAddress);
				System.out.println("leave group");
			}
		}
	}

	private void JoinGroup(byte[] GroupAddress) {
		int group_ip = ConvertIP(GroupAddress);
		if (group_ip != -1) {
			if (group.get(group_ip) == null)
				group.put(group_ip, new ArrayList<host>());
			byte[] src_ip = ConvertIP(analysis.getSrcIPaddress());
			
			//already join
			ArrayList<host> g = group.get(group_ip);
			for (int i = 0; i < g.size(); i++)
				if (Arrays.equals(g.get(i).ipaddr, src_ip))
					return;
			
			group.get(group_ip).add(new host(src_ip));
		}

		for (int i = 0; i < group.get(group_ip).size(); i++) {
			System.out.println(String.format("%x.%x.%x.%x", group.get(group_ip).get(i).ipaddr[0],
					group.get(group_ip).get(i).ipaddr[1], group.get(group_ip).get(i).ipaddr[2],
					group.get(group_ip).get(i).ipaddr[3]));
		}

	}

	private void LeaveGroup(byte[] GroupAddress) {
		int group_ip = ConvertIP(GroupAddress);
		if (group_ip != -1) {
			if (group.get(group_ip) != null) {
				byte[] src_ip = ConvertIP(analysis.getSrcIPaddress());
				ArrayList<host> g = group.get(group_ip);
				for (int i = 0; i < g.size(); i++)
					if (Arrays.equals(g.get(i).ipaddr, src_ip))
						g.remove(i);
			}
		}
	}

	private int ConvertIP(byte[] ipaddr) {
		int ip = 0;
		if (ipaddr.length != 4)
			return -1;

		ip = (ipaddr[0] & 0xFF) << 24 | (ipaddr[1] & 0xFF) << 16 | (ipaddr[2] & 0xFF) << 8 | (ipaddr[3] & 0xFF);
		return ip;
	}

	private byte[] ConvertIP(int ipaddr) {
		byte[] ip = new byte[4];
		for (int i = 3; i >= 0; i--) {
			ip[i] = (byte) (ipaddr & 0xFF);
			ipaddr = ipaddr >> 8;
		}
		return ip;
	}

	public boolean isIGMPPacket() {
		if (packet == null)
			return false;

		if (packet.length >= 24 && packet[23] == 0x02)
			return true;
		return false;
	}
}
