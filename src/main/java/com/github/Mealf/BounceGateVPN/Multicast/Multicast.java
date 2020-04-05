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

	Multicast() {
		group = new HashMap<Integer, ArrayList<host>>();
		analysis = new Analysis();
	}

	public ArrayList<byte[]> analysis(byte[] packet) {
		analysis.setFramePacket(packet);
		if (isIGMPpacket(packet)) {
			IGMPhandler(packet);
			return null;
		}

		int group_ip = analysis.getDesIPaddress();
		ArrayList<byte[]> IP_in_group = new ArrayList<byte[]>();
		ArrayList<host> hosts = group.get(group_ip);
		Iterator<host> iterator = hosts.iterator();

		while (iterator.hasNext()) {
			IP_in_group.add(iterator.next().ipaddr);
		}
		if (IP_in_group.isEmpty())
			return null;
		return IP_in_group;
	}

	private void IGMPhandler(byte[] packet) {
		int IP_header_length = (packet[14] & 0xF) * 4;
		int IGMP_pos = 14 + IP_header_length;
		byte IGMP_type = packet[IGMP_pos];
		if (IGMP_type == 0x11) { // Membership query
			int IGMP_length = packet[16] * 255 + packet[17] - IP_header_length;
			int MaxRespTime = packet[IGMP_pos + 1];

			if (IGMP_length == 8 && MaxRespTime == 0) { // Version 1

			}
			if (IGMP_length == 8 && MaxRespTime != 0) { // Version 2

			}
			if (IGMP_length >= 12) { // Version 3

			}
		}
		if (IGMP_type == 0x12) { // Version 1 Membership Report
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			JoinGroup(GroupAddress);
		}
		if (IGMP_type == 0x16) { // Version 2 Membership Report
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			JoinGroup(GroupAddress);
		}
		if (IGMP_type == 0x17) { // Version 2 Leave Group
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			LeaveGroup(GroupAddress);
		}
		if (IGMP_type == 0x22) { // Version 3 Membership Report
			byte recordType = packet[IGMP_pos + 8];
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 12, IGMP_pos + 16);
			if (recordType == 0x04) { // join group
				JoinGroup(GroupAddress);
			}
			if (recordType == 0x03) { // leave group
				LeaveGroup(GroupAddress);
			}
		}
	}

	private void JoinGroup(byte[] GroupAddress) {
		int group_ip = ConvertIP(GroupAddress);
		if (group_ip != -1) {
			if (group.get(group_ip) == null)
				group.put(group_ip, new ArrayList<host>());
			byte[] src_ip = ConvertIP(analysis.getSrcIPaddress());
			group.get(group_ip).add(new host(src_ip));
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
		for (int i = 0; i < 4; i++)
			ip = ip * 255 + ipaddr[i];
		return ip;
	}

	private byte[] ConvertIP(int ipaddr) {
		byte[] ip = new byte[4];
		for (int i = 0; i < 4; i++) {
			ip[i] = (byte) (ipaddr % 255);
			ipaddr /= 255;
		}
		return ip;
	}

	public boolean isIGMPpacket(byte[] packet) {
		if (packet.length >= 24 && packet[23] == 0x02)
			return true;
		return false;
	}
}
