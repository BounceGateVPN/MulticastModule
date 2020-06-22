package com.github.Mealf.BounceGateVPN.Multicast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Multicast {
	Map<Integer, ArrayList<host>> groupV2, groupV3;
	IGMPAnalysis analysis;
	byte[] packet;
	boolean queryFlag;

	public Multicast() {
		groupV2 = new HashMap<Integer, ArrayList<host>>();
		groupV3 = new HashMap<Integer, ArrayList<host>>();
		analysis = new IGMPAnalysis();
		queryFlag = false;
	}

	public void setPacket(byte[] packet) {
		this.packet = packet;
		analysis.setFramePacket(packet);

		if (analysis.getType() == MulticastType.NULL)
			return;
		if (analysis.getType() == MulticastType.IGMP)
			IGMPhandler();
	}

	public MulticastType getType() {
		return analysis.getType();
	}

	public ArrayList<byte[]> getIPinGroup() {
		if (analysis.getType() == MulticastType.NULL)
			return null;
		int group_ip = analysis.getDesIPaddress();
		ArrayList<byte[]> IP_in_group = new ArrayList<byte[]>();

		// get IGMPv2 member
		ArrayList<host> hosts = groupV2.get(group_ip);
		Iterator<host> iterator;
		if (hosts != null) {
			iterator = hosts.iterator();
			while (iterator.hasNext())
				IP_in_group.add(iterator.next().ipaddr);
		}

		// get IGMPv2 member
		hosts = groupV3.get(group_ip);
		if (hosts != null) {
			iterator = hosts.iterator();
			while (iterator.hasNext())
				IP_in_group.add(iterator.next().ipaddr);
		}

		if (IP_in_group.isEmpty())
			return null;
		return IP_in_group;
	}

	private void IGMPhandler() {
		if (analysis.getType() != MulticastType.IGMP)
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
			JoinGroup(GroupAddress, 2);
		}

		// Version 2 Membership Report
		if (IGMP_type == 0x16) {
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			JoinGroup(GroupAddress, 2);
		}

		// Version 2 Leave Group
		if (IGMP_type == 0x17) {
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 4, IGMP_pos + 8);
			LeaveGroup(GroupAddress, 2);
		}

		// Version 3 Membership Report
		if (IGMP_type == 0x22) {
			byte recordType = packet[IGMP_pos + 8];
			byte[] GroupAddress = Arrays.copyOfRange(packet, IGMP_pos + 12, IGMP_pos + 16);

			// join group
			if (recordType == 0x04) {
				JoinGroup(GroupAddress, 3);
			}
			// leave group
			if (recordType == 0x03) {
				LeaveGroup(GroupAddress, 3);
			}
		}
	}

	private void JoinGroup(byte[] GroupAddress, int version) {
		int group_ip = ConvertIP(GroupAddress);
		Map<Integer, ArrayList<host>> group;
		if (version == 2)
			group = groupV2;
		else if (version == 3)
			group = groupV3;
		else
			return;

		if (group_ip != -1) {
			if (group.get(group_ip) == null)
				group.put(group_ip, new ArrayList<host>());
			byte[] src_ip = ConvertIP(analysis.getSrcIPaddress());

			// already join
			ArrayList<host> g = group.get(group_ip);
			for (int i = 0; i < g.size(); i++)
				if (Arrays.equals(g.get(i).ipaddr, src_ip))
					return;

			group.get(group_ip).add(new host(src_ip));
		}
	}

	private void LeaveGroup(byte[] GroupAddress, int version) {
		int group_ip = ConvertIP(GroupAddress);
		Map<Integer, ArrayList<host>> group;
		if (version == 2)
			group = groupV2;
		else if (version == 3)
			group = groupV3;
		else
			return;
		
		if (group_ip != -1) {
			if (group.get(group_ip) != null) {
				byte[] src_ip = ConvertIP(analysis.getSrcIPaddress());
				ArrayList<host> g = group.get(group_ip);
				for (int i = 0; i < g.size(); i++)
					if (Arrays.equals(g.get(i).ipaddr, src_ip)) {
						g.remove(i);
						if(g.isEmpty())
							group.remove(group_ip);
					}
			}
			if(groupV2.isEmpty()) {
				System.out.println("empty");
				queryFlag = false;
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
}
