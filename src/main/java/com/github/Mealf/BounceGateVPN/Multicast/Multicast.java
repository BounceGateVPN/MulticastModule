package com.github.Mealf.BounceGateVPN.Multicast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

public class Multicast {
	Map<Integer, ArrayList<host>> group;
	IGMPAnalysis analysis;
	byte[] packet;
	//MulticastType type;

	public Multicast() {
		group = new HashMap<Integer, ArrayList<host>>();
		analysis = new IGMPAnalysis();
		//type = MulticastType.NULL;
	}

	public void setPacket(byte[] packet) {
		this.packet = packet;
		analysis.setFramePacket(packet);
		
		if(analysis.getType() == MulticastType.NULL)
			return;
		if(analysis.getType() == MulticastType.IGMP)
			IGMPhandler();
		/*if ((packet[30] & 0xF0) != 0xe0 || !analysis.compareChecksum()) {
			type = MulticastType.NULL;
			return;
		}
		if (isIGMPPacket()) {
			if (compareIGMPChecksum()) {
				type = MulticastType.IGMP;
				IGMPhandler();
			} else
				type = MulticastType.NULL;
		} else
			type = MulticastType.MULTICAST;*/
	}

	public MulticastType getType() {
		return analysis.getType();
	}

	public ArrayList<byte[]> getIPinGroup() {
		if (analysis.getType() == MulticastType.NULL)
			return null;
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
			}
			// leave group
			if (recordType == 0x03) {
				LeaveGroup(GroupAddress);
			}
		}
	}

	/*public byte[] GeneralQuery(byte[] desMAC, int groupIP, int version) {
		byte[] packet = hex2Byte("0000000000000000000000004600002032e40000010200000000000000000000940400001164000000000000");
		analysis.setFramePacket(packet);
		analysis.setChecksum();
		this.packet = analysis.getFramePacket();
		/*short IGMPChecksum = calculateIGMPChecksum();
		this.packet[40] = (byte) ((IGMPChecksum >> 4));
		this.packet[41] = (byte) ((IGMPChecksum & 0xFF));*/
		
		/*fill desMAC
		for(int i=0;i<6;i++)
			this.packet[i] = desMAC[i];
		
		for(int i=0;i<4;i++) {
			this.packet[32-i] = (byte)(groupIP%256);
			this.packet[45-i] = (byte)(groupIP%256);
			groupIP/=256;
		}
		return this.packet;
	}*/

	private void JoinGroup(byte[] GroupAddress) {
		int group_ip = ConvertIP(GroupAddress);
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

	/*private boolean compareIGMPChecksum() {
		if (calculateIGMPChecksum() == getChecksum())
			return true;
		return false;
	}
	
	private short calculateIGMPChecksum() {
		int IP_header_length = (packet[14] & 0xF) * 4;
		int total_len = (packet[16] & 0xFF) << 8 | (packet[17] & 0xFF);
		int IGMP_pos = 14 + IP_header_length;
		int IGMP_len = total_len - IP_header_length;
		int sum = 0;
		for (int i = IGMP_pos; i < IGMP_pos + IGMP_len; i += 2) {
			if (i == IGMP_pos + 2)
				continue;
			if (i + 1 == packet.length)
				sum += (packet[i] & 0xFF) << 8;
			else
				sum += (packet[i] & 0xFF) << 8 | (packet[i + 1] & 0xFF);
		}
		sum = ((sum & 0x00FF0000) >> 16) + (sum & 0x0000FFFF);
		sum = ~sum;
		return (short)sum;
	}

	private short getChecksum() {
		int IP_header_length = (packet[14] & 0xF) * 4;
		int IGMP_pos = 14 + IP_header_length;
		return (short) ((packet[IGMP_pos + 2] & 0xFF) << 8 | (packet[IGMP_pos + 3] & 0xFF));
	}*/

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

	/*private byte[] hex2Byte(String hexString) {
		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < bytes.length; i++)
			bytes[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
		return bytes;
	}*/

	/*public boolean isIGMPPacket() {
		if (packet == null)
			return false;

		if (packet.length >= 24 && packet[23] == 0x02)
			return true;
		return false;
	}*/
}
