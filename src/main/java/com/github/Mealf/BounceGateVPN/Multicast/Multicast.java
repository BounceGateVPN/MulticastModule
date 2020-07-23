package com.github.Mealf.BounceGateVPN.Multicast;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import com.github.Mealf.util.ConvertIP;

public class Multicast {
	Map<Integer, ArrayList<host>> groupV2, groupV3;
	IGMPAnalysis analysis;
	byte[] packet;
	boolean queryFlag;
	String routerIP;
	byte[] routerMAC;
	Date delete_member_runable_time;
	Date query_sendable_time;
	final int INTERVAL_OF_RUNABLE_TIME = 60 * 1000;
	final int INTERVAL_OF_WAIT_OTHER_QUERY = 120 * 1000;

	public Multicast() {
		groupV2 = new HashMap<Integer, ArrayList<host>>();
		groupV3 = new HashMap<Integer, ArrayList<host>>();
		analysis = new IGMPAnalysis();
		queryFlag = false;
		routerIP = "";
		routerMAC = null;
		delete_member_runable_time = new Date();
		query_sendable_time = new Date();
	}

	public Multicast(String routerIP) {
		this();
		this.routerIP = routerIP;
	}

	// 設定封包
	public void setPacket(byte[] packet) {
		this.packet = packet;
		analysis.setFramePacket(packet);

		if (analysis.getType() == MulticastType.NULL)
			return;
		if (analysis.getType() == MulticastType.IGMP)
			IGMPhandler();
	}

	public void setRouterIP(String routerIP) {
		this.routerIP = routerIP;
	}

	public void setRouterMAC(byte[] routerMAC) {
		this.routerMAC = routerMAC;
	}

	// 取得封包類型
	public MulticastType getType() {
		return analysis.getType();
	}

	// 取得group內成員IP
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

	public boolean isSpecialAddress() {
		if (packet[0] == -32 && packet[1] == 0 && packet[2] == 0)
			return true;
		return false;
	}

	// 生成Group IP為224.0.0.1的query
	public byte[] generateQuery(int version) {

		if (queryFlag == false)
			return null;

		Date now = new Date();
		if (query_sendable_time.before(now))
			return null;
		if (delete_member_runable_time.after(now)) {
			delete_member_runable_time.setTime(now.getTime() + INTERVAL_OF_RUNABLE_TIME);
			autoDeleteMember();
		}

		System.out.println("generate Query!");
		return analysis.generateQuery(routerIP, routerMAC, "224.0.0.1", version);
	}

	// 生成特定Group IP的query
	public byte[] generateQuery(String groupIP, int version) {
		return analysis.generateQuery(routerIP, routerMAC, groupIP, version);
	}

	// 處理IGMP封包
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
				Date now = new Date();
				if (delete_member_runable_time.before(now)) {
					delete_member_runable_time.setTime(now.getTime() + INTERVAL_OF_RUNABLE_TIME);
					autoDeleteMember();
				}

				if (analysis.getSrcIPaddress() < ConvertIP.toInt(routerIP))
					query_sendable_time.setTime(now.getTime() + INTERVAL_OF_WAIT_OTHER_QUERY);
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

	// 加入group
	private void JoinGroup(byte[] GroupAddress, int version) {
		System.out.println(
				ConvertIP.toString(analysis.getSrcIPaddress()) + " join group :" + ConvertIP.toString(GroupAddress));
		int group_ip = ConvertIP.toInt(GroupAddress);
		Map<Integer, ArrayList<host>> group;
		if (version == 2) {
			queryFlag = true;
			group = groupV2;
		} else if (version == 3)
			group = groupV3;
		else
			return;

		if (group_ip != -1) {
			if (group.get(group_ip) == null)
				group.put(group_ip, new ArrayList<host>());
			byte[] src_ip = ConvertIP.toByteArray(analysis.getSrcIPaddress());

			// already join
			ArrayList<host> g = group.get(group_ip);
			for (int i = 0; i < g.size(); i++)
				// flag recover
				if (Arrays.equals(g.get(i).ipaddr, src_ip)) {
					g.get(i).flag = true;
					return;
				}

			group.get(group_ip).add(new host(src_ip));
		}
	}

	// 離開group
	private void LeaveGroup(byte[] GroupAddress, int version) {
		int group_ip = ConvertIP.toInt(GroupAddress);
		Map<Integer, ArrayList<host>> group;
		if (version == 2)
			group = groupV2;
		else if (version == 3)
			group = groupV3;
		else
			return;

		if (group_ip != -1) {
			if (group.get(group_ip) != null) {
				byte[] src_ip = ConvertIP.toByteArray(analysis.getSrcIPaddress());
				ArrayList<host> g = group.get(group_ip);
				for (int i = 0; i < g.size(); i++)
					if (Arrays.equals(g.get(i).ipaddr, src_ip)) {
						g.remove(i);
						if (g.isEmpty())
							group.remove(group_ip);
					}
			}
			if (groupV2.isEmpty()) {
				System.out.println("empty");
				queryFlag = false;
			}
		}
	}

	// remove members with false flags
	private void autoDeleteMember() {
		for (Map.Entry<Integer, ArrayList<host>> entry : groupV2.entrySet()) {
			ArrayList<host> list = entry.getValue();
			for (int i = 0; i < list.size(); i++) {
				if (!list.get(i).flag) {
					list.remove(i);
					i--;
				} else {
					list.get(i).flag = false;
				}
			}
			if (list.isEmpty())
				groupV2.remove(entry.getKey());
		}
		if (groupV2.isEmpty()) {
			System.out.println("empty");
			queryFlag = false;
		}
	}
}
