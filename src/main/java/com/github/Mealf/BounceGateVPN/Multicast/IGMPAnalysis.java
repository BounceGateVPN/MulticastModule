package com.github.Mealf.BounceGateVPN.Multicast;

import com.github.smallru8.driver.tuntap.Analysis;

public class IGMPAnalysis extends Analysis {
	private MulticastType type;

	public IGMPAnalysis() {
		type = MulticastType.NULL;
	}

	/**
	 * 回傳目前封包的類型(NULL, IGMP, Multicast)
	 * 
	 * @return MulticastType
	 */
	public MulticastType getType() {
		return type;
	}

	/**
	 * 設定封包並判斷封包類型
	 * 
	 * @param data
	 */
	@Override
	public void setFramePacket(byte[] data) {
		super.setFramePacket(data);
		if ((packet[30] & 0xF0) != 0xe0 || !compareChecksum()) {
			type = MulticastType.NULL;
		}
		if (isIGMPPacket()) {
			if (compareIGMPChecksum()) {
				type = MulticastType.IGMP;
			} else
				type = MulticastType.NULL;
		} else
			type = MulticastType.MULTICAST;

	}

	/**
	 * 判斷是否為IGMP封包
	 * 
	 * @return boolean
	 */
	public boolean isIGMPPacket() {
		if (packet == null)
			return false;

		if (packet.length >= 24 && packet[23] == 0x02)
			return true;
		return false;
	}

	/**
	 * 取得IGMP checksum
	 * 
	 * @return short
	 */
	public short getIGMPChecksum() {
		if (!isIGMPPacket())
			return 0;

		int IP_header_length = (packet[14] & 0xF) * 4;
		int IGMP_pos = 14 + IP_header_length;
		return (short) ((packet[IGMP_pos + 2] & 0xFF) << 8 | (packet[IGMP_pos + 3] & 0xFF));
	}

	/**
	 * 計算IGMP checksum
	 * 
	 * @return short
	 */
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
		return (short) sum;
	}

	/**
	 * 比對IGMP checksum是否正確
	 * 
	 * @return boolean
	 */
	public boolean compareIGMPChecksum() {
		if (calculateIGMPChecksum() == getIGMPChecksum())
			return true;
		return false;
	}

	/**
	 * 產生IGMP Query
	 * 
	 * @param groupIP
	 * @param version
	 * @return
	 */
	public byte[] generalQuery(int groupIP, int version) {
		if (version == 2)
			packet = hex2Byte(
					"00000000000000000000000008004600002032e40000010200000000000000000000940400001164000000000000");
		else
			packet = hex2Byte(
					"00000000000000000000000008004600002432e400000102000000000000000000009404000011A200000000000018000000");

		/* fill MAC, desIP and groupID */
		for (int i = 0; i < 4; i++) {
			byte rightmostByte = (byte) (groupIP & 0xFF);
			this.packet[5 - i] = rightmostByte;
			this.packet[33 - i] = rightmostByte;
			this.packet[45 - i] = rightmostByte;
			groupIP = groupIP >> 8;
		}

		/* fill desMAC */
		this.packet[0] = 0x01;
		this.packet[2] = 0x5e;
		this.packet[3] = (byte) (this.packet[3] & 0b01111111);

		super.setChecksum();

		short IGMPChecksum = calculateIGMPChecksum();
		this.packet[40] = (byte) ((IGMPChecksum >> 8) & 0xFF);
		this.packet[41] = (byte) ((IGMPChecksum & 0xFF));
		
		return this.packet;
	}

	/**
	 * 16進位字串轉byte array
	 * 
	 * @param hexString
	 * @return byte[]
	 */
	private byte[] hex2Byte(String hexString) {
		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < bytes.length; i++)
			bytes[i] = (byte) Integer.parseInt(hexString.substring(2 * i, 2 * i + 2), 16);
		return bytes;
	}
}
