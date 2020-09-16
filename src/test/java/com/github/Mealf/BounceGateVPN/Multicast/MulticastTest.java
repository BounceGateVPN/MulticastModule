package com.github.Mealf.BounceGateVPN.Multicast;

import static org.junit.Assert.*;

import java.math.BigInteger;
import java.util.ArrayList;


import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;

public class MulticastTest {

	@Rule
	public TestRule watcher = new TestWatcher() {
	   protected void starting(Description description) {
	      System.out.println("Starting test: " + description.getMethodName());
	   }
	   protected void finished(Description description) {
		   System.out.println("Finished test: " + description.getMethodName() + "\n");
	   }
	};
	
	@Test
	public void testGetTypeisNULL() {
		Multicast multicast = new Multicast();
		String s = "5cd9981db2661c1b0da44b840800450000707137000080111788c0a8006499fe56b3ce316989005cc9ab565330313000060202000000a218dd00ac0300007801000001000000ac03000030000000153080312f5e8de6e7f0ca2dea1b0b9d012a60d43610b519e697896bbca966987e704ecd6918a876bcf8ae17d9160f88";
		byte[] val = new BigInteger(s, 16).toByteArray();
		multicast.setPacket(val);

		assertEquals(multicast.getType(), MulticastType.NULL);
	}

	@Test
	public void testGetTypeisIGMP() {
		Multicast multicast = new Multicast();
		String s = "01005e0000fc1c1b0da44b84080046000020440c000001023ec3c0a80064e00000fc9404000016000903e00000fc";
		byte[] val = new BigInteger(s, 16).toByteArray();
		multicast.setPacket(val);

		assertEquals(multicast.getType(), MulticastType.IGMP);
		
		s = "01005e000016e2acb1cb08e2080046c00028000040000102ec4ec0a85702e0000016940400002200f6fc0000000104000000e2000101";
		val = new BigInteger(s, 16).toByteArray();
		multicast.setPacket(val);

		assertEquals(multicast.getType(), MulticastType.IGMP);
				
	}

	@Test
	public void testGetTypeisMulticast() {
		Multicast multicast = new Multicast();
		String s = "01005e0101010a002700000608004500003079370000011166dac0a83801e0010101e47b162e001cef233939393939393939393939393939393939393939";
		byte[] val = new BigInteger(s, 16).toByteArray();
		multicast.setPacket(val);

		assertEquals(multicast.getType(), MulticastType.MULTICAST);
	}

	@Test
	public void testGetIPinGroup() {
		ArrayList<byte[]> expected = new ArrayList<byte[]>();
		expected.add(new byte[] { (byte) 0xc0, (byte) 0xa8, (byte) 0x00, (byte) 0x64 });
		expected.add(new byte[] { (byte) 0xc0, (byte) 0xa8, (byte) 0x00, (byte) 0x65 });

		Multicast multicast = new Multicast();
		String[] s = { "01005e0000fb1c1b0da44b840800460000204ae20000010237eec0a80064e00000fb9404000016000904e00000fb",
				"01005e0000fb000c29989973080046c00020000040000102420fc0a80065e00000fb9404000016000904e00000fb0000000000000000000000000000",
				"01005e0000164ac711656e0c080046c00028000040000102ec4ec0a85702e0000016940400002200f6fc0000000104000000e2000101"};
		byte[] val;
		for (String hexStream : s) {
			val = new BigInteger(hexStream, 16).toByteArray();
			multicast.setPacket(val);
		}

		String msg = "01005e0000fb1c1b0da44b840800450000304b1500000111cca0c0a80064e00000fbddf8162e001c87a53030303030303030303030303030303030303030";
		val = new BigInteger(msg, 16).toByteArray();
		multicast.setPacket(val);

		assertArrayEquals(multicast.getIPinGroup().toArray(), expected.toArray());
	}

	@Test
	public void testAutoDeleteMember() throws InterruptedException {
		ArrayList<byte[]> expected = new ArrayList<byte[]>();
		expected.add(new byte[] { (byte) 0xc0, (byte) 0xa8, (byte) 0x00, (byte) 0x64 });
		
		Multicast multicast = new Multicast();
		String[] s = { "01005e0000fb1c1b0da44b840800460000204ae20000010237eec0a80064e00000fb9404000016000904e00000fb",
				"01005e0000fb000c29989973080046c00020000040000102420fc0a80065e00000fb9404000016000904e00000fb0000000000000000000000000000" };
		byte[] val;
		for (String hexStream : s) {
			val = new BigInteger(hexStream, 16).toByteArray();
			multicast.setPacket(val);
		}
		//第一次Query
		String query = "01005e0000015cd9981db266080045c0001cc58e0000010252e7c0a80001e00000011164ee9b00000000050505050505050505050505050500000000";
		val = new BigInteger(query, 16).toByteArray();
		multicast.setPacket(val);
		
		//0xc0a80064回應
		val = new BigInteger(s[0], 16).toByteArray();
		multicast.setPacket(val);
		Thread.sleep(60000);
		//第二次Query, 0xc0a80065被刪除
		val = new BigInteger(query, 16).toByteArray();
		multicast.setPacket(val);
		//將desIP換為註冊的GroupIP
		val = new BigInteger(s[0], 16).toByteArray();
		multicast.setPacket(val);
		
		assertArrayEquals(expected.toArray(), multicast.getIPinGroup().toArray());
	}
}
