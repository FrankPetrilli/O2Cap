O2Cap - Rust packet capture and analysis

Built for EWU CSCD 433/533 - Advanced Networks

This code is far from modular / pretty; please excuse the giant main.rs and some clumsy conventions.

Usage
=====

Run the executable with root permissions; the first argument is a standard pcap filename if desired.

`o2cap [input.pcap]`

Output
=====

Shows TCP, IPv4, Ethernet, PPPoE, MPLS, EoMPLS, ICMP, etc.

```
    ___       ___       ___       ___       ___   
   /\  \     /\  \     /\  \     /\  \     /\  \   
  /::\  \   /\:\  \   /::\  \   /::\  \   /::\  \   
 /:/\:\__\ /::\:\__\ /:/\:\__\ /::\:\__\ /::\:\__\
 \:\/:/  / \:\::/__/ \:\ \/__/ \/\::/  / \/\::/  /
  \::/  /   \:\/_\    \:\__\     /:/  /     \/__/ 
   \/__/     \/__/     \/__/     \/__/             




O2Cap | Oxidized Packet Capture






Enter a filter? (y / N): n
Output filename (none): 
Select a device:
	0: enp2s0
	1: any
	2: lo

Enter your choice (0 - 2): 0

Ethernet: 70:85:C2:46:7F:33 -> C:C4:7A:93:A4:EE {
	IPv4: 172.17.2.225 -> 1.2.3.4 (TTL: 64, DSCP: 0) {
		TCP 4001 -> 4001 (Flags: ACK,PSH)
	
	}

}
Ethernet: CA:1:E:88:0:6 -> CC:5:E:88:0:0 {
	PPPoE session (Code: 0, Session ID: 0x11) {
		PPP (Protocol: 0x57) {
			IPv6: fc00:0000:0000:0000:0000:0000:0000:0001 -> fc00:0000:0002:0100:0000:0000:0001:0001 (TTL: 64) {
				ICMPv6 (Type: Echo Reply)
			
			}
		}
	
	}

}
Ethernet: CC:5:E:88:0:0 -> CA:1:E:88:0:6 {
	PPPoE session (Code: 0, Session ID: 0x11) {
		PPP (Protocol: 0xc021) {
			LCP (Code: Echo-Request)
		}
	
	}

}
Ethernet: CA:1:E:88:0:6 -> CC:5:E:88:0:0 {
	PPPoE session (Code: 0, Session ID: 0x11) {
		PPP (Protocol: 0xc021) {
			LCP (Code: Echo-Reply)
		}
	
	}

}
Ethernet: CC:0:D:5C:0:10 -> CC:1:D:5C:0:10 {
	MPLS (Label: 18, Exp: 1, TTL: 254) {
		MPLS (Label: 16, Exp: 0, TTL: 255) {
			Ethernet: 0:50:79:66:68:1 -> 0:50:79:66:68:0 {
				IPv4: 192.168.0.20 -> 192.168.0.10 (TTL: 64, DSCP: 0) {
					ICMP (Type: Echo Reply, Code: 0)
				
				}
			
			}
		
		}
	
	}

}
```
