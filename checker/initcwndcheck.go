package initcwndcheck

//Originally stollen from https://github.com/kdar/gorawtcpsyn/blob/master/main.go
import (
	"bytes"
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"time"
)

// get the local ip and port based on our destination ip
func localIPPort(dstip net.IP) (net.IP, int) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	// We don't actually connect to anything, but we can determine
	// based on our destination ip what source ip we should use.
	if con, err := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, udpaddr.Port
		}
	}
	log.Fatal("could not get local ip: " + err.Error())
	return nil, -1
}

func listenandcount(conn net.PacketConn, dstip string, srcport layers.TCPPort) (pkt_count, payload_size int, fullpayload []byte) {
	//Drain the connection without ACKing
	detected := make(map[uint32]bool) //Store the detected seq to weed out retransmits
	timer := time.NewTicker(10 * time.Second)
	for {
		select {
		case <-timer.C:
			//Stop draining when channel pings first time
			return
		default:
			b := make([]byte, 4096)
			n, addr, err := conn.ReadFrom(b)
			//log.Println(n)
			if err != nil {
				log.Println("error reading packet: ", err)
				return
			} else if addr.String() == dstip {
				packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
				if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					ok := detected[tcp.Seq]
					if !ok {
						//log.Println(packet)
						if tcp.DstPort == srcport {
							if payloadlayer := packet.Layer(gopacket.LayerTypePayload); payloadlayer != nil {
								log.Println(tcp.Seq)
								detected[tcp.Seq] = true
								pkt_count++
								cnt := payloadlayer.LayerContents()
								fullpayload = append(fullpayload, cnt...)
								//fmt.Println(string(cnt))
								payload_size += len(cnt)
								//log.Println(pkt_count, payload_size)
							}
						}
					} else {
						log.Println("retransmit")
					}
				}
			}
		}
	}
	return
}

func porttoint(port layers.TCPPort) string {
	return strconv.Itoa(int(port))
}

func getack(conn net.PacketConn, srcport layers.TCPPort, dstip string) (ack uint32, err error) {
	for {
		b := make([]byte, 4096)
		log.Println("reading from conn")
		var n int
		var addr net.Addr
		n, addr, err = conn.ReadFrom(b)
		if err != nil {
			log.Println("reading..", err)
			return
		} else if addr.String() == dstip {
			// Decode a packet
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)
			// Get the TCP layer from this packet
			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)
				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						ack = tcp.Seq
					} else {
						err = errors.New("Port is CLOSED")
					}
					return
				}
			}
		} else {
			err = errors.New("Got packet not matching addr")
		}
	}
	return
}

//Detectinitcwnd attempts to detect the initial congession window of an http endpoint.
//First does a 3 way tcp handshake, sends GET request and then does not ack any response while measuring the packets received. This allows us to see how much data the server can send without acknowledgement.
func Detectinitcwnd(host, url string, dstip net.IP) (pkt_count, payload_size int, fullpayload []byte, err error) {
	pldata := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", url, host))
	var dstport layers.TCPPort

	dstport = layers.TCPPort(80)

	srcip, sport := localIPPort(dstip)
	srcport := layers.TCPPort(sport)
	log.Printf("using srcip: %v", srcip.String())
	log.Printf("using dstip: %v", dstip.String())

	// Our IP header... not used, but necessary for TCP checksumming.
	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}
	//layers.TCPOption{3, 3, []byte{7}} maybe for window scaling... dunno
	tcpopts := []layers.TCPOption{layers.TCPOption{2, 4, []byte{5, 172}}} //Set MSS 1452
	// Our TCP header
	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  65535,
		Options: tcpopts,
	}
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, tcp)
	if err != nil {
		return
	}
	var out1 bytes.Buffer
	iptset := exec.Command("iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-s", srcip.String(), "--sport", porttoint(srcport), "--dport", porttoint(dstport), "-j", "DROP")
	iptset.Stderr = &out1
	log.Println(iptset)
	err = iptset.Run()
	if err != nil {
		return
	}
	log.Println(out1.String())
	iptrem := exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-s", srcip.String(), "--sport", porttoint(srcport), "--dport", porttoint(dstport), "-j", "DROP")
	conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		return
	}
	defer func() {
		fmt.Println(iptrem)
		var out bytes.Buffer
		iptrem.Stderr = &out
		err = iptrem.Run()
		if err != nil {
			log.Println(err)
		}
		fmt.Printf(out.String())
		log.Println("Removed iptable rule")
		//Now RST should be allowed... send it
		rst_pkt := &layers.TCP{
			SrcPort: srcport,
			DstPort: dstport,
			Seq:     1105024980,
			Window:  65535,
			RST:     true,
		}
		rst_pkt.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, rst_pkt); err != nil {
			//Shadowing err since we dont care
			log.Println(err)
		}
		if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
			//Shadowing err since we dont care
			log.Println(err)
		}

	}()
	log.Println("writing request")
	_, err = conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip})
	if err != nil {
		return
	}

	// Set deadline so we don't wait forever.
	err = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		return
	}
	//Capture synack from our syn, return the ack value
	ack, err := getack(conn, srcport, dstip.String())
	if err != nil {
		log.Println(err)
		return
	} else {
		//Prepare http request, ack the synack
		payload := &layers.TCP{
			SrcPort: srcport,
			DstPort: dstport,
			Seq:     1105024979,
			ACK:     true,
			Window:  65535,
			Ack:     ack + 1,
		}
		payload.SetNetworkLayerForChecksum(ip)
		if err := gopacket.SerializeLayers(buf, opts, payload, gopacket.Payload(pldata)); err != nil {
			log.Fatal(err)
		}
		if _, err := conn.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
			log.Fatal(err)
		}
		pkt_count, payload_size, fullpayload = listenandcount(conn, dstip.String(), srcport)
		log.Println("Initcwnd: ", pkt_count)
		log.Println("Data: ", payload_size)

		return
	}
	return
}
