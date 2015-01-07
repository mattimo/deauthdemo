package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"log"
	"fmt"
)

type AP struct {
	Ssid string
	Channel layers.RadioTapChannelFrequency
	Bssid []byte
}

func (ap AP) String() string {
	return fmt.Sprintf("%s: %s [% x]", ap.Ssid, ap.Channel, ap.Bssid)
}

var APList map[string]AP

func handlePacket(p gopacket.Packet) {
	ap := AP{}
	// extract beacon
	// extract Ssid
	for _, l := range p.Layers() {
		switch l.LayerType() {
		case layers.LayerTypeDot11MgmtBeacon:
			beacon, ok := p.Layer(layers.LayerTypeDot11MgmtBeacon).(*layers.Dot11MgmtBeacon)
			if !ok {
				log.Println("Could not marshal layer thing")
				continue
			}
			pack := gopacket.NewPacket(beacon.LayerContents(), layers.LayerTypeDot11MgmtBeacon, gopacket.Default)
			for _, subpack := range pack.Layers() {
				info, ok := subpack.(*layers.Dot11InformationElement)
				if !ok {
					continue
				}
				if info.ID == layers.Dot11InformationElementIDSSID {
					ap.Ssid = fmt.Sprintf("%s", info.Info)
					break
				}
			}
		case layers.LayerTypeDot11:
			base, ok := p.Layer(layers.LayerTypeDot11).(*layers.Dot11)
			if !ok {
				continue
			}
			ap.Bssid = base.Address2
			continue
		case layers.LayerTypeRadioTap:
			radio, ok := p.Layer(layers.LayerTypeRadioTap).(*layers.RadioTap)
			if !ok {
				continue
			}
			ap.Channel = radio.ChannelFrequency
			continue

		}
	}
	APList[ap.Ssid] = ap
}

func main() {
	APList = make(map[string]AP)
	log.Println("Starting deauth-demo")
	//handle, err := pcap.OpenLive("em1", 1600, true, 0)
	handle, err := pcap.OpenOffline("/home/iniuser/Downloads/bssidcap.pcapng")
	if err != nil {
		log.Fatal("Error starting capture:", err)
	}
	err = handle.SetBPFFilter("(type mgt subtype beacon) or (type mgt subtype probe-req)")
	if err != nil {
		log.Fatal("Error setting bpf:", err)
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range source.Packets() {
		if errPack := packet.ErrorLayer(); errPack != nil {
			log.Println("Packet could not be decoded:", errPack)
		}
		handlePacket(packet)
	}
	log.Println(APList)
}
