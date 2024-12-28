package ospf_cnn

import (
	"encoding/binary"
	packet2 "github.com/IrineSistiana/mosdns/v5/pkg/ospf_cnn/packet"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var decOpts = gopacket.DecodeOptions{
	Lazy:                     false,
	NoCopy:                   true,
	SkipDecodeRecovery:       false,
	DecodeStreamsAsDatagrams: false,
}

func (i *Interface) doReadDispatch(pkt recvPkt) {
	//dst := pkt.h.Dst
	//if dst.String() != AllSPFRouters && !dst.Equal(i.Address.IP) {
	//	logWarn("interface %s skipped 1 pkt processing causing its IPv4.Dst(%s)"+
	//		" is neither AllSPFRouter(%s) nor interface addr(%s)", i.c.ifi.Name, dst.String(), AllSPFRouters, i.Address.IP.String())
	//	return
	//}
	ps := gopacket.NewPacket(pkt.p, layers.LayerTypeOSPF, decOpts)
	p := ps.Layer(layers.LayerTypeOSPF)
	if p == nil {
		logErr("interface %s unexpected got nil OSPF layer parse result", i.c.ifi.Name)
		return
	}
	l, ok := p.(*layers.OSPFv2)
	if !ok {
		logWarn("interface %s doReadDispatch expecting(*layers.OSPFv2) but got(%T)", i.c.ifi.Name, p)
		return
	}
	i.doParsedMsgProcessing(pkt.h, (*packet2.LayerOSPFv2)(l))
}

func (i *Interface) queuePktForSend(pkt sendPkt) {
	select {
	case i.pendingSendPkt <- pkt:
	default:
		logWarn("interface %s pending send pkt queue full. Dropped 1 %s pkt", i.c.ifi.Name, pkt.p.GetType())
	}
}

func (i *Interface) doHello() (err error) {
	hello := &packet2.OSPFv2Packet[packet2.HelloPayloadV2]{
		OSPFv2: i.Area.ospfPktHeader(func(p *packet2.LayerOSPFv2) {
			p.Type = layers.OSPFHello
		}),
		Content: packet2.HelloPayloadV2{
			HelloPkg: layers.HelloPkg{
				RtrPriority:              i.RouterPriority,
				Options:                  2,
				HelloInterval:            i.HelloInterval,
				RouterDeadInterval:       i.RouterDeadInterval,
				DesignatedRouterID:       i.DR.Load(),
				BackupDesignatedRouterID: i.BDR.Load(),
			},
			NetworkMask: binary.BigEndian.Uint32(i.Address.Mask),
		},
	}
	i.nbMu.RLock()
	for _, nb := range i.Neighbors {
		hello.Content.NeighborID = append(hello.Content.NeighborID, nb.NeighborId)
	}
	i.nbMu.RUnlock()
	p := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(p, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, hello)
	if err != nil {
		logErr("interface %s err marshal %s->%s interval hello packet", i.c.ifi.Name, i.Address.IP.String(), AllSPFRouters)
		return nil
	}
	_, err = i.c.WriteMulticastAllSPF(p.Bytes())
	if err != nil {
		logErr("interface %s err send %s->%s interval hello packet", i.c.ifi.Name, i.Address.IP.String(), AllSPFRouters)
	} else {
		//logDebug("Sent interval Hello Packet(%d) %s->%s via Interface %s:\n%+v", len(p.Bytes()),
		//	i.Gateway.IP.String(), AllSPFRouters,
		//	i.c.ifi.Name,
		//	hello)
	}
	return err
}

func (a *Area) ospfPktHeader(fn func(p *packet2.LayerOSPFv2)) layers.OSPFv2 {
	ret := layers.OSPFv2{
		OSPF: layers.OSPF{
			Version:  2,
			Type:     0,
			RouterID: a.ins.RouterId,
			AreaID:   a.AreaId,
		},
		AuType:         0,
		Authentication: 0,
	}
	fn((*packet2.LayerOSPFv2)(&ret))
	return ret
}
