package snmp

import (
	"encoding/asn1"
	"fmt"
	//"math/rand"
	"net"
	//"time"
)

type SnmpReceiver struct {
	ln net.Listener
}

func (s *SnmpReceiver) Listen(laddr ...string) (err error) {
	if len(laddr) == 0 {
		s.ln, err = net.Listen("udp", ":162")
	} else {
		s.ln, err = net.Listen("udp", laddr[0])
	}
	return
}

func (s *SnmpReceiver) Accept() {
	for s.ln != nil {
		conn, err := s.ln.Accept()
		if err != nil {
			// handle error
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SnmpReceiver) handleConnection(conn net.Conn) (*TrapV2, *TrapV1, error) {
	buf := make([]byte, 65536, 65536) // TODO freelist
	conn.Read(buf)

	n, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}
	if n == len(buf) {
		return nil, nil, fmt.Errorf("response too big")
	}

	var snmpV2trap struct {
		Version   int
		Community []byte
		Data      struct {
			RequestID   int32
			ErrorStatus int
			ErrorIndex  int
			Bindings    []Binding
		} `asn1:"application,tag:7"` // 7 is SNMP v2c trap, rfc1905
	}

	if _, err = asn1.Unmarshal(buf[:n], &snmpV2trap); err != nil {
		var snmpV1trap struct {
			Version   int
			Community []byte
			Data      struct {
				Enterprise   asn1.ObjectIdentifier // OBJECT IDENTIFIER
				AgentAddr    int32                 // NetworkAddress
				GenericTrap  int                   // INTEGER 0-6
				SpecificTrap int
				Timestamp    TimeTicks // TimeTicks 0, 4294967295
				Bindings     []Binding
			} `asn1:"application,tag:4"` // 4 is SNMP v1 trap (deprecated)
		}

		if _, err = asn1.Unmarshal(buf[:n], &snmpV1trap); err != nil {
			return nil, nil, err
		} else {
			// TODO handle SNMPv1 trap
			trap := &TrapV1{
				Enterprise:   snmpV1trap.Data.Enterprise,
				AgentAddr:    snmpV1trap.Data.AgentAddr,
				GenericTrap:  snmpV1trap.Data.GenericTrap,
				SpecificTrap: snmpV1trap.Data.SpecificTrap,
				Timestamp:    snmpV1trap.Data.Timestamp,
				Bindings:     snmpV1trap.Data.Bindings}
			return nil, trap, nil
		}
	} else {
		// send SNMP inform-request
		var p struct {
			Version   int
			Community []byte
			Data      struct {
				RequestID   int32
				ErrorStatus int
				ErrorIndex  int
				Bindings    []Binding
			} `asn1:"application,tag:6"` // 6 is SNMP inform-request, rfc1905
		}
		p.Version = snmpV2trap.Version
		p.Community = snmpV2trap.Community
		p.Data.RequestID = snmpV2trap.Data.RequestID
		var outBuf []byte
		outBuf, err = asn1.Marshal(p)
		if _, err := conn.Write(outBuf); err != nil {
			return nil, nil, err
		}
	}
	trap := &TrapV2{snmpV2trap.Data.RequestID, snmpV2trap.Data.ErrorStatus, snmpV2trap.Data.ErrorIndex, snmpV2trap.Data.Bindings}
	return trap, nil, nil
}
