package snmp

import (
	"encoding/asn1"
	"fmt"
	//"math/rand"
	"net"
	//"time"
)

type Receiver struct {
	ln        net.Listener
	Community string
	handler   func(*TrapV2, *TrapV1, net.Addr, error) // net.Addr is the remote network address
}

// local network address laddr, pass empty laddr to Listen on UDP port 162 on all interfaces.
func NewReceiver(laddr, community string, handler func(*TrapV2, *TrapV1, net.Addr, error)) (*Receiver, error) {
	receiver := &Receiver{Community: community, handler: handler}

	var err error
	if len(laddr) == 0 {
		receiver.ln, err = net.Listen("udp", ":162")
	} else {
		receiver.ln, err = net.Listen("udp", laddr)
	}
	return receiver, err
}

func (s *Receiver) Close() {
	if s.ln != nil {
		s.ln.Close()
		s.ln = nil
	}
}

func (s *Receiver) Accept() {
	for s.ln != nil {
		conn, err := s.ln.Accept()
		if err != nil {
			// handle error
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Receiver) handleConnection(conn net.Conn) {
	buf := make([]byte, 65536, 65536) // TODO freelist
	defer conn.Close()
	conn.Read(buf)

	n, err := conn.Read(buf)
	if err != nil {
		if s.handler != nil {
			s.handler(nil, nil, conn.RemoteAddr(), err)
		}
		return
	}
	if n == len(buf) {
		if s.handler != nil {
			s.handler(nil, nil, conn.RemoteAddr(), fmt.Errorf("response too big"))
		}
		return
	}

	var snmpInform struct {
		Version   int
		Community []byte
		Data      struct {
			RequestID   int32
			ErrorStatus int
			ErrorIndex  int
			Bindings    []Binding
		} `asn1:"application,tag:6"` // 6 is SNMP inform-request, rfc1905
	}

	if _, err = asn1.Unmarshal(buf[:n], &snmpInform); err == nil {
		// receive SNMP inform-request
		var response struct {
			Version   int
			Community []byte
			Data      struct {
				RequestID   int32
				ErrorStatus int
				ErrorIndex  int
				Bindings    []Binding
			} `asn1:"application,tag:2"` // 2 is SNMP response, rfc1905
		}
		response.Version = snmpInform.Version
		response.Community = snmpInform.Community
		response.Data.RequestID = snmpInform.Data.RequestID
		var outBuf []byte
		outBuf, err = asn1.Marshal(response)
		if _, err := conn.Write(outBuf); err != nil {
			//return nil, nil, err
		}
		// treat SNMP Inform as Trap
		inform := &TrapV2{snmpInform.Data.RequestID, snmpInform.Data.ErrorStatus, snmpInform.Data.ErrorIndex, snmpInform.Data.Bindings}
		s.handler(inform, nil, conn.RemoteAddr(), nil)
		return
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
			s.handler(nil, nil, conn.RemoteAddr(), err)
		} else {
			trap := &TrapV1{
				Enterprise:   snmpV1trap.Data.Enterprise,
				AgentAddr:    snmpV1trap.Data.AgentAddr,
				GenericTrap:  snmpV1trap.Data.GenericTrap,
				SpecificTrap: snmpV1trap.Data.SpecificTrap,
				Timestamp:    snmpV1trap.Data.Timestamp,
				Bindings:     snmpV1trap.Data.Bindings}
			s.handler(nil, trap, conn.RemoteAddr(), nil)
		}
	}
	trap := &TrapV2{snmpV2trap.Data.RequestID, snmpV2trap.Data.ErrorStatus, snmpV2trap.Data.ErrorIndex, snmpV2trap.Data.Bindings}
	s.handler(trap, nil, conn.RemoteAddr(), nil)
}
