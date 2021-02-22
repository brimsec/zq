package zng

import (
	"errors"
	"net"

	"github.com/brimsec/zq/zcode"
)

type TypeOfNet struct{}

func NewNet(s *net.IPNet) Value {
	return Value{TypeNet, EncodeNet(s)}
}

func EncodeNet(subnet *net.IPNet) zcode.Bytes {
	var b [32]byte
	ip := subnet.IP.To4()
	if ip != nil {
		copy(b[:], ip)
		if len(subnet.Mask) == 16 {
			copy(b[4:], subnet.Mask[12:])
		} else {
			copy(b[4:], subnet.Mask)
		}
		return b[:8]
	}
	copy(b[:], subnet.IP)
	copy(b[16:], subnet.Mask)
	return b[:]
}

func DecodeNet(zv zcode.Bytes) (*net.IPNet, error) {
	if zv == nil {
		return nil, nil
	}
	switch len(zv) {
	case 8:
		ip := net.IP(zv[:4])
		mask := net.IPMask(zv[4:])
		return &net.IPNet{
			IP:   ip,
			Mask: mask,
		}, nil
	case 32:
		ip := net.IP(zv[:16])
		mask := net.IPMask(zv[16:])
		return &net.IPNet{
			IP:   ip,
			Mask: mask,
		}, nil
	}
	return nil, errors.New("failure trying to decode IP subnet that is not 8 or 32 bytes long")
}

func (t *TypeOfNet) Parse(in []byte) (zcode.Bytes, error) {
	_, subnet, err := net.ParseCIDR(string(in))
	if err != nil {
		return nil, err
	}
	return EncodeNet(subnet), nil
}

func (t *TypeOfNet) ID() int {
	return IdNet
}

func (t *TypeOfNet) String() string {
	return "net"
}

func (t *TypeOfNet) Marshal(zv zcode.Bytes) (interface{}, error) {
	s, err := DecodeNet(zv)
	if err != nil {
		return nil, err
	}
	return (*s).String(), nil
}

func (t *TypeOfNet) ZSON() string {
	return "net"
}

func (t *TypeOfNet) ZSONOf(zv zcode.Bytes) string {
	s, err := DecodeNet(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	ipnet := net.IPNet(*s)
	return ipnet.String()
}
