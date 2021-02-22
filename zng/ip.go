package zng

import (
	"errors"
	"net"

	"github.com/brimsec/zq/pkg/byteconv"
	"github.com/brimsec/zq/zcode"
)

type TypeOfIP struct{}

func NewIP(a net.IP) Value {
	return Value{TypeIP, EncodeIP(a)}
}

func EncodeIP(a net.IP) zcode.Bytes {
	ip := a.To4()
	if ip == nil {
		ip = net.IP(a)
	}
	return zcode.Bytes(ip)
}

func DecodeIP(zv zcode.Bytes) (net.IP, error) {
	if zv == nil {
		return nil, nil
	}
	switch len(zv) {
	case 4, 16:
		return net.IP(zv), nil
	}
	return nil, errors.New("failure trying to decode IP address that is not 4 or 16 bytes long")
}

func (t *TypeOfIP) Parse(in []byte) (zcode.Bytes, error) {
	ip, err := byteconv.ParseIP(in)
	if err != nil {
		return nil, err
	}
	return EncodeIP(ip), nil
}

func (t *TypeOfIP) ID() int {
	return IdIP
}

func (t *TypeOfIP) String() string {
	return "ip"
}

func (t *TypeOfIP) Marshal(zv zcode.Bytes) (interface{}, error) {
	ip, err := DecodeIP(zv)
	if err != nil {
		return nil, err
	}
	return ip.String(), nil
}

func (t *TypeOfIP) ZSON() string {
	return "ip"
}

func (t *TypeOfIP) ZSONOf(zv zcode.Bytes) string {
	ip, err := DecodeIP(zv)
	if err != nil {
		return badZng(err, t, zv)
	}
	return ip.String()
}
