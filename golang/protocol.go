package main

import (
	"bytes"
	"encoding/binary"
	"time"
)

type Protocol struct {
	base *UDPBasedProtocol
	seq  uint64
	ack  uint64
}

type Header struct {
	seq  uint64
	ack  uint64
	size uint64
	last bool
	data []byte
}

const FRAGMENT_SIZE = 512
const HEADER_SIZE = 25

const TIMEOUT = 3 * time.Millisecond
const MAX_ATTEMPTS = 180

// Конструктор для создания NewProtocol
func NewProtocol(localAddr, remoteAddr string) (*Protocol, error) {
	// Парсим локальный адрес
	base, err := NewUDPBasedProtocol(localAddr, remoteAddr)
	if err != nil {
		return nil, err
	}

	p := &Protocol{
		base: base,
		seq:  0,
		ack:  0,
	}

	return p, nil
}

func (p *Protocol) Send(data []byte) (int, error) {
	sentBytes := 0
	dataBytes := len(data)

	for sentBytes < dataBytes {
		fragment := &Header{}

		currSize := dataBytes - sentBytes
		if currSize > FRAGMENT_SIZE {
			currSize = FRAGMENT_SIZE
			fragment.size = uint64(currSize)
		} else {
			fragment.size = uint64(currSize)
			fragment.last = true
		}

		fragment.data = data[sentBytes:(sentBytes + currSize)]

		p.seq++

		fragment.seq = p.seq
		fragment.ack = p.ack

		attempts := 0

		packet := BytesFromPacket(fragment)
		for ; attempts < MAX_ATTEMPTS; attempts++ {
			_, _ = p.base.SendTo(packet)

			data, err := p.base.RecvFrom(HEADER_SIZE)
			if err != nil || len(data) <= 0 {
				continue
			}

			ackPacket := PacketFromBytes(data)
			if ackPacket.ack == p.seq {
				break
			}
		}

		sentBytes += currSize
	}

	return sentBytes, nil
}

func (p *Protocol) Recv(n int) ([]byte, error) {
	message := make([]byte, 0, n)

	for {
		data, err := p.base.RecvFrom(FRAGMENT_SIZE + HEADER_SIZE)
		if err != nil || len(data) <= 0 {
			continue
		}

		fragment := PacketFromBytes(data)

		if fragment.seq <= p.ack {
			p.SendAck(fragment.seq)
			continue
		}

		message = append(message, fragment.data...)

		p.ack++

		p.SendAck(p.ack)

		if fragment.last {
			break
		}
	}

	return message, nil
}

func (p *Protocol) SendAck(ack uint64) {
	packet := &Header{
		ack: ack,
	}

	p.base.SendTo(BytesFromPacket(packet))
}

func BytesFromPacket(packet *Header) []byte {
	buffer := new(bytes.Buffer)

	binary.Write(buffer, binary.BigEndian, packet.seq)
	binary.Write(buffer, binary.BigEndian, packet.ack)
	binary.Write(buffer, binary.BigEndian, packet.size)
	binary.Write(buffer, binary.BigEndian, packet.last)

	buffer.Write(packet.data[:])

	return buffer.Bytes()
}

func PacketFromBytes(data []byte) *Header {
	buffer := bytes.NewBuffer(data)

	packet := &Header{}
	binary.Read(buffer, binary.BigEndian, &packet.seq)
	binary.Read(buffer, binary.BigEndian, &packet.ack)
	binary.Read(buffer, binary.BigEndian, &packet.size)
	binary.Read(buffer, binary.BigEndian, &packet.last)

	packet.data = make([]byte, packet.size)
	buffer.Read(packet.data)

	return packet
}
