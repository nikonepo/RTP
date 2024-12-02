package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type UDPBasedProtocol struct {
	udpConn    *net.UDPConn
	remoteAddr *net.UDPAddr
}

// Конструктор для создания UDPBasedProtocol
func NewUDPBasedProtocol(localAddr, remoteAddr string) (*UDPBasedProtocol, error) {
	// Парсим локальный адрес
	localUDPAddr, err := net.ResolveUDPAddr("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("ошибка при парсинге локального адреса: %v", err)
	}

	// Парсим удалённый адрес
	remoteUDPAddr, err := net.ResolveUDPAddr("udp", remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("ошибка при парсинге удалённого адреса: %v", err)
	}

	// Открываем UDP сокет
	udpConn, err := net.ListenUDP("udp", localUDPAddr)
	if err != nil {
		return nil, fmt.Errorf("ошибка при создании сокета: %v", err)
	}

	return &UDPBasedProtocol{
		udpConn:    udpConn,
		remoteAddr: remoteUDPAddr,
	}, nil
}

// Отправка данных через UDP
func (p *UDPBasedProtocol) SendTo(data []byte) (int, error) {
	return p.udpConn.WriteToUDP(data, p.remoteAddr)
}

// Получение данных через UDP
func (p *UDPBasedProtocol) RecvFrom(n int) ([]byte, error) {
	p.udpConn.SetReadDeadline(time.Now().Add(TIMEOUT))
	buffer := make([]byte, n)
	nRead, _, err := p.udpConn.ReadFromUDP(buffer)
	p.udpConn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}
	return buffer[:nRead], nil
}

// Закрытие соединения
func (p *UDPBasedProtocol) Close() error {
	return p.udpConn.Close()
}

type FakeTCPConn struct {
	protocol *Protocol
	buffer   bytes.Buffer
	addr     net.Addr
}

func (w *FakeTCPConn) Read(p []byte) (n int, err error) {
	if w.buffer.Len() == 0 {
		data, err := w.protocol.Recv(len(p))
		if err != nil {
			return 0, err
		}
		w.buffer.Write(data)
	}
	return w.buffer.Read(p)
}

func (w *FakeTCPConn) Write(p []byte) (n int, err error) {
	return w.protocol.Send(p)
}

func (w *FakeTCPConn) Close() error {
	return w.protocol.base.Close()
}

func (w *FakeTCPConn) LocalAddr() net.Addr {
	return w.addr
}

func (w *FakeTCPConn) RemoteAddr() net.Addr {
	return w.addr
}

func (w *FakeTCPConn) SetDeadline(t time.Time) error {
	return nil
}

func (w *FakeTCPConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (w *FakeTCPConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func NewTLSClient(protocol *Protocol, config *tls.Config) (*tls.Conn, error) {
	wrapper := &FakeTCPConn{
		protocol: protocol,
		addr:     protocol.base.remoteAddr,
	}
	return tls.Client(wrapper, config), nil
}

func NewTLSServer(protocol *Protocol, config *tls.Config) (*tls.Conn, error) {
	wrapper := &FakeTCPConn{
		protocol: protocol,
		addr:     protocol.base.remoteAddr,
	}
	return tls.Server(wrapper, config), nil
}
