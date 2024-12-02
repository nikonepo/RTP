package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"os"
	"strconv"
)

func main() {
	os.Setenv("SSLKEYLOGFILE", "sslkey.log")

	// Проверяем, что передано достаточное количество аргументов
	if len(os.Args) < 7 {
		fmt.Println("Использование: <mode> <laddr> <lport> <msg_size> <raddr> <rport> [iterations]")
		os.Exit(1)
	}

	// Чтение аргументов
	mode := os.Args[1]
	laddr := os.Args[2]
	lport, err := strconv.Atoi(os.Args[3])
	if err != nil {
		fmt.Println("Ошибка: lport должен быть числом.")
		os.Exit(1)
	}
	msgSize, err := strconv.Atoi(os.Args[4])
	if err != nil {
		fmt.Println("Ошибка: msg_size должен быть числом.")
		os.Exit(1)
	}
	if msgSize <= 0 {
		fmt.Println("Ошибка: msg_size должен быть положительным числом.")
		os.Exit(1)
	}

	raddr := os.Args[5]
	rport, err := strconv.Atoi(os.Args[6])
	if err != nil {
		fmt.Println("Ошибка: rport должен быть числом.")
		os.Exit(1)
	}
	iterations := 1
	if len(os.Args) > 7 {
		iterations, err = strconv.Atoi(os.Args[7])
		if err != nil {
			fmt.Println("Ошибка: iterations должен быть числом.")
			os.Exit(1)
		}
	}

	fmt.Fprintf(os.Stderr, "Режим работы: %s\n", mode)
	fmt.Fprintf(os.Stderr, "Локальный адрес: %s\n", laddr)
	fmt.Fprintf(os.Stderr, "Локальный порт: %d\n", lport)
	fmt.Fprintf(os.Stderr, "Удалённый адрес: %s\n", raddr)
	fmt.Fprintf(os.Stderr, "Удалённый порт: %d\n", rport)
	fmt.Fprintf(os.Stderr, "Размер сообщения: %d байт\n", msgSize)

	// Проверяем режим работы
	if mode == "client" {
		cer, err := tls.LoadX509KeyPair("server.crt", "server.key")

		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка загрузки сертификата: %v\n", err)
			os.Exit(1)
		}

		protocol, err := NewProtocol(fmt.Sprintf("%s:%d", laddr, lport), fmt.Sprintf("%s:%d", raddr, rport))
		config := &tls.Config{
			Certificates:       []tls.Certificate{cer},
			InsecureSkipVerify: true,
		}
		tlsClient, err := NewTLSClient(protocol, config)

		if err != nil {
			fmt.Println("Ошибка")
			os.Exit(1)
		}

		// Используем msg_size для создания буфера
		buffer := make([]byte, msgSize)
		var data []byte
		for {
			n, err := os.Stdin.Read(buffer)
			if err != nil && err != io.EOF {
				fmt.Fprintf(os.Stderr, "Ошибка чтения: %v\n", err)
				return
			}
			if n == 0 {
				break
			}

			// Добавляем считанные данные в массив байт
			data = append(data, buffer[:n]...)
		}

		for i := 0; i < iterations; i++ {
			_, err := tlsClient.Write(data)
			//n, err := protocol.Send(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка посылки: %s\n", err)
				os.Exit(1)
			}
			//result, err := protocol.Recv(n)
			buffer := make([]byte, msgSize)
			_, err = tlsClient.Read(buffer)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка приема: %s\n", err)
				os.Exit(1)
			}
			os.Stdout.Write(buffer)
			os.Stdout.WriteString("\n")
		}
	} else if mode == "server" {
		cer, err := tls.LoadX509KeyPair("server.crt", "server.key")

		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка загрузки сертификата: %v\n", err)
			os.Exit(1)
		}

		protocol, err := NewProtocol(fmt.Sprintf("%s:%d", laddr, lport), fmt.Sprintf("%s:%d", raddr, rport))
		config := &tls.Config{
			Certificates: []tls.Certificate{cer},
		}
		tlsServer, err := NewTLSServer(protocol, config)

		if err != nil {
			fmt.Println("Ошибка: rport должен быть числом.")
			os.Exit(1)
		}
		for i := 0; i < iterations; i++ {
			//result, err := protocol.Recv(msgSize)
			result := make([]byte, msgSize)
			tlsServer.Read(result)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка приема: %s\n", err)
				os.Exit(1)
			}
			//n, err := protocol.Send(result)
			n, err := tlsServer.Write(result)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Ошибка посылки: %s\n", err)
				os.Exit(1)
			}
			fmt.Println(n)
		}
	} else {
		fmt.Println("Ошибка: mode должен быть 'client' или 'server'.")
		os.Exit(1)
	}

}
