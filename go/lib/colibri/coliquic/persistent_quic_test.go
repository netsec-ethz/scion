// Copyright 2022 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package coliquic

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestInvariantColibriRepresentation(t *testing.T) {
	colPath := newTestColibriPath()
	copy(colPath.PacketTimestamp[:], []byte{0, 1, 2, 3, 4, 5, 6, 7})
	colPath.InfoField.OrigPayLen = 12345
	buff := make([]byte, colPath.Len())
	err := colPath.SerializeTo(buff)
	require.NoError(t, err)

	// representation of the original
	repr1 := invariantColibri(buff)

	// modify timestamp and orig payload length and obtain the representation again
	copy(colPath.PacketTimestamp[:], []byte{10, 11, 12, 13, 14, 15, 16, 17})
	colPath.InfoField.OrigPayLen = 11111
	err = colPath.SerializeTo(buff)
	require.NoError(t, err)
	repr2 := invariantColibri(buff)

	require.Equal(t, repr1, repr2)
}

// TestPersistentClientWithPersistentServer creates a persistent server and a persistent client
// and uses them at the same time.
func TestPersistentClientWithPersistentServer(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	thisNet := newMockNetwork(t)

	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquictest"},
	}
	dialer := NewPersistentQUIC(
		newConnMock(t, mockScionAddress(t, "1-ff00:0:111", "127.0.0.1:26345"), thisNet),
		clientTlsConfig, nil)
	require.Len(t, dialer.sessions, 0)

	clientWg := sync.WaitGroup{}
	runClient := func(serverAddr net.Addr, msg string) {
		clientWg.Add(1)
		// run the client
		go func() {
			defer clientWg.Done()
			conn, err := dialer.Dial(ctx, serverAddr)
			require.NoError(t, err, "failed for: %s", msg)
			n, err := io.WriteString(conn, msg)
			require.NoError(t, err, "failed for: %s", msg)
			require.Greater(t, n, 0, "failed for: %s", msg)
			err = conn.Close()
			require.NoError(t, err, "failed for: %s", msg)
		}()
	}

	server1Addr := mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.111:20001",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	server2Addr := mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.111:20002",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	messagesServer1 := make(chan string)
	messagesServer2 := make(chan string)
	stop1 := make(chan struct{})
	stop2 := make(chan struct{})
	go runListenerDefaultConfig(t, thisNet, server1Addr, messagesServer1, "server 1", stop1)
	go runListenerDefaultConfig(t, thisNet, server2Addr, messagesServer2, "server 2", stop2)
	runClient(server1Addr, "hello 1 from client 1")
	runClient(server1Addr, "hello 1 from client 2")
	runClient(server2Addr, "hello 2 from client 1")
	runClient(server2Addr, "hello 2 from client 2")
	require.NoError(t, waitWithContext(ctx, &clientWg))
	// read the messages from the clients
	readMsgs := func(serverNumber int, clientCount int) {
		// this function will read the appropriate channel depending on the serverNumber, and
		// will check that exactly clientCount distinct valid messages are read.
		var ch chan string
		switch serverNumber {
		case 1:
			ch = messagesServer1
		case 2:
			ch = messagesServer2
		default:
			require.FailNow(t, "bad test")
		}

		messages := make(map[string]struct{})
		for i := 0; i < clientCount; i++ {
			select {
			case <-ctx.Done():
				require.FailNow(t, "timeout for msg")
			case msg := <-ch:
				parts := strings.Split(msg, " ")
				require.Equal(t, parts[0], "hello")
				require.Equal(t, parts[1], strconv.Itoa(serverNumber))
				require.Equal(t, parts[2], "from")
				require.Equal(t, parts[3], "client")
				idx, err := strconv.Atoi(parts[4])
				require.NoError(t, err)
				require.Greater(t, idx, 0)
				require.LessOrEqual(t, idx, clientCount)
				require.NotContains(t, messages, msg)
				messages[msg] = struct{}{}
			}
		}
	}
	readMsgs(1, 2)
	readMsgs(2, 2)
	stop1 <- struct{}{}
	stop2 <- struct{}{}
}

// TestListenerManySessions is a multi part test that checks the listener for proper behavior.
// - part 1 tests listening without any sessions yet.
// - part 2 reuses the previous session
// - part 3 opens a new session
// - part 4 closes first session and opens a new stream w/ second session
// - part 5 closes second and only remaining session, opens a new one
// - part 6: closes listener and accept should return an error
func TestListenerManySessions(t *testing.T) {
	wgServer := sync.WaitGroup{}
	thisNet := newMockNetwork(t)
	serverAddr := mockScionAddress(t, "1-ff00:0:110", "127.0.0.1:10001")
	wgServer.Add(1)
	messagesReceivedAtServer := make(chan string)
	go func() { // server
		defer wgServer.Done()
		pconn := newConnMock(t, serverAddr, thisNet)
		serverTlsConfig := &tls.Config{
			Certificates: []tls.Certificate{*createTestCertificate(t)},
			NextProtos:   []string{"coliquictest"},
		}
		listener := NewListener(pconn, serverTlsConfig, nil)
		// keep track of sessions and streams
		sessions := make(map[quic.Session]struct{})
		streams := make(map[quic.Stream]struct{})
		expectedSessionsPerPart := []int{1, 1, 2, 2, 3}
		// parts 1-5
		for i, expectedSessions := range expectedSessionsPerPart {
			conn, err := listener.Accept()
			require.NoError(t, err)
			buff2, err := io.ReadAll(conn)
			require.NoError(t, err)
			msg := string(buff2)
			c := conn.(*streamAsConn)
			sessions[c.session] = struct{}{}
			streams[c.stream] = struct{}{}
			require.Len(t, sessions, expectedSessions, "wrong number of sessions")
			require.Len(t, streams, i+1)
			messagesReceivedAtServer <- msg
		}
		// part 6
		err := listener.Close()
		require.NoError(t, err)
		conn, err := listener.Accept()
		require.Nil(t, conn)
		require.Error(t, err)
	}()
	// client
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	clientAddr := mockScionAddress(t, "1-ff00:0:111", "127.0.0.1:1234")
	pconn := newConnMock(t, clientAddr, thisNet)
	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquictest"},
	}
	// useful func to read or timeout
	messageFromServer := func() string {
		select {
		case <-ctx.Done():
			return "context deadline exceeded: no message from server"
		case msg := <-messagesReceivedAtServer:
			return msg
		}
	}
	// part 1
	t.Log("-------------------- part 1")
	sess1, err := quic.DialContext(ctx, pconn, serverAddr, "serverName", clientTlsConfig, nil)
	require.NoError(t, err)
	stream, err := sess1.OpenStream()
	require.NoError(t, err)
	msg := "hello server 1"
	_, err = stream.Write([]byte(msg))
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	require.Equal(t, msg, messageFromServer())
	// part 2
	t.Log("-------------------- part 2")
	stream, err = sess1.OpenStream()
	require.NoError(t, err)
	msg = "hello server 2"
	_, err = stream.Write([]byte(msg))
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	require.Equal(t, msg, messageFromServer())
	// part 3
	t.Log("-------------------- part 3")
	sess2, err := quic.DialContext(ctx, pconn, serverAddr, "serverName", clientTlsConfig, nil)
	require.NoError(t, err)
	stream, err = sess2.OpenStream()
	require.NoError(t, err)
	msg = "hello server 3"
	_, err = stream.Write([]byte(msg))
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	require.Equal(t, msg, messageFromServer())
	// part 4
	t.Log("-------------------- part 4")
	err = sess1.CloseWithError(quic.ApplicationErrorCode(0), "")
	require.NoError(t, err)
	stream, err = sess2.OpenStream()
	require.NoError(t, err)
	msg = "hello server 4"
	_, err = stream.Write([]byte(msg))
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	require.Equal(t, msg, messageFromServer())
	// part 5
	t.Log("-------------------- part 5")
	err = sess2.CloseWithError(quic.ApplicationErrorCode(0), "")
	require.NoError(t, err)
	sess3, err := quic.DialContext(ctx, pconn, serverAddr, "serverName", clientTlsConfig, nil)
	require.NoError(t, err)
	stream, err = sess3.OpenStream()
	require.NoError(t, err)
	msg = "hello server 5"
	_, err = stream.Write([]byte(msg))
	require.NoError(t, err)
	err = stream.Close()
	require.NoError(t, err)
	require.Equal(t, msg, messageFromServer())
	// part 6 is server only
	// wait for server to shutdown
	require.NoError(t, waitWithContext(ctx, &wgServer))
}

// TestSingleSession checks that only one session is created per path.
// Mimic the tiny topology, and attempt to connect from 111 to 110 and 112
// This test is a multipart one:
// - part 1: use one path to go to 110. Expect 1 session.
// - part 2: use a different one to go to 112. Expect 2 sessions (1 from part 1, one from here).
// - part 3: use 50 times the same paths to go again to 110. Expect 2 sessions (part 1 and 2).
func TestSingleSession(t *testing.T) {
	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()
	thisNet := newMockNetwork(t)
	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquictest"},
	}

	dialer := NewPersistentQUIC(
		newConnMock(t, mockScionAddress(t, "1-ff00:0:111", "127.0.0.1:22345"), thisNet),
		clientTlsConfig, nil)
	require.Len(t, dialer.sessions, 0)

	messages := make(chan string)
	runPersistentServer := func(serverAddr net.Addr, msg string, stopServer chan struct{}) {
		// health of the test itself: no previous path should be present in the dialer
		repr, err := addrToString(serverAddr)
		require.NoError(t, err, "problem within test, could not represent addr/path")
		_, ok := dialer.sessions[repr]
		require.False(t, ok, "problem within test, addr/path already present (should not call"+
			"twice runPersistentServer for the same addr/path)")
		go runListenerDefaultConfig(t, thisNet, serverAddr, messages, msg, stopServer)
	}

	clientWg := sync.WaitGroup{}
	runClient := func(serverAddr net.Addr, sessions int, msg string) {
		clientWg.Add(1)
		// run the client
		go func() {
			defer clientWg.Done()
			conn, err := dialer.Dial(ctx, serverAddr)
			require.NoError(t, err, "failed for: %s", msg)
			require.Len(t, dialer.sessions, sessions, "failed for: %s", msg)
			n, err := io.WriteString(conn, msg)
			require.NoError(t, err, "failed for: %s", msg)
			require.Greater(t, n, 0, "failed for: %s", msg)
			err = conn.Close()
			require.NoError(t, err, "failed for: %s", msg)
			select {
			case <-ctx.Done():
				require.FailNow(t, "timeout", "for msg %s", msg)
			case <-messages:
			}
		}()
	}

	stop := make(chan struct{})
	// to 110 with scion
	t.Log("to 110 with scion")
	dst := mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.1:20001",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	runPersistentServer(dst, "server 110", stop)
	runClient(dst, 1, "hello 110")
	require.NoError(t, waitWithContext(ctx, &clientWg))

	// to 112 with scion
	t.Log("to 112 with scion")
	dst = mockScionAddressWithPath(t, "1-ff00:0:112", "127.0.0.1:20002",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110", 2, 1, "1-ff00:0:112")
	runPersistentServer(dst, "server 112", stop)
	runClient(dst, 2, "hello 112")
	require.NoError(t, waitWithContext(ctx, &clientWg))

	// to 110 again with several connections
	t.Log("to 110 again with several connections")
	dst = mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.1:20001",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	for i := 0; i < 50; i++ {
		runClient(dst, 2, fmt.Sprintf("hello 110 again %d", i))
	}
	require.NoError(t, waitWithContext(ctx, &clientWg))
	stop <- struct{}{}
	stop <- struct{}{}
}

// TestTooManyStreams checks that the persistent quic can connect to the destination even
// in the case when too many streams have been created for a stream.
func TestTooManyStreams(t *testing.T) {
	const maxIncomingStreams = 1000
	thisNet := newMockNetwork(t)
	serverAddr := mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.1:30001",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	messages := make(chan string)
	serverQuicConfig := &quic.Config{
		KeepAlive:          true,
		MaxIncomingStreams: maxIncomingStreams,
	}
	stop := make(chan struct{})
	go runListenerWithConfig(t, thisNet, serverAddr, messages, "theserver", serverQuicConfig, stop)

	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquictest"},
	}
	dialer := NewPersistentQUIC(
		newConnMock(t, mockScionAddress(t, "1-ff00:0:111", "127.0.0.1:32345"), thisNet),
		clientTlsConfig, nil)

	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	conns := make([]net.Conn, 0)
	connsM := sync.Mutex{}
	wgClients := sync.WaitGroup{}
	sessions := make(map[quic.Session]struct{})
	runClient := func(id int) {
		wgClients.Add(1)
		go func() {
			defer wgClients.Done()
			conn, err := dialer.Dial(ctx, serverAddr)
			require.NoError(t, err)
			n, err := io.WriteString(conn, "message from client")
			require.NoError(t, err, "failed for: %s", id)
			require.Greater(t, n, 0, "failed for: %s", id)

			require.IsType(t, streamAsConn{}, conn)
			c := conn.(streamAsConn)

			connsM.Lock()
			sessions[c.session] = struct{}{}
			conns = append(conns, conn)
			connsM.Unlock()
			// do not close the stream
		}()
	}

	N := 5000 // 5000 simultaneous streams to the same destination
	for i := 0; i < N; i++ {
		runClient(i)
	}
	// read the N messages
	for i := 0; i < N; i++ {
		<-messages
	}
	require.NoError(t, waitWithContext(ctx, &wgClients))
	require.Len(t, dialer.sessions, 1) // active
	require.Len(t, conns, N)
	// check that we have used more than one session, but only one is active
	require.Len(t, sessions, N/maxIncomingStreams)

	// check that all connections are still working
	for i := 0; i < N; i++ {
		_, err := io.WriteString(conns[i], fmt.Sprintf("hello %d", i))
		require.NoError(t, err)
	}
	uniqueMsgs := make(map[string]struct{})
	for i := 0; i < N; i++ {
		msg := <-messages
		uniqueMsgs[msg] = struct{}{}
	}
	require.Len(t, uniqueMsgs, N)

	// close all connections
	for i, c := range conns {
		err := c.Close()
		require.NoError(t, err, "closing connection number %d", i)
	}
	stop <- struct{}{}
}

func TestCloseSession(t *testing.T) {
	const maxIncomingStreams = 10
	thisNet := newMockNetwork(t)
	serverAddr := mockScionAddressWithPath(t, "1-ff00:0:110", "127.0.0.212:30001",
		"1-ff00:0:111", 41, 1, "1-ff00:0:110")
	messages := make(chan string)
	serverQuicConfig := &quic.Config{
		KeepAlive:          true,
		MaxIncomingStreams: maxIncomingStreams,
	}
	stop := make(chan struct{})
	go runListenerWithConfig(t, thisNet, serverAddr, messages, "theserver", serverQuicConfig, stop)

	clientTlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"coliquictest"},
	}
	dialer := NewPersistentQUIC(
		newConnMock(t, mockScionAddress(t, "1-ff00:0:111", "127.0.0.122:32345"), thisNet),
		clientTlsConfig, nil)

	ctx, cancelF := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelF()

	mu := sync.Mutex{}
	conns := make([]net.Conn, 0)
	sessions := make(map[quic.Session]struct{})
	wgClients := sync.WaitGroup{}
	runClient := func(id int) {
		wgClients.Add(1)
		go func() {
			defer wgClients.Done()
			conn, err := dialer.Dial(ctx, serverAddr)
			require.NoError(t, err)
			n, err := io.WriteString(conn, "message from client")
			require.NoError(t, err, "failed for: %s", id)
			require.Greater(t, n, 0, "failed for: %s", id)

			require.IsType(t, streamAsConn{}, conn)
			c := conn.(streamAsConn)

			mu.Lock()
			sessions[c.session] = struct{}{}
			conns = append(conns, conn)
			mu.Unlock()
			// do not close the stream
		}()
	}

	N := 50 // 50 simultaneous streams to the same destination
	for i := 0; i < N; i++ {
		runClient(i)
	}
	wgClients.Wait()
	for i := 0; i < N; i++ {
		_ = readChannel(t, ctx, messages)
	}

	type contexter interface {
		Context() context.Context
	}
	// all sessions are still open
	for s := range sessions {
		require.NoError(t, s.Context().Err())
	}
	// all connections are still open
	for _, c := range conns {
		cc, ok := c.(contexter)
		require.True(t, ok)
		require.NoError(t, cc.Context().Err())
	}
	// closing sessions and streams now
	err := dialer.Close()
	require.NoError(t, err)
	// all sessions should be closed
	for s := range sessions {
		require.Error(t, s.Context().Err())
		// if we try to open a stream we receive an error
		_, err := s.OpenStream()
		require.Error(t, err)
	}
	// all connections should be closed
	for _, c := range conns {
		cc, ok := c.(contexter)
		require.True(t, ok)
		require.Error(t, cc.Context().Err()) // it is closed
		// if we try to write we get an error
		_, err := c.Write([]byte("1"))
		require.Error(t, err)
	}
	stop <- struct{}{}
}

func waitWithContext(ctx context.Context, wg *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		wg.Wait()
	}()
	select {
	case <-ctx.Done():
		return fmt.Errorf("context deadline exceeded, wait group not finished")
	case <-done:
	}
	return nil
}

func readChannel(t *testing.T, ctx context.Context, ch chan string) string {
	var str string
	done := make(chan struct{})
	go func() {
		defer close(done)
		str = <-ch
	}()
	select {
	case <-ctx.Done():
		require.Fail(t, "context deadline exceeded")
	case <-done:
	}
	return str
}

func runListenerDefaultConfig(t *testing.T, theNet *mockNetwork, serverAddr net.Addr,
	messages chan string, serverId string, stopServer chan struct{}) {

	defaultQuicConfig := &quic.Config{
		KeepAlive: true,
	}
	runListenerWithConfig(t, theNet, serverAddr, messages, serverId, defaultQuicConfig, stopServer)
}

// runListenerWithConfig continuously accepts connections and spawns a new routine
// to read from each new connection. It will close the connection once it reads EOF.
// Each message read is copied to the string channel.
func runListenerWithConfig(t *testing.T, theNet *mockNetwork, serverAddr net.Addr,
	messages chan string, serverId string, config *quic.Config, stopServer chan struct{}) {

	serverTlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*createTestCertificate(t)},
		NextProtos:   []string{"coliquictest"},
	}

	listener := NewListener(newConnMock(t, serverAddr, theNet),
		serverTlsConfig, config)
	stopRequested := false
	go func() {
		for {
			conn, err := listener.Accept()
			if stopRequested {
				return
			}
			require.NoError(t, err, "failed for: %s", serverId)

			go func() {
				var buff [16384]byte
				for {
					n, err := conn.Read(buff[:])
					msg := string(buff[:n])
					if err == io.EOF {
						// close stream
						err = conn.Close()
						require.NoError(t, err)
						if n > 0 {
							messages <- msg
						}
						break
					}
					require.NoError(t, err, "failed for: %s", serverId)
					require.Greater(t, n, 0, "failed for: %s", serverId)
					messages <- msg
				}
			}()
		}
	}()

	<-stopServer
	stopRequested = true
	err := listener.Close()
	require.NoError(t, err)
}
