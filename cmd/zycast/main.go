// conwrt-zycast — ZyXEL multicast flash utility
//
// Implements the ZyXEL Multiboot protocol for flashing firmware to ZyXEL
// devices (NR7101, etc.) via UDP multicast. Cross-compiles for MIPS, ARM,
// and x86_64 — designed to run directly on OpenWrt switches.
//
// Protocol: UDP multicast to 225.0.0.0:5631
//   - 30-byte header with magic "zyx\0"
//   - 1024-byte payload chunks
//   - Loops until interrupted (Ctrl-C or timeout)
//
// Based on zycast.c from openwrt/firmware-utils (GPL-2.0)
// Copyright (C) 2024 Bjørn Mork <bjorn@mork.no>
// Go implementation Copyright (C) 2026 Amperstrand
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	magic    uint32 = 0x7A797800 // "zyx\0" big-endian
	hdrSize         = 30
	chunkSize       = 1024
	defGroup        = "225.0.0.0"
	defPort         = 5631
	defPktDelay     = 10 * time.Millisecond
	// NR7101 dual-partition flash takes ~8-10 min for ~16MB.
	// We send 3 loops (3 × ~85s) then stop and wait for boot.
	defFlashLoops = 3

	typeBootbase byte = 0x01 // BIT(0)
	typeROM      byte = 0x02 // BIT(1)
	typeRAS      byte = 0x04 // BIT(2)
	typeROMD     byte = 0x08 // BIT(3)
	typeBackup   byte = 0x10 // BIT(4)
)

var imageTypes = map[string]byte{
	"bootbase": typeBootbase,
	"rom":      typeROM,
	"ras":      typeRAS,
	"romd":     typeROMD,
	"backup":   typeBackup,
}


func poeSetPort(port string, enable bool) error {
	action := "enable"
	if !enable {
		action = "disable"
	}
	payload := fmt.Sprintf(`{"port":"%s","action":"%s"}`, port, action)
	out, err := exec.Command("ubus", "call", "poe", "manage", payload).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ubus poe manage: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

type poePortInfo struct {
	Status string `json:"status"`
}

func poeGetPortStatus(port string) (string, error) {
	out, err := exec.Command("ubus", "call", "poe", "info").Output()
	if err != nil {
		return "", err
	}
	var info struct {
		Ports map[string]poePortInfo `json:"ports"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		return "", err
	}
	p, ok := info.Ports[port]
	if !ok {
		return "", fmt.Errorf("port %s not found in poe info", port)
	}
	return p.Status, nil
}

func powerCyclePort(port string, offDelay time.Duration) error {
	log.Printf("[poe] disabling port %s", port)
	if err := poeSetPort(port, false); err != nil {
		return fmt.Errorf("disable: %w", err)
	}
	log.Printf("[poe] waiting %v with port off", offDelay)
	time.Sleep(offDelay)
	log.Printf("[poe] re-enabling port %s", port)
	if err := poeSetPort(port, true); err != nil {
		return fmt.Errorf("enable: %w", err)
	}
	time.Sleep(3 * time.Second)
	st, err := poeGetPortStatus(port)
	if err != nil {
		log.Printf("[poe] warning: could not read status: %v", err)
	} else {
		log.Printf("[poe] port %s status: %s", port, st)
	}
	return nil
}


func pingAddr(addr string, timeout time.Duration) bool {
	deadline := int(timeout.Seconds())
	if deadline < 1 {
		deadline = 1
	}
	out, err := exec.Command("ping", "-c", "1", "-W", fmt.Sprintf("%d", deadline), addr).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "bytes from")
}

func waitForHost(addr string, interval, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if pingAddr(addr, interval) {
			return true
		}
		time.Sleep(interval)
	}
	return false
}


func zycastChecksum(data []byte) uint16 {
	var total uint32
	for _, b := range data {
		total += uint32(b)
	}
	return uint16((total>>16 + total) & 0xFFFF)
}

func bindToDevice(conn net.PacketConn, iface string) error {
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not a UDPConn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		setErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, 25, iface)
	})
	if err != nil {
		return err
	}
	return setErr
}

func setMulticastIF(conn net.PacketConn, iface string) error {
	ifaceObj, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q not found: %w", iface, err)
	}
	addrs, err := ifaceObj.Addrs()
	if err != nil {
		return fmt.Errorf("cannot get addresses for %q: %w", iface, err)
	}
	if len(addrs) == 0 {
		return fmt.Errorf("interface %q has no addresses", iface)
	}
	ipStr := addrs[0].String()
	ip, _, err := net.ParseCIDR(ipStr)
	if err != nil {
		ip = net.ParseIP(ipStr)
	}
	if ip == nil {
		return fmt.Errorf("cannot parse IP for %q", iface)
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("not a UDPConn")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	err = raw.Control(func(fd uintptr) {
		var mreq [12]byte
		binary.LittleEndian.PutUint32(mreq[8:12], uint32(ifaceObj.Index))
		setErr = syscall.SetsockoptString(int(fd), 0, 32, string(mreq[:]))
	})
	if err != nil {
		return err
	}
	return setErr
}

func sendLoops(conn net.PacketConn, addr *net.UDPAddr, imageData []byte, typeBit byte, maxLoops int, pktDelay time.Duration, stopCh <-chan struct{}) (int, error) {
	fileLen := uint32(len(imageData))
	totalChunks := (fileLen + chunkSize - 1) / chunkSize
	loopCount := 0
	totalSent := 0
	startTime := time.Now()

	for {
		loopCount++
		for offset := uint32(0); offset < fileLen; {
			end := offset + chunkSize
			if end > fileLen {
				end = fileLen
			}
			chunk := imageData[offset:end]
			chunkLen := uint32(len(chunk))
			pid := offset / chunkSize

			header := make([]byte, hdrSize)
			binary.BigEndian.PutUint32(header[0:4], magic)
			binary.BigEndian.PutUint16(header[4:6], zycastChecksum(chunk))
			binary.BigEndian.PutUint32(header[6:10], pid)
			binary.BigEndian.PutUint32(header[10:14], chunkLen)
			binary.BigEndian.PutUint32(header[14:18], fileLen)
			binary.BigEndian.PutUint16(header[18:20], 0)
			header[20] = typeBit
			header[21] = typeBit
			header[22] = 'F'
			header[23] = 'F'
			header[24] = 0x01

			packet := append(header, chunk...)
			if _, err := conn.WriteTo(packet, addr); err != nil {
				return totalSent, fmt.Errorf("send: %w", err)
			}

			offset = end
			totalSent++
			time.Sleep(pktDelay)

			select {
			case <-stopCh:
				return totalSent, nil
			default:
			}
		}

		elapsed := time.Since(startTime)
		rate := float64(totalSent) / elapsed.Seconds()
		log.Printf("[zycast] loop %d/%d complete (%d chunks, %.0f pkt/s, %v elapsed)",
			loopCount, maxLoops, totalChunks, rate, elapsed.Round(time.Second))

		if maxLoops > 0 && loopCount >= maxLoops {
			log.Printf("[zycast] sent %d loops, stopping", loopCount)
			return totalSent, nil
		}

		select {
		case <-stopCh:
			return totalSent, nil
		case <-time.After(200 * time.Millisecond):
		}
	}
}


func runFlash(args []string) {
	fs := flag.NewFlagSet("flash", flag.ExitOnError)
	iface := fs.String("i", "", "network interface (e.g. switch.1003)")
	poePort := fs.String("poe-port", "", "PoE port name for power cycle (e.g. lan3)")
	poeOffDelay := fs.Duration("poe-off", 5*time.Second, "PoE off duration before re-enable")
	imgType := fs.String("t", "ras", "image type: bootbase, rom, ras, romd, backup")
	flashLoops := fs.Int("loops", defFlashLoops, "number of zycast loops before stopping")
	pktDelayFlag := fs.Duration("delay", defPktDelay, "inter-packet delay")
	waitBoot := fs.Duration("wait-boot", 3*time.Minute, "max time to wait for device to boot after flash")
	bootIP := fs.String("boot-ip", "192.168.1.1", "IP address to check for OpenWrt boot detection")
	group := fs.String("g", defGroup, "multicast group address")
	port := fs.Int("p", defPort, "multicast port")
	noPowerCycle := fs.Bool("no-power-cycle", false, "skip PoE power cycle (device already booting)")
	fs.Parse(args)

	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "Usage: conwrt-zycast flash [options] <image>\n")
		fs.Usage()
		os.Exit(1)
	}
	imagePath := fs.Arg(0)

	if *iface == "" {
		log.Fatalf("error: -i (interface) is required for flash")
	}

	typeBit, ok := imageTypes[*imgType]
	if !ok {
		log.Fatalf("unknown image type: %s", *imgType)
	}

	imageData, err := os.ReadFile(imagePath)
	if err != nil {
		log.Fatalf("failed to read image: %v", err)
	}
	fileLen := uint32(len(imageData))
	chunks := (fileLen + chunkSize - 1) / chunkSize
	estTime := time.Duration(chunks) * *pktDelayFlag * time.Duration(*flashLoops)

	log.Printf("=== conwrt-zycast flash ===")
	log.Printf("image: %s (%d bytes, %d chunks, type=%s)", imagePath, fileLen, chunks, *imgType)
	log.Printf("iface: %s, dst: %s:%d", *iface, *group, *port)
	log.Printf("loops: %d, est send time: %v", *flashLoops, estTime.Round(time.Second))
	log.Printf("boot detection: %s (timeout %v)", *bootIP, *waitBoot)
	if *poePort != "" {
		log.Printf("poe port: %s (off delay %v)", *poePort, *poeOffDelay)
	}

	// Setup socket
	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *group, *port))
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	defer conn.Close()

	if err := bindToDevice(conn, *iface); err != nil {
		if err2 := setMulticastIF(conn, *iface); err2 != nil {
			log.Fatalf("cannot bind to %q: %v (fallback: %v)", *iface, err, err2)
		}
		log.Printf("bound via IP_MULTICAST_IF to %s", *iface)
	} else {
		log.Printf("bound to device %s", *iface)
	}

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Printf("[signal] stopping...")
		close(stopCh)
	}()

	log.Printf("--- power cycle ---")
	if *poePort != "" && !*noPowerCycle {
		if err := powerCyclePort(*poePort, *poeOffDelay); err != nil {
			log.Fatalf("PoE power cycle failed: %v", err)
		}
		log.Printf("[poe] device powered on, bootloader should be starting")
	} else if *noPowerCycle {
		log.Printf("[poe] skipping power cycle (--no-power-cycle)")
	}

	log.Printf("--- sending multicast ---")
	totalSent, err := sendLoops(conn, addr, imageData, typeBit, *flashLoops, *pktDelayFlag, stopCh)
	if err != nil {
		log.Fatalf("zycast send failed: %v", err)
	}
	log.Printf("[zycast] done: %d packets sent", totalSent)

	log.Printf("--- waiting for boot at %s ---", *bootIP)
	log.Printf("[boot] polling every 5s, timeout %v", *waitBoot)

	if waitForHost(*bootIP, 5*time.Second, *waitBoot) {
		log.Printf("")
		log.Printf("=== SUCCESS: device responding at %s ===", *bootIP)
		log.Printf("Try: ssh root@%s", *bootIP)
	} else {
		oldIP := "192.168.2.1"
		log.Printf("[boot] %s not responding, trying %s ...", *bootIP, oldIP)
		if pingAddr(oldIP, 3*time.Second) {
			log.Printf("")
			log.Printf("=== DEVICE AT OLD IP: %s (flash may have failed) ===", oldIP)
		} else {
			log.Printf("")
			log.Printf("=== TIMEOUT: no response from %s or %s ===", *bootIP, oldIP)
			log.Printf("The bootloader may need more time, or multicast was not received.")
			log.Printf("Try: increase --loops, check -i interface, or add serial for debug.")
		}
		os.Exit(1)
	}
}

func runSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	iface := fs.String("i", "", "network interface")
	group := fs.String("g", defGroup, "multicast group address")
	port := fs.Int("p", defPort, "multicast port")
	imgType := fs.String("t", "ras", "image type")
	timeout := fs.Duration("timeout", 0, "stop after duration (0 = until Ctrl-C)")
	loops := fs.Int("loops", 0, "stop after N loops (0 = unlimited)")
	pktDelayFlag := fs.Duration("delay", defPktDelay, "inter-packet delay")
	fs.Parse(args)

	if fs.NArg() != 1 || *iface == "" {
		fmt.Fprintf(os.Stderr, "Usage: conwrt-zycast send -i <iface> [options] <image>\n")
		fs.Usage()
		os.Exit(1)
	}

	typeBit, ok := imageTypes[*imgType]
	if !ok {
		log.Fatalf("unknown image type: %s", *imgType)
	}

	imageData, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	fileLen := uint32(len(imageData))
	log.Printf("image: %s (%d bytes), type=%s(0x%02x), dst=%s:%d, iface=%s",
		fs.Arg(0), fileLen, *imgType, typeBit, *group, *port, *iface)

	addr, _ := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", *group, *port))
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		log.Fatalf("socket: %v", err)
	}
	defer conn.Close()

	if err := bindToDevice(conn, *iface); err != nil {
		if err2 := setMulticastIF(conn, *iface); err2 != nil {
			log.Fatalf("bind: %v / %v", err, err2)
		}
		log.Printf("bound via IP_MULTICAST_IF to %s", *iface)
	} else {
		log.Printf("bound to device %s", *iface)
	}

	stopCh := make(chan struct{})
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		close(stopCh)
	}()

	// Wrap timeout into stopCh
	if *timeout > 0 {
		go func() {
			time.Sleep(*timeout)
			log.Printf("timeout reached, stopping")
			close(stopCh)
		}()
	}

	maxLoops := *loops
	if maxLoops == 0 {
		maxLoops = -1
	}

	total, err := sendLoops(conn, addr, imageData, typeBit, maxLoops, *pktDelayFlag, stopCh)
	if err != nil {
		log.Fatalf("send failed: %v", err)
	}
	log.Printf("done: %d total packets sent", total)
}

func runPoe(args []string) {
	fs := flag.NewFlagSet("poe", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() < 2 {
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  conwrt-zycast poe status\n")
		fmt.Fprintf(os.Stderr, "  conwrt-zycast poe off <port>\n")
		fmt.Fprintf(os.Stderr, "  conwrt-zycast poe on <port>\n")
		fmt.Fprintf(os.Stderr, "  conwrt-zycast poe cycle <port> [off-duration]\n")
		os.Exit(1)
	}

	cmd := fs.Arg(0)
	port := fs.Arg(1)

	switch cmd {
	case "status":
		st, err := poeGetPortStatus(port)
		if err != nil {
			log.Fatalf("error: %v", err)
		}
		fmt.Printf("%s: %s\n", port, st)

	case "on":
		if err := poeSetPort(port, true); err != nil {
			log.Fatalf("error: %v", err)
		}
		log.Printf("enabled PoE on %s", port)

	case "off":
		if err := poeSetPort(port, false); err != nil {
			log.Fatalf("error: %v", err)
		}
		log.Printf("disabled PoE on %s", port)

	case "cycle":
		dur := 5 * time.Second
		if fs.NArg() >= 3 {
			d, err := time.ParseDuration(fs.Arg(2))
			if err != nil {
				log.Fatalf("invalid duration: %v", err)
			}
			dur = d
		}
		if err := powerCyclePort(port, dur); err != nil {
			log.Fatalf("error: %v", err)
		}
		log.Printf("power cycle complete on %s", port)

	default:
		log.Fatalf("unknown poe command: %s (use: status, on, off, cycle)", cmd)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "conwrt-zycast — ZyXEL multicast flash utility\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  conwrt-zycast flash [options] <image>   — Full flash workflow\n")
	fmt.Fprintf(os.Stderr, "  conwrt-zycast send [options] <image>    — Send multicast only\n")
	fmt.Fprintf(os.Stderr, "  conwrt-zycast poe <cmd> <port> [args]   — PoE port control\n")
	fmt.Fprintf(os.Stderr, "\nRun 'conwrt-zycast <command> -h' for subcommand options.\n")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "flash":
		runFlash(os.Args[2:])
	case "send":
		runSend(os.Args[2:])
	case "poe":
		runPoe(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}
