package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ping/ping"
	"github.com/gocolly/colly/v2"
)

var publicYggdrasilPeersURL = "https://publicpeers.neilalexander.dev/"

var wg sync.WaitGroup

// YggdrasilIPAddress represents an yggdrasil IP address with additional information.
type YggdrasilIPAddress struct {
	FullIPAddress string
	IPAddress     string
	latency       float64
}

func getPeers() string {
	c := colly.NewCollector()
	var ipAddresses []YggdrasilIPAddress

	c.OnHTML(".statusup #address", func(e *colly.HTMLElement) {
		result := strings.ReplaceAll(e.Text, "tls://", "")
		result = strings.ReplaceAll(result, "tcp://", "")
		result = strings.ReplaceAll(result, "[", "")
		result = strings.ReplaceAll(result, "]", "")
		splitResult := strings.Split(result, ":")
		finalResult := strings.ReplaceAll(result, ":"+splitResult[len(splitResult)-1], "")

		ipAddr := YggdrasilIPAddress{
			FullIPAddress: e.Text,
			IPAddress:     finalResult,
			latency:       9999,
		}

		ipAddresses = append(ipAddresses, ipAddr)
	})

	c.Visit(publicYggdrasilPeersURL)

	for index := 0; index < len(ipAddresses); index++ {
		wg.Add(1)
		go pingAddress(&ipAddresses[index])
	}

	wg.Wait()

	sort.Slice(ipAddresses, func(i, j int) bool {
		return ipAddresses[i].latency < ipAddresses[j].latency
	})

	return fmt.Sprintf("  Peers: [\"%s\", \"%s\", \"%s\"]", ipAddresses[0].FullIPAddress, ipAddresses[1].FullIPAddress, ipAddresses[2].FullIPAddress)
}

func main() {
	fmt.Println(getPeers())
}

func pingAddress(addr *YggdrasilIPAddress) {
	pinger, err := ping.NewPinger(addr.IPAddress)
	pinger.Timeout = time.Second / 2

	if err != nil {
		panic(err)
	}
	pinger.Count = 6
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		panic(err)
	}
	stats := pinger.Statistics() // get send/receive/rtt stats

	if stats.AvgRtt.String() == "0s" {
		addr.latency = 9999
		defer wg.Done()
		return
	}

	addr.latency, _ = strconv.ParseFloat(strings.ReplaceAll(stats.AvgRtt.String(), "ms", ""), 64)
	defer wg.Done()
}
