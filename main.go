package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-ping/ping"
	"github.com/gocolly/colly/v2"
	"github.com/kardianos/minwinsvc"

	"github.com/atotto/clipboard"
	"golang.org/x/text/encoding/unicode"

	"github.com/gologme/log"
	gsyslog "github.com/hashicorp/go-syslog"
	"github.com/hjson/hjson-go"
	"github.com/mitchellh/mapstructure"
	"github.com/therecipe/qt/core"
	"github.com/therecipe/qt/gui"
	"github.com/therecipe/qt/widgets"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/admin"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/crypto"
	"github.com/yggdrasil-network/yggdrasil-go/src/module"
	"github.com/yggdrasil-network/yggdrasil-go/src/multicast"
	"github.com/yggdrasil-network/yggdrasil-go/src/tuntap"
	"github.com/yggdrasil-network/yggdrasil-go/src/version"
	"github.com/yggdrasil-network/yggdrasil-go/src/yggdrasil"
)

var publicYggdrasilPeersURL = "https://publicpeers.neilalexander.dev/"
var configPeers string

// IPAddress represents an ip adress.
var IPAddress net.IP

// IPSubnet represents a subnet.
var IPSubnet net.IPNet

var ipLabel *widgets.QLabel
var subnetLabel *widgets.QLabel
var debugLabel *widgets.QLabel
var connectionLabel *widgets.QLabel
var connectButton *widgets.QPushButton

var n node

var confjson *bool
var genconf *bool
var useconf *bool
var useconffile *string
var normaliseconf *bool
var autoconf *bool
var ver *bool
var logto *string
var getaddr *bool
var getsnet *bool
var loglevel *string

var wg sync.WaitGroup

var debug = true

// YggdrasilIPAddress represents an yggdrasil IP address with additional information.
type YggdrasilIPAddress struct {
	FullIPAddress string
	IPAddress     string
	latency       float64
}

// QSystemTrayIconWithCustomSlot represents a custom slot.
type QSystemTrayIconWithCustomSlot struct {
	widgets.QSystemTrayIcon

	_ func(f func()) `slot:"triggerSlot,auto"`
}

func (tray *QSystemTrayIconWithCustomSlot) triggerSlot(f func()) { f() }

type node struct {
	core      yggdrasil.Core
	state     *config.NodeState
	tuntap    module.Module
	multicast module.Module
	admin     module.Module
}

func debugLog(logMessage string) {
	if debug {
		fmt.Println("[Debug]: ", logMessage)
	}
}

func checkRoot() bool {
	debugLog("Checking permissions.")

	if getProcessOwner() == "root" {
		debugLog("We are root.")
		return true
	}

	debugLog("We are a regular user.")
	askPasswordAndExecuteAsRoot()

	return false
}

func askPasswordAndExecuteAsRoot() {
	debugLog("Opening dialog to ask the users password.")

	app := widgets.NewQApplication(len(os.Args), os.Args)
	app.SetWindowIcon(gui.NewQIcon5(":/qml/icon.ico"))

	var password = ""

	var widget = widgets.NewQWidget(nil, 0)
	var dialog = widgets.NewQInputDialog(widget, core.Qt__Dialog)

	dialog.SetWindowTitle("ThreeFold Network Connector")
	dialog.SetLabelText("ThreeFold Network Connector would like to automatically\nset up your connection to the ThreeFold Network.\n\nTo do this,  please provide the password for \"" + getUsername() + "\"")
	dialog.SetTextEchoMode(widgets.QLineEdit__Password)
	dialog.SetInputMethodHints(core.Qt__ImhNone)

	dialog.ConnectAccept(func() {
		debugLog("Confirming askPassword dialog.")
		password = dialog.TextValue()
		dialog.Close()
	})

	dialog.Exec()

	cleanupYggdrasilSock(password)
	elevateMyself(password)
}

func cleanupYggdrasilSock(password string) {
	debugLog("Cleaning up yggdrasil.sock.")

	cmd := "echo " + password + " | sudo -S rm -rf /var/run/yggdrasil.sock"
	_, err := exec.Command("bash", "-c", cmd).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func elevateMyself(password string) {
	debugLog("Executing myself as root.")
	cmd := "echo " + password + " | sudo -S " + getExecutingDirectory() + "/ThreeFoldNetworkConnector"

	rcmd := exec.Command("bash", "-c", cmd)
	err := rcmd.Start()

	if err != nil {
		fmt.Println(err)
	}
}

func getExecutingDirectory() string {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))

	if err != nil {
		log.Fatal(err)
	}

	return dir
}

func getUsername() string {
	cmd := "id -F"
	stdout, err := exec.Command("bash", "-c", cmd).Output()

	if err != nil {
		fmt.Println(err)
	}

	return strings.TrimSpace(string(stdout))
}

func getProcessOwner() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()

	if err != nil {
		fmt.Println(err)
	}

	return strings.TrimSpace(string(stdout))
}

func getConfigPeers() <-chan string {
	r := make(chan string)

	go func() {
		defer close(r)

		c := colly.NewCollector()
		var ipAddresses []YggdrasilIPAddress

		c.OnHTML(".statusup #address", func(e *colly.HTMLElement) {

			// Filtering out all tcp connections
			if strings.Contains(e.Text, "tcp://") {
				return
			}

			// Filtering out all ipv6 connections
			if strings.Contains(e.Text, "[") && strings.Contains(e.Text, "]") {
				return
			}

			// This also filters ipv6 incase we want it in the future.
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
			go pingAddress(ipAddresses[index])
		}

		wg.Wait()

		sort.Slice(ipAddresses, func(i, j int) bool {
			return ipAddresses[i].latency < ipAddresses[j].latency
		})

		r <- fmt.Sprintf("Peers: [\"%s\", \"%s\", \"%s\"]", ipAddresses[0].FullIPAddress, ipAddresses[1].FullIPAddress, ipAddresses[2].FullIPAddress)
	}()

	return r
}

func pingAddress(addr YggdrasilIPAddress) {
	pinger, _ := ping.NewPinger(addr.IPAddress)
	pinger.Timeout = time.Second / 2

	pinger.Count = 2
	pinger.Run()

	stats := pinger.Statistics()

	if stats.AvgRtt.String() == "0s" {
		addr.latency = 9999
		defer wg.Done()
		return
	}

	addr.latency, _ = strconv.ParseFloat(strings.ReplaceAll(stats.AvgRtt.String(), "ms", ""), 64)
	defer wg.Done()
}

func readConfig(useconf *bool, useconffile *string, normaliseconf *bool) *config.NodeConfig {

	var conf []byte
	var err error

	if *useconffile != "" {
		conf, err = ioutil.ReadFile(*useconffile)
	} else {
		conf, err = ioutil.ReadAll(os.Stdin)
	}

	if err != nil {
		//panic(err)
	}

	if bytes.Equal(conf[0:2], []byte{0xFF, 0xFE}) ||
		bytes.Equal(conf[0:2], []byte{0xFE, 0xFF}) {
		utf := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
		decoder := utf.NewDecoder()
		conf, err = decoder.Bytes(conf)
		if err != nil {
			//panic(err)
		}
	}

	cfg := config.GenerateConfig()
	var dat map[string]interface{}

	if err := hjson.Unmarshal(conf, &dat); err != nil {
		//panic(err)
	}

	if listen, ok := dat["Listen"].(string); ok {
		dat["Listen"] = []string{listen}
	}

	if tunnelrouting, ok := dat["TunnelRouting"].(map[string]interface{}); ok {
		if c, ok := tunnelrouting["IPv4Sources"]; ok {
			delete(tunnelrouting, "IPv4Sources")
			tunnelrouting["IPv4LocalSubnets"] = c
		}
		if c, ok := tunnelrouting["IPv6Sources"]; ok {
			delete(tunnelrouting, "IPv6Sources")
			tunnelrouting["IPv6LocalSubnets"] = c
		}
		if c, ok := tunnelrouting["IPv4Destinations"]; ok {
			delete(tunnelrouting, "IPv4Destinations")
			tunnelrouting["IPv4RemoteSubnets"] = c
		}
		if c, ok := tunnelrouting["IPv6Destinations"]; ok {
			delete(tunnelrouting, "IPv6Destinations")
			tunnelrouting["IPv6RemoteSubnets"] = c
		}
	}

	confJSON, err := json.Marshal(dat)

	if err != nil {
		// panic(err)
	}

	json.Unmarshal(confJSON, &cfg)

	if err = mapstructure.Decode(dat, &cfg); err != nil {
		// panic(err)
	}

	return cfg
}

func doGenconf(isjson bool) string {
	cfg := config.GenerateConfig()

	var bs []byte
	var err error

	if isjson {
		bs, err = json.MarshalIndent(cfg, "", "  ")
	} else {
		bs, err = hjson.Marshal(cfg)
	}

	if err != nil {
		// panic(err)
	}

	return string(bs)
}

func setLogLevel(loglevel string, logger *log.Logger) {
	levels := [...]string{"error", "warn", "info", "debug", "trace"}
	loglevel = strings.ToLower(loglevel)

	contains := func() bool {
		for _, l := range levels {
			if l == loglevel {
				return true
			}
		}
		return false
	}

	if !contains() {
		logger.Infoln("Loglevel parse failed. Set default level(info)")
		loglevel = "info"
	}

	for _, l := range levels {
		logger.EnableLevel(l)
		if l == loglevel {
			break
		}
	}
}

func userInterface() {
	app := widgets.NewQApplication(len(os.Args), os.Args)
	app.SetWindowIcon(gui.NewQIcon5(":/qml/icon.ico"))

	window := widgets.NewQMainWindow(nil, 0)

	window.SetMinimumSize2(600, 140)
	window.SetWindowTitle("ThreeFold network connector")

	widget := widgets.NewQWidget(nil, 0)
	widget.SetLayout(widgets.NewQVBoxLayout())
	window.SetCentralWidget(widget)

	systray := NewQSystemTrayIconWithCustomSlot(nil)
	systray.SetIcon(gui.NewQIcon5(":/qml/icon.ico"))

	systrayMenu := widgets.NewQMenu(nil)

	settingsMenuAction := systrayMenu.AddAction("Settings")
	settingsMenuAction.ConnectTriggered(func(bool) {
		println("Showing window ...")
		window.Show()
	})

	yggdrasilVersionMenuAction := systrayMenu.AddAction("Reset")
	yggdrasilVersionMenuAction.ConnectTriggered(func(bool) {
		resetApplication()
		widgets.QMessageBox_Information(nil, "ThreeFold network connector", "All the settings have been reset.\n The application will close itself. \n\n You can simply open it again.", widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		os.Exit(0)
	})

	quitMenuAction := systrayMenu.AddAction("Quit")
	quitMenuAction.ConnectTriggered(func(bool) {
		println("Exiting application ... ")
		app.Exit(0)
	})

	systray.SetContextMenu(systrayMenu)
	systray.Show()

	connectionState := false
	groupBox := widgets.NewQGroupBox2("Settings", nil)

	gridLayout := widgets.NewQGridLayout2()

	statusLabel := widgets.NewQLabel2("Connection status: ", nil, 0)
	connectionLabel = widgets.NewQLabel2("Disconnected", nil, 0)
	connectionLabel.SetStyleSheet("QLabel {color: red;}")

	connectButton = widgets.NewQPushButton2("Connect", nil)

	CopyIPButton := widgets.NewQPushButton2("Copy Ipv6", nil)
	copySubnetButton := widgets.NewQPushButton2("Copy Subnet", nil)

	CopyIPButton.ConnectClicked(func(bool) {
		clipboard.WriteAll(IPAddress.String())
	})

	copySubnetButton.ConnectClicked(func(bool) {
		clipboard.WriteAll(IPSubnet.String())
	})

	connectButton.ConnectClicked(func(bool) {
		connectButton.SetDisabled(true)

		if !connectionState {
			connectButton.SetText("Disconnect")
			ipLabel.SetText("...")
			subnetLabel.SetText("...")

			go submain()
			connectionState = true
			return
		}

		connectButton.SetText("Connect")

		connectionLabel.SetText("Disconnected")
		connectionLabel.SetStyleSheet("QLabel {color: red;}")

		connectionState = false

		ipLabel.SetText("N/A")
		subnetLabel.SetText("N/A")

		c := make(chan os.Signal, 1)
		r := make(chan os.Signal, 1)

		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		signal.Notify(r, os.Interrupt, syscall.SIGHUP)

		minwinsvc.SetOnExit(n.shutdown)
		defer n.shutdown()
	})

	gridLayout.AddWidget2(statusLabel, 0, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(connectionLabel, 0, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(connectButton, 0, 2, core.Qt__AlignRight)

	ipLabelInfo := widgets.NewQLabel2("Ipv6: ", nil, 0)
	subnetLabelInfo := widgets.NewQLabel2("Subnet: ", nil, 0)

	ipLabel = widgets.NewQLabel2("N/A", nil, 0)
	subnetLabel = widgets.NewQLabel2("N/A", nil, 0)
	debugLabel = widgets.NewQLabel2("Debug info", nil, 0)

	gridLayout.AddWidget2(ipLabelInfo, 2, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(ipLabel, 2, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(CopyIPButton, 2, 2, core.Qt__AlignRight)

	gridLayout.AddWidget2(subnetLabelInfo, 3, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(subnetLabel, 3, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(copySubnetButton, 3, 2, core.Qt__AlignRight)

	groupBox.SetLayout(gridLayout)
	widget.Layout().AddWidget(groupBox)

	window.ConnectCloseEvent(func(event *gui.QCloseEvent) {
		widgets.QMessageBox_Information(nil, "ThreeFold network connector", "The ThreeFold network connector will be minimized.", widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)
		window.Hide()
		event.Ignore()
	})

	window.Show()
	app.Exec()
}

func fileExists(filename string) bool {
	info, err := os.Stat(filename)

	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

func generateConfigFile(cfg *config.NodeConfig) {
	debugLog("Generating config file.")

	cfg = config.GenerateConfig()

	configFile := doGenconf(*confjson)
	configFile = strings.ReplaceAll(configFile, "Peers: []", configPeers)

	debugLog("Replaced peers.")

	f, err := os.Create("/etc/threefold_yggdrasil.conf")

	if err != nil {
		fmt.Println(err)
		return
	}

	l, err := f.WriteString(configFile)

	if err != nil {
		fmt.Println(err)
		f.Close()
		return
	}

	debugLog("Wrote " + strconv.Itoa(l) + " byte(s) to file.")
	err = f.Close()

	if err != nil {
		fmt.Println(err)
		return
	}
}

func resetApplication() {
	debugLog("Removing /var/run/yggdrasil.sock.")
	err := os.Remove("/var/run/yggdrasil.sock")

	if err != nil {
		fmt.Println(err)
	}

	debugLog("Removing /etc/threefold_yggdrasil.conf.")
	err = os.Remove("/etc/threefold_yggdrasil.conf")

	if err != nil {
		fmt.Println(err)
	}
}

func submain() {
	if confjson == nil {
		confjson = flag.Bool("json", false, "print configuration from -genconf or -normaliseconf as JSON instead of HJSON")
	}

	var cfg *config.NodeConfig
	var err error

	if !fileExists("/etc/threefold_yggdrasil.conf") {
		generateConfigFile(cfg)
	}

	if genconf == nil {
		genconf = flag.Bool("genconf", false, "print a new config to stdout")
	}

	if useconf == nil {
		useconf = flag.Bool("useconf", false, "read HJSON/JSON config from stdin")
	}

	if useconffile == nil {
		useconffile = flag.String("useconffile", "/etc/threefold_yggdrasil.conf", "read HJSON/JSON config from specified file path")
	}

	if normaliseconf == nil {
		normaliseconf = flag.Bool("normaliseconf", false, "use in combination with either -useconf or -useconffile, outputs your configuration normalised")
	}

	if autoconf == nil {
		autoconf = flag.Bool("autoconf", false, "automatic mode (dynamic IP, peer with IPv6 neighbors)")
	}

	if ver == nil {
		ver = flag.Bool("version", false, "prints the version of this build")
	}

	if logto == nil {
		logto = flag.String("logto", "stdout", "file path to log to, \"syslog\" or \"stdout\"")
	}

	if getaddr == nil {
		getaddr = flag.Bool("address", false, "returns the IPv6 address as derived from the supplied configuration")
	}

	if getsnet == nil {
		getsnet = flag.Bool("subnet", false, "returns the IPv6 subnet as derived from the supplied configuration")
	}

	if loglevel == nil {
		loglevel = flag.String("loglevel", "info", "loglevel to enable")
	}

	flag.Parse()

	switch {
	case *ver:
		fmt.Println("Build name:", version.BuildName())
		fmt.Println("Build version:", version.BuildVersion())
		return
	case *autoconf:
		cfg = config.GenerateConfig()
	case *useconffile != "" || *useconf:
		cfg = readConfig(useconf, useconffile, normaliseconf)

		if *normaliseconf {
			var bs []byte
			if *confjson {
				bs, err = json.MarshalIndent(cfg, "", "  ")
			} else {
				bs, err = hjson.Marshal(cfg)
			}
			if err != nil {
				//panic(err)
			}
			fmt.Println(string(bs))
			return
		}
	case *genconf:
		fmt.Println(doGenconf(*confjson))
	default:
		flag.PrintDefaults()
	}

	if cfg == nil {
		return
	}

	getNodeID := func() *crypto.NodeID {
		if pubkey, err := hex.DecodeString(cfg.EncryptionPublicKey); err == nil {
			var box crypto.BoxPubKey
			copy(box[:], pubkey)
			return crypto.GetNodeID(&box)
		}
		return nil
	}

	switch {
	case *getaddr:
		if nodeid := getNodeID(); nodeid != nil {
			addr := *address.AddrForNodeID(nodeid)
			ip := net.IP(addr[:])
			fmt.Println(ip.String())
		}
		return
	case *getsnet:
		if nodeid := getNodeID(); nodeid != nil {
			snet := *address.SubnetForNodeID(nodeid)
			ipnet := net.IPNet{
				IP:   append(snet[:], 0, 0, 0, 0, 0, 0, 0, 0),
				Mask: net.CIDRMask(len(snet)*8, 128),
			}
			fmt.Println(ipnet.String())
		}
		return
	default:
	}

	var logger *log.Logger

	switch *logto {
	case "stdout":
		logger = log.New(os.Stdout, "", log.Flags())
	case "syslog":
		if syslogger, err := gsyslog.NewLogger(gsyslog.LOG_NOTICE, "DAEMON", version.BuildName()); err == nil {
			logger = log.New(syslogger, "", log.Flags())
		}
	default:
		if logfd, err := os.OpenFile(*logto, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			logger = log.New(logfd, "", log.Flags())
		}
	}

	if logger == nil {
		logger = log.New(os.Stdout, "", log.Flags())
		logger.Warnln("Logging defaulting to stdout")
	}

	setLogLevel(*loglevel, logger)

	n = node{}

	n.state, err = n.core.Start(cfg, logger)
	if err != nil {
		logger.Errorln("An error occurred during startup")
		//panic(err)
	}

	n.core.SetSessionGatekeeper(n.sessionFirewall)

	n.admin = &admin.AdminSocket{}
	n.multicast = &multicast.Multicast{}
	n.tuntap = &tuntap.TunAdapter{}

	n.admin.Init(&n.core, n.state, logger, nil)
	if err := n.admin.Start(); err != nil {
		logger.Errorln("An error occurred starting admin socket:", err)
	}
	n.admin.SetupAdminHandlers(n.admin.(*admin.AdminSocket))

	n.multicast.Init(&n.core, n.state, logger, nil)
	if err := n.multicast.Start(); err != nil {
		logger.Errorln("An error occurred starting multicast:", err)
	}
	n.multicast.SetupAdminHandlers(n.admin.(*admin.AdminSocket))

	if listener, err := n.core.ConnListen(); err == nil {
		if dialer, err := n.core.ConnDialer(); err == nil {
			n.tuntap.Init(&n.core, n.state, logger, tuntap.TunOptions{Listener: listener, Dialer: dialer})
			if err := n.tuntap.Start(); err != nil {
				logger.Errorln("An error occurred starting TUN/TAP:", err)
			}
			n.tuntap.SetupAdminHandlers(n.admin.(*admin.AdminSocket))
		} else {
			logger.Errorln("Unable to get Dialer:", err)
		}
	} else {
		logger.Errorln("Unable to get Listener:", err)
	}

	IPAddress = n.core.Address()
	IPSubnet = n.core.Subnet()

	logger.Infof("Your IPv6 address is %s", IPAddress.String())
	logger.Infof("Your IPv6 subnet is %s", IPSubnet.String())

	ipLabel.SetText(IPAddress.String())
	subnetLabel.SetText(IPSubnet.String())

	connectionLabel.SetText("Connected")
	connectionLabel.SetStyleSheet("QLabel {color: green;}")

	time.Sleep(1 * time.Second)
	connectButton.SetDisabled(false)
}

func main() {
	if checkRoot() {
		configPeers = <-getConfigPeers()

		if fileExists("/etc/threefold_yggdrasil.conf") {
			debugLog("Updating peers.")

			data, _ := ioutil.ReadFile("/etc/threefold_yggdrasil.conf")
			dataAsString := string(data)

			var re = regexp.MustCompile(`Peers: \["(.*)"\]`)
			s := re.ReplaceAllString(dataAsString, configPeers)

			ioutil.WriteFile("/etc/threefold_yggdrasil.conf", []byte(s), 0644)
		}

		userInterface()
	} else {
		debugLog("Ending app.")
	}
}

func (n *node) shutdown() {
	debugLog("Shutdown.")

	n.admin.Stop()
	n.multicast.Stop()
	n.tuntap.Stop()
	n.core.Stop()

	time.Sleep(1 * time.Second)
	connectButton.SetDisabled(false)
}

func (n *node) sessionFirewall(pubkey *crypto.BoxPubKey, initiator bool) bool {
	n.state.Mutex.RLock()
	defer n.state.Mutex.RUnlock()

	if !n.state.Current.SessionFirewall.Enable {
		return true
	}

	var box crypto.BoxPubKey

	for _, b := range n.state.Current.SessionFirewall.BlacklistEncryptionPublicKeys {
		key, err := hex.DecodeString(b)
		if err == nil {
			copy(box[:crypto.BoxPubKeyLen], key)
			if box == *pubkey {
				return false
			}
		}
	}

	for _, b := range n.state.Current.SessionFirewall.WhitelistEncryptionPublicKeys {
		key, err := hex.DecodeString(b)
		if err == nil {
			copy(box[:crypto.BoxPubKeyLen], key)
			if box == *pubkey {
				return true
			}
		}
	}

	if n.state.Current.SessionFirewall.AlwaysAllowOutbound {
		if initiator {
			return true
		}
	}

	var isDirectPeer bool
	for _, peer := range n.core.GetPeers() {
		if peer.PublicKey == *pubkey {
			isDirectPeer = true
			break
		}
	}

	if n.state.Current.SessionFirewall.AllowFromDirect && isDirectPeer {
		return true
	}

	if n.state.Current.SessionFirewall.AllowFromRemote && !isDirectPeer {
		return true
	}

	return false
}
