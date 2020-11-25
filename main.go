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
var IPAddress net.IP
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

// YggdrasilIPAddress represents an yggdrasil IP address with additional information.
type YggdrasilIPAddress struct {
	FullIPAddress string
	IPAddress     string
	latency       float64
}

type QSystemTrayIconWithCustomSlot struct {
	widgets.QSystemTrayIcon

	_ func(f func()) `slot:"triggerSlot,auto"` //create a slot that takes a function and automatically connect it
}

func (tray *QSystemTrayIconWithCustomSlot) triggerSlot(f func()) { f() } //the slot just needs to call the passed function to execute it inside the main thread

type node struct {
	core      yggdrasil.Core
	state     *config.NodeState
	tuntap    module.Module // tuntap.TunAdapter
	multicast module.Module // multicast.Multicast
	admin     module.Module // admin.AdminSocket
}

func checkRoot() bool {
	if getProcessOwner() == "root" {
		fmt.Println("You're sudo!")
		return true
	}

	fmt.Println("Not running with sudo, trying to elevate!")

	fmt.Println("Asking user for password")

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
		password = dialog.TextValue()
		dialog.Close()
	})

	dialog.Exec()

	fmt.Println("Cleaning up yggdrasil sock.")
	cleanupYggdrasilSock(password)

	fmt.Println("Restarting myself as a new elevated process")
	elevateMyself(password)
	// time.Sleep(3 * time.Second)
	return false
}

func cleanupYggdrasilSock(password string) string {
	cmd := "echo " + password + " | sudo -S rm -rf /var/run/yggdrasil.sock"
	// fmt.Println(cmd)
	stdout, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		fmt.Println(err)
		// os.Exit(1)
	}
	return strings.TrimSpace(string(stdout))
}

func elevateMyself(password string) {
	cmd := "echo " + password + " | sudo -S " + getExecutingDirectory() + "/ThreeFoldNetworkConnector"
	// fmt.Println(cmd)
	rcmd := exec.Command("bash", "-c", cmd)
	err := rcmd.Start()

	if err != nil {
		fmt.Println(err)
		// os.Exit(1)
	}

}

func getExecutingDirectory() string {
	// cmd := "pwd"
	// stdout, err := exec.Command("bash", "-c", cmd).Output()
	// if err != nil {
	// 	fmt.Println(err)
	// 	os.Exit(1)
	// }
	// return strings.TrimSpace(string(stdout))
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
		// os.Exit(1)
	}
	return strings.TrimSpace(string(stdout))
}

func getProcessOwner() string {
	stdout, err := exec.Command("ps", "-o", "user=", "-p", strconv.Itoa(os.Getpid())).Output()
	if err != nil {
		fmt.Println(err)
		// os.Exit(1)
	}
	return strings.TrimSpace(string(stdout))
}

// Making this function async in some magic go-syntax land.
func getConfigPeers() <-chan string {
	r := make(chan string)

	go func() {
		defer close(r)

		c := colly.NewCollector()
		var ipAddresses []YggdrasilIPAddress

		c.OnHTML(".statusup #address", func(e *colly.HTMLElement) {

			// Filtering out all tcp and ipv6 addresses

			if strings.Contains(e.Text, "tcp://") {
				return
			}

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
	pinger, err := ping.NewPinger(addr.IPAddress)
	pinger.Timeout = time.Second / 2

	if err != nil {
		//panic(err)
	}
	pinger.Count = 2
	err = pinger.Run() // Blocks until finished.
	if err != nil {
		// panic(err)
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

func readConfig(useconf *bool, useconffile *string, normaliseconf *bool) *config.NodeConfig {
	// Use a configuration file. If -useconf, the configuration will be read
	// from stdin. If -useconffile, the configuration will be read from the
	// filesystem.
	var conf []byte
	var err error
	if *useconffile != "" {
		// Read the file from the filesystem
		conf, err = ioutil.ReadFile(*useconffile)
	} else {
		// Read the file from stdin.
		conf, err = ioutil.ReadAll(os.Stdin)
	}
	if err != nil {
		//panic(err)
	}
	// If there's a byte order mark - which Windows 10 is now incredibly fond of
	// throwing everywhere when it's converting things into UTF-16 for the hell
	// of it - remove it and decode back down into UTF-8. This is necessary
	// because hjson doesn't know what to do with UTF-16 and will panic
	if bytes.Equal(conf[0:2], []byte{0xFF, 0xFE}) ||
		bytes.Equal(conf[0:2], []byte{0xFE, 0xFF}) {
		utf := unicode.UTF16(unicode.BigEndian, unicode.UseBOM)
		decoder := utf.NewDecoder()
		conf, err = decoder.Bytes(conf)
		if err != nil {
			//panic(err)
		}
	}
	// Generate a new configuration - this gives us a set of sane defaults -
	// then parse the configuration we loaded above on top of it. The effect
	// of this is that any configuration item that is missing from the provided
	// configuration will use a sane default.
	cfg := config.GenerateConfig()
	var dat map[string]interface{}
	if err := hjson.Unmarshal(conf, &dat); err != nil {
		//panic(err)
	}
	// Check for fields that have changed type recently, e.g. the Listen config
	// option is now a []string rather than a string
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
	// Sanitise the config
	confJson, err := json.Marshal(dat)
	if err != nil {
		// panic(err)
	}
	json.Unmarshal(confJson, &cfg)
	// Overlay our newly mapped configuration onto the autoconf node config that
	// we generated above.
	if err = mapstructure.Decode(dat, &cfg); err != nil {
		// panic(err)
	}
	return cfg
}

// Generates a new configuration and returns it in HJSON format. This is used
// with -genconf.
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

	if !contains() { // set default log level
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

	// println(window.Type())
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
		// defer n.shutdown()
		// go submain()
		// widgets.QMessageBox_Information(nil, "OK", "Connecting ...", widgets.QMessageBox__Ok, widgets.QMessageBox__Ok)

		ipLabel.SetText("N/A")
		subnetLabel.SetText("N/A")

		// Catch interrupts from the operating system to exit gracefully.
		c := make(chan os.Signal, 1)
		r := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		signal.Notify(r, os.Interrupt, syscall.SIGHUP)
		// Capture the service being stopped on Windows.
		minwinsvc.SetOnExit(n.shutdown)
		defer n.shutdown()
		// Wait for the terminate/interrupt signal. Once a signal is received, the
		// deferred Stop function above will run which will shut down TUN/TAP.
	})

	gridLayout.AddWidget2(statusLabel, 0, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(connectionLabel, 0, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(connectButton, 0, 2, core.Qt__AlignRight)

	ipLabelInfo := widgets.NewQLabel2("Ipv6: ", nil, 0)
	subnetLabelInfo := widgets.NewQLabel2("Subnet: ", nil, 0)
	// debugLabelInfo := widgets.NewQLabel2("Debug: ", nil, 0)

	ipLabel = widgets.NewQLabel2("N/A", nil, 0)
	subnetLabel = widgets.NewQLabel2("N/A", nil, 0)
	debugLabel = widgets.NewQLabel2("Debug info", nil, 0)

	gridLayout.AddWidget2(ipLabelInfo, 2, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(ipLabel, 2, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(CopyIPButton, 2, 2, core.Qt__AlignRight)

	gridLayout.AddWidget2(subnetLabelInfo, 3, 0, core.Qt__AlignLeft)
	gridLayout.AddWidget2(subnetLabel, 3, 1, core.Qt__AlignCenter)
	gridLayout.AddWidget2(copySubnetButton, 3, 2, core.Qt__AlignRight)

	// Debugging purposes

	// gridLayout.AddWidget2(debugLabelInfo, 3, 0, core.Qt__AlignCenter)
	// gridLayout.AddWidget2(debugLabel, 3, 1, core.Qt__AlignCenter)

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
	// if !fileExists("/etc/threefold_yggdrasil.conf") {
	debugLabel.SetText("[info]: No config file")
	fmt.Println("Config file doesnt exist ...")
	cfg = config.GenerateConfig()
	fmt.Println(cfg)

	debugLabel.SetText("[info]: config generated")

	configFile := doGenconf(*confjson)
	fmt.Println("Config file created")
	debugLabel.SetText("[info]: Created config file")
	configFile = strings.ReplaceAll(configFile, "Peers: []", configPeers)
	fmt.Println("Peers replaced")
	debugLabel.SetText("[info]: Peers replaced")

	f, err := os.Create("/etc/threefold_yggdrasil.conf")
	if err != nil {
		fmt.Println(err)
		debugLabel.SetText("[err01]: " + err.Error())
		return
	}
	l, err := f.WriteString(configFile)
	if err != nil {
		fmt.Println(err)
		debugLabel.SetText("[err02]: " + err.Error())
		f.Close()
		return
	}
	debugLabel.SetText("[info]: Config written")
	fmt.Println(l, "bytes written successfully")
	err = f.Close()
	if err != nil {
		fmt.Println(err)
		return
	}
	// }
}

func resetApplication() {
	err := os.Remove("/var/run/yggdrasil.sock")

	if err != nil {
		fmt.Println(err)
	}

	err = os.Remove("/etc/threefold_yggdrasil.conf")

	if err != nil {
		fmt.Println(err)
	}
}

func submain() {

	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Recovering from panic in submain error is: %v \n", r)
		}
	}()

	if confjson == nil {
		confjson = flag.Bool("json", false, "print configuration from -genconf or -normaliseconf as JSON instead of HJSON")
	}

	var cfg *config.NodeConfig
	var err error

	debugLabel.SetText("[info]: submain")
	fmt.Println("initt")

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

	// Automaticly generate a config file if it doesnt already exist.
	// Automaticly connect on startup?
	// Call different functions to change the actions.

	switch {
	case *ver:
		fmt.Println("Build name:", version.BuildName())
		fmt.Println("Build version:", version.BuildVersion())
		return
	case *autoconf:
		// Use an autoconf-generated config, this will give us random keys and
		// port numbers, and will use an automatically selected TUN/TAP interface.
		cfg = config.GenerateConfig()
	case *useconffile != "" || *useconf:
		// Read the configuration from either stdin or from the filesystem
		cfg = readConfig(useconf, useconffile, normaliseconf)
		// If the -normaliseconf option was specified then remarshal the above
		// configuration and print it back to stdout. This lets the user update
		// their configuration file with newly mapped names (like above) or to
		// convert from plain JSON to commented HJSON.
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
		// Generate a new configuration and print it to stdout.
		fmt.Println(doGenconf(*confjson))
	default:
		// No flags were provided, therefore print the list of flags to stdout.
		flag.PrintDefaults()
	}

	debugLabel.SetText("[info]: 1")
	// Have we got a working configuration? If we don't then it probably means
	// that neither -autoconf, -useconf or -useconffile were set above. Stop
	// if we don't.
	if cfg == nil {
		return
	}
	// Have we been asked for the node address yet? If so, print it and then stop.
	getNodeID := func() *crypto.NodeID {
		if pubkey, err := hex.DecodeString(cfg.EncryptionPublicKey); err == nil {
			var box crypto.BoxPubKey
			copy(box[:], pubkey)
			return crypto.GetNodeID(&box)
		}
		return nil
	}
	debugLabel.SetText("[info]: 2")

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

	debugLabel.SetText("[info]: 3")
	// Create a new logger that logs output to stdout.
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

	// Setup the Yggdrasil node itself. The node{} type includes a Core, so we
	// don't need to create this manually.
	n = node{}
	// Now start Yggdrasil - this starts the DHT, router, switch and other core
	// components needed for Yggdrasil to operate
	n.state, err = n.core.Start(cfg, logger)
	if err != nil {
		logger.Errorln("An error occurred during startup")
		//panic(err)
	}
	// Register the session firewall gatekeeper function
	n.core.SetSessionGatekeeper(n.sessionFirewall)
	// Allocate our modules
	n.admin = &admin.AdminSocket{}
	n.multicast = &multicast.Multicast{}
	n.tuntap = &tuntap.TunAdapter{}
	// Start the admin socket
	n.admin.Init(&n.core, n.state, logger, nil)
	if err := n.admin.Start(); err != nil {
		logger.Errorln("An error occurred starting admin socket:", err)
	}
	n.admin.SetupAdminHandlers(n.admin.(*admin.AdminSocket))
	// Start the multicast interface
	n.multicast.Init(&n.core, n.state, logger, nil)
	if err := n.multicast.Start(); err != nil {
		logger.Errorln("An error occurred starting multicast:", err)
	}
	n.multicast.SetupAdminHandlers(n.admin.(*admin.AdminSocket))
	// Start the TUN/TAP interface
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
	// Make some nice output that tells us what our IPv6 address and subnet are.
	// This is just logged to stdout for the user.
	IPAddress = n.core.Address()
	IPSubnet = n.core.Subnet()
	logger.Infof("Your IPv6 address is %s", IPAddress.String())
	logger.Infof("Your IPv6 subnet is %s", IPSubnet.String())

	ipLabel.SetText(IPAddress.String())
	subnetLabel.SetText(IPSubnet.String())
	debugLabel.SetText("[info]: Ip has been set")

	connectionLabel.SetText("Connected")
	connectionLabel.SetStyleSheet("QLabel {color: green;}")

	time.Sleep(1 * time.Second)
	connectButton.SetDisabled(false)

	// 	// Catch interrupts from the operating system to exit gracefully.
	// 	c := make(chan os.Signal, 1)
	// 	r := make(chan os.Signal, 1)
	// 	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// 	signal.Notify(r, os.Interrupt, syscall.SIGHUP)
	// 	// Capture the service being stopped on Windows.
	// 	minwinsvc.SetOnExit(n.shutdown)
	// 	defer n.shutdown()
	// 	// Wait for the terminate/interrupt signal. Once a signal is received, the
	// 	// deferred Stop function above will run which will shut down TUN/TAP.
	// 	for {
	// 		select {
	// 		case <-c:
	// 			goto exit
	// 		case <-r:
	// 			if *useconffile != "" {
	// 				cfg = readConfig(useconf, useconffile, normaliseconf)
	// 				logger.Infoln("Reloading configuration from", *useconffile)
	// 				n.core.UpdateConfig(cfg)
	// 				n.tuntap.UpdateConfig(cfg)
	// 				n.multicast.UpdateConfig(cfg)
	// 			} else {
	// 				logger.Errorln("Reloading config at runtime is only possible with -useconffile")
	// 			}
	// 		}
	// 	}
	// exit:
}

// The main function is responsible for configuring and starting Yggdrasil.
func main() {
	if checkRoot() {
		configPeers = <-getConfigPeers()

		if fileExists("/etc/threefold_yggdrasil.conf") {
			fmt.Println("Updating peers")
			data, _ := ioutil.ReadFile("/etc/threefold_yggdrasil.conf")
			dataAsString := string(data)

			var re = regexp.MustCompile(`Peers: \["(.*)"\]`)
			s := re.ReplaceAllString(dataAsString, configPeers)
			ioutil.WriteFile("/etc/threefold_yggdrasil.conf", []byte(s), 0644)
		}

		userInterface()
	} else {
		fmt.Println("Ending app ...")
	}
}

func (n *node) shutdown() {
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

	// Allow by default if the session firewall is disabled
	if !n.state.Current.SessionFirewall.Enable {
		return true
	}

	// Prepare for checking whitelist/blacklist
	var box crypto.BoxPubKey
	// Reject blacklisted nodes
	for _, b := range n.state.Current.SessionFirewall.BlacklistEncryptionPublicKeys {
		key, err := hex.DecodeString(b)
		if err == nil {
			copy(box[:crypto.BoxPubKeyLen], key)
			if box == *pubkey {
				return false
			}
		}
	}

	// Allow whitelisted nodes
	for _, b := range n.state.Current.SessionFirewall.WhitelistEncryptionPublicKeys {
		key, err := hex.DecodeString(b)
		if err == nil {
			copy(box[:crypto.BoxPubKeyLen], key)
			if box == *pubkey {
				return true
			}
		}
	}

	// Allow outbound sessions if appropriate
	if n.state.Current.SessionFirewall.AlwaysAllowOutbound {
		if initiator {
			return true
		}
	}

	// Look and see if the pubkey is that of a direct peer
	var isDirectPeer bool
	for _, peer := range n.core.GetPeers() {
		if peer.PublicKey == *pubkey {
			isDirectPeer = true
			break
		}
	}

	// Allow direct peers if appropriate
	if n.state.Current.SessionFirewall.AllowFromDirect && isDirectPeer {
		return true
	}

	// Allow remote nodes if appropriate
	if n.state.Current.SessionFirewall.AllowFromRemote && !isDirectPeer {
		return true
	}

	// Finally, default-deny if not matching any of the above rules
	return false
}
