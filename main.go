package main

/*
elastichoney - Elasticsearch Honeypot

The MIT License (MIT)

Copyright (c) 2015 Jordan Wright

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
	"github.com/fw42/go-hpfeeds"
)

var version = "0.0.1"

var (
	configFlag  = flag.String("config", "config.json", "Location of the configuration file")
	logFlag     = flag.String("log", "elastichoney.log", "Location of the log file")
	verboseFlag = flag.Bool("verbose", false, "Output verbose logging to STDOUT")
)

var logger = log.New(os.Stdout, "", log.Lshortfile)

var hpfeedsChannel = make(chan []byte)

// Config represents the configuration information.
type Config struct {
	LogFile        string  `json:"logfile"`
	UseRemote      bool    `json:"use_remote"`
	Remote         Remote  `json:"remote"`
	HpFeeds        HpFeeds `json:"hpfeeds"`
	InstanceName   string  `json:"instance_name"`
	Anonymous      bool    `json:"anonymous"`
	SensorIP       string  `json:"honeypot_ip"`
	SpoofedVersion string  `json:"spoofed_version"`
	PublicIpUrl    string  `json:"public_ip_url"`
}

// Remote is a struct used to contain the details for a remote server connection
type Remote struct {
	URL     string `json:"url"`
	UseAuth bool   `json:"use_auth"`
	Auth    Auth   `json:"auth"`
}

type HpFeeds struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Channel string `json:"channel"`
	Ident   string `json:"ident"`
	Secret  string `json:"secret"`
	Enabled bool   `json:"enabled"`
}

// Auth contains the details in case basic auth is to be used when connecting
// to the remote server
type Auth struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Conf holds the global config
var Conf Config

// Attack is a struct that contains the details of an attack entry
type Attack struct {
	SourceIP  string    `json:"source"`
	Timestamp time.Time `json:"@timestamp"`
	URL       string    `json:"url"`
	Method    string    `json:"method"`
	Form      string    `json:"form"`
	Payload   string    `json:"payload"`
	Headers   Headers   `json:"headers"`
	Type      string    `json:"type"`
	SensorIP  string    `json:"honeypot"`
}

// Headers contains the filtered headers of the HTTP request
type Headers struct {
	UserAgent      string `json:"user_agent"`
	Host           string `json:"host"`
	ContentType    string `json:"content_type"`
	AcceptLanguage string `json:"accept_language"`
}

// FakeBanner presents a fake elasticsearch banner for the index page
// TODO: Change Name to be randomly generated from real elasticsearch choices
// Make sure to keep name consistent for the same remote IP
func FakeBanner(w http.ResponseWriter, r *http.Request) {
	LogRequest(r, "recon")
	response := fmt.Sprintf(`{
        "status" : 200,
        "name" : "%s",
        "cluster_name" : "elasticsearch",
        "version" : {
            "number" : "%s",
            "build_hash" : "89d3241d670db65f994242c8e838b169779e2d4",
            "build_snapshot" : false,
            "lucene_version" : "4.10.2"
        },
        "tagline" : "You Know, for Search"
    }`, Conf.InstanceName, Conf.SpoofedVersion)
	WriteResponse(w, response)
	return
}

// FakeNodes presents a fake /_nodes result
// TODO: Change IP Address with actual server IP address
func FakeNodes(w http.ResponseWriter, r *http.Request) {
	LogRequest(r, "recon")
	response := fmt.Sprintf(`
	{
        "cluster_name" : "elasticsearch",
        "nodes" : {
            "x1JG6g9PRHy6ClCOO2-C4g" : {
              "name" : "%s",
              "transport_address" : "inet[/
			%s:9300]",
              "host" : "elk",
              "ip" : "127.0.1.1",
              "version" : "%s",
              "build" : "89d3241",
              "http_address" : "inet[/%s:9200]",
              "os" : {
                "refresh_interval_in_millis" : 1000,
                "available_processors" : 12,
                "cpu" : {
                  "total_cores" : 24,
                  "total_sockets" : 48,
                  "cores_per_socket" : 2
                }
              },
              "process" : {
                "refresh_interval_in_millis" : 1000,
                "id" : 2039,
                "max_file_descriptors" : 65535,
                "mlockall" : false
              },
              "jvm" : {
                "version" : "1.7.0_65"
              },
              "network" : {
                "refresh_interval_in_millis" : 5000,
                "primary_interface" : {
                  "address" : "%s",
                  "name" : "eth0",
                  "mac_address" : "08:01:c7:3F:15:DD"
                }
              },
              "transport" : {
                "bound_address" : "inet[/0:0:0:0:0:0:0:0:9300]",
                "publish_address" : "inet[/%s:9300]"
              },
              "http" : {
                "bound_address" : "inet[/0:0:0:0:0:0:0:0:9200]",
                "publish_address" : "inet[/%s:9200]",
                "max_content_length_in_bytes" : 104857600
              }}
            }
        }`, Conf.InstanceName, Conf.SensorIP, Conf.SpoofedVersion, Conf.SensorIP, Conf.SensorIP, Conf.SensorIP, Conf.SensorIP)
	WriteResponse(w, response)
	return
}

// FakeSearch returns fake search results
func FakeSearch(w http.ResponseWriter, r *http.Request) {
	LogRequest(r, "attack")
	response := fmt.Sprintf(`
	{
        "took" : 6,
        "timed_out" : false,
        "_shards" : {
            "total" : 6,
            "successful" : 6,
            "failed" : 0
        },
        "hits" : {
            "total" : 1,
            "max_score" : 1.0,
            "hits" : [ {
                "_index" : ".kibana",
                "_type" : "index-pattern",
                "_id" : "logstash-*",
                "_score" : 1.0,
                "_source":{"title":"logstash-*","timeFieldName":"@timestamp","customFormats":"{}","fields":"[{\"type\":\"string\",\"indexed\":true,\"analyzed\":true,\"doc_values\":false,\"name\":\"host\",\"count\":0},{\"type\":\"string\",\"indexed\":false,\"analyzed\":false,\"name\":\"_source\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"message.raw\",\"count\":0},{\"type\":\"string\",\"indexed\":false,\"analyzed\":false,\"name\":\"_index\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"@version\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":true,\"doc_values\":false,\"name\":\"message\",\"count\":0},{\"type\":\"date\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"@timestamp\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"name\":\"_type\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"name\":\"_id\",\"count\":0},{\"type\":\"string\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"host.raw\",\"count\":0},{\"type\":\"geo_point\",\"indexed\":true,\"analyzed\":false,\"doc_values\":false,\"name\":\"geoip.location\",\"count\":0}]"}
            }]
        }
    }`)
	WriteResponse(w, response)
	return
}

// LogRequest handles the logging of requests to configurable endpoints
func LogRequest(r *http.Request, t string) {
	as_c := new(bytes.Buffer)
	r.ParseForm()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Printf("[!] Error: %s\n", err)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.Printf("[!] Error: %s\n", err)
	}
	// Create the attack entry
	attack := Attack{
		Timestamp: time.Now(),
		SourceIP:  ip,
		Method:    r.Method,
		URL:       strings.Join([]string{r.Host, r.URL.String()}, ""),
		Form:      r.Form.Encode(),
		Payload:   string(body),
		Headers: Headers{
			Host:           r.Host,
			UserAgent:      r.UserAgent(),
			ContentType:    r.Header.Get("Content-Type"),
			AcceptLanguage: r.Header.Get("Accept-Language"),
		},
		SensorIP: Conf.SensorIP,
		Type:     t,
	}
	// Convert to JSON
	as, err := JSONMarshal(attack)
	if err != nil {
		logger.Printf("[!] ERROR: %s\n", err)
	}
	err = json.Compact(as_c, as)
	fmt.Printf("%s\n", as)
	// Log the entry
	f, err := os.OpenFile(*logFlag, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0660)
	if err != nil {
		logger.Printf("[!] ERROR: %s\n", err)
	} else {
		defer f.Close()
		if _, err = f.WriteString(string(as_c.String()) + "\n"); err != nil {
			logger.Printf("[!] ERROR: %s\n", err)
		}
	}
	// If the client wants to use a remote server, let's upload the attack data
	if Conf.UseRemote {
		buff := bytes.NewBuffer(as)
		req, err := http.NewRequest("POST", Conf.Remote.URL, buff)
		if err != nil {
			logger.Printf("[!] Error: %s\n", err)
			return
		}
		// Set the Basic Auth if desired
		if Conf.Remote.UseAuth {
			req.SetBasicAuth(Conf.Remote.Auth.Username, Conf.Remote.Auth.Password)
		}
		req.Header.Set("User-Agent", fmt.Sprintf("elastichoney v%s", version))
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			logger.Printf("[!] Error: %s\n", err)
		} else {
			if *verboseFlag {
				logger.Printf("Upload Status: %d\n", resp.StatusCode)
			}
		}
	}

	if Conf.HpFeeds.Enabled {
		hpfeedsChannel <- []byte(as_c.String())
	}
}

// WriteResponse contains the logic to write JSON back out to the attacker
func WriteResponse(w http.ResponseWriter, d string) {
	w.WriteHeader(200)
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Write([]byte(d))
	return
}

// JSONMarshal helper to not convert <,>, and &.
// Shamlessly taken from https://stackoverflow.com/questions/24656624/golang-display-character-not-ascii-like-not-0026
func JSONMarshal(v interface{}) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		fmt.Println(err)
		return b, err
	}
	b = bytes.Replace(b, []byte("\\u003c"), []byte("<"), -1)
	b = bytes.Replace(b, []byte("\\u003e"), []byte(">"), -1)
	b = bytes.Replace(b, []byte("\\u0026"), []byte("&"), -1)
	return b, err
}

func hpfeedsConnect() {
	backoff := 0
	hp := hpfeeds.NewHpfeeds(Conf.HpFeeds.Host, Conf.HpFeeds.Port, Conf.HpFeeds.Ident, Conf.HpFeeds.Secret)
	hp.Log = true
	logger.Printf("Connecting to hpfeeds server: %s:%d ...\n", Conf.HpFeeds.Host, Conf.HpFeeds.Port)
	for {
		err := hp.Connect()
		if err == nil {
			logger.Printf("Connected to Hpfeeds server.")
			hp.Publish(Conf.HpFeeds.Channel, hpfeedsChannel)
			<-hp.Disconnected
			logger.Printf("Lost connection to %s:%d :-(\n", Conf.HpFeeds.Host, Conf.HpFeeds.Port)
		}

		logger.Printf("Reconnecting to %s:%d after %ds\n", Conf.HpFeeds.Host, Conf.HpFeeds.Port, backoff)
		time.Sleep(time.Duration(backoff) * time.Second)
		if backoff <= 10 {
			backoff++
		}
	}
}


func main() {
	flag.Parse()
	// Get the config file
	configFile, err := ioutil.ReadFile(*configFlag)
	if err != nil {
		fmt.Printf("[!] Error: %v\n", err)
	}
	json.Unmarshal(configFile, &Conf)
	// If the user doesn't want their honeypot IP to be anonymous, let's get
	// the external IP
	if !Conf.Anonymous {
		resp, err := http.Get(Conf.PublicIpUrl)
		if err != nil {
			panic(err)
		}
		ip, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		Conf.SensorIP = strings.TrimSpace(string(ip))
		resp.Body.Close()
	} else {
		Conf.SensorIP = "1.1.1.1"
	}
	if *verboseFlag {
		logger.Printf("Using sensor ip: %s", Conf.SensorIP)
	}

	if Conf.HpFeeds.Enabled {
		go hpfeedsConnect()
	}

	// Create the handlers
	http.HandleFunc("/", FakeBanner)
	http.HandleFunc("/_nodes", FakeNodes)
	http.HandleFunc("/_search", FakeSearch)
	if *verboseFlag {
		logger.Printf("Listening on :9200")
	}
	// Start the server
	http.ListenAndServe(":9200", nil)
}
