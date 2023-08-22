package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v2"

	mtr "github.com/Shinzu/go-mtr"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
)

type Exporter struct {
	mutex              sync.Mutex
	sent               *prometheus.CounterVec
	received           *prometheus.CounterVec
	latency            *prometheus.SummaryVec
	best               *prometheus.GaugeVec
	worst              *prometheus.GaugeVec
	meanJitter         *prometheus.GaugeVec
	worstJitter        *prometheus.GaugeVec
	interarrivalJitter *prometheus.GaugeVec
	routeChanges       *prometheus.CounterVec
	destinationChanges *prometheus.CounterVec
	failed             *prometheus.CounterVec
	lastDest           map[string]net.IP
	lastRoute          map[string][]net.IP
}

type Config struct {
	Arguments []string `yaml:"args"`
	Cycles    int      `yaml:"cycles"`
	Hosts     []Host   `yaml:"hosts"`
	Sleep     int      `yaml:"sleep"`
}

type Host struct {
	Name  string `yaml:"name"`
	Alias string `yaml:"alias"`
}

type TargetFeedback struct {
	Target string
	Alias  string
	Hosts  []*mtr.Host
}

var config Config

const (
	Namespace = "mtr"
)

func NewExporter() *Exporter {
	var (
		alias        = "alias"
		server       = "server"
		hop_id       = "hop_id"
		hop_ip       = "hop_ip"
		previousDest = "previous"
		currentDest  = "current"
	)

	return &Exporter{
		sent: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "packets_sent_total",
				Help:      "Total number of packets sent.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		received: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "packets_received_total",
				Help:      "Total number of packets received.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		latency: prometheus.NewSummaryVec(
			prometheus.SummaryOpts{
				Namespace: Namespace,
				Name:      "packet_latency_microseconds",
				Help:      "The MTR packet latencies in microseconds.",
				Objectives: map[float64]float64{
					0.5:  0.05,
					0.9:  0.01,
					0.99: 0.001,
				},
				MaxAge:     prometheus.DefMaxAge,
				AgeBuckets: prometheus.DefAgeBuckets,
				BufCap:     prometheus.DefBufCap,
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		best: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "packet_latency_best_microseconds",
				Help:      "The best MTR packet latency in microseconds.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		worst: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "packet_latency_worst_microseconds",
				Help:      "The worst MTR packet latency in microseconds.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		meanJitter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "packet_jitter_mean_microseconds",
				Help:      "The mean MTR packet jitter in microseconds.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		worstJitter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "packet_jitter_worst_microseconds",
				Help:      "The worst MTR packet jitter in microseconds.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		interarrivalJitter: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: Namespace,
				Name:      "packet_jitter_interarrival_microseconds",
				Help:      "The MTR packet interarrival jitter in microseconds.",
			},
			[]string{alias, server, hop_id, hop_ip},
		),
		routeChanges: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "route_changes_total",
				Help:      "Total number of times the route has changed.",
			},
			[]string{alias, server, hop_id},
		),
		destinationChanges: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "destination_ip_changes_total",
				Help:      "Total number of times the destination IP has changed",
			},
			[]string{alias, server, previousDest, currentDest},
		),
		failed: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: Namespace,
				Name:      "runs_failed_total",
				Help:      "Total number of failed MTR runs.",
			},
			[]string{alias, server},
		),
		lastDest:  make(map[string]net.IP, len(config.Hosts)),
		lastRoute: make(map[string][]net.IP, len(config.Hosts)),
	}
}

func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	e.sent.Describe(ch)
	e.received.Describe(ch)
	e.latency.Describe(ch)
	e.best.Describe(ch)
	e.worst.Describe(ch)
	e.meanJitter.Describe(ch)
	e.worstJitter.Describe(ch)
	e.interarrivalJitter.Describe(ch)
	e.routeChanges.Describe(ch)
	e.destinationChanges.Describe(ch)
	e.failed.Describe(ch)
}

func min(a int, b int) int {
	if a > b {
		return b
	}
	return a
}

func (e *Exporter) collect() error {
	for {
		results := make(chan *TargetFeedback)
		wg := &sync.WaitGroup{}
		wg.Add(len(config.Hosts))

		for w, host := range config.Hosts {
			go func(w int, host Host) {
				log.Infoln("worker", w, "processing job", host.Name, "aliased as", host.Alias)
				err := worker(w, host, results, wg)
				if err != nil {
					log.Errorf("worker %d failed job %v aliased as %v: %v", w, host.Name, host.Alias, err)
					e.failed.WithLabelValues(host.Alias, host.Name).Inc()
				} else {
					log.Infoln("worker", w, "finished job", host.Name, "aliased as", host.Alias)
				}
			}(w, host)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		for tf := range results {
			route := make([]net.IP, len(tf.Hosts))
			destination := tf.Hosts[len(tf.Hosts)-1].IP
			for i, host := range tf.Hosts {
				route[i] = host.IP
				e.sent.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Add(float64(host.Sent))
				e.received.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Add(float64(host.Received))
				for _, packet := range host.PacketMicrosecs {
					e.latency.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Observe(float64(packet))
				}
				e.best.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Set(float64(host.Best))
				e.worst.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Set(float64(host.Worst))
				e.meanJitter.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Set(float64(host.MeanJitter))
				e.worstJitter.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Set(float64(host.WorstJitter))
				e.interarrivalJitter.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(host.Hop), host.IP.String()).Set(float64(host.InterarrivalJitter))
			}
			if e.lastRoute[tf.Alias] != nil {
				m := min(len(route), len(e.lastRoute[tf.Alias]))
				if len(route) != len(e.lastRoute[tf.Alias]) {
					e.routeChanges.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(m)).Inc()
				} else {
					// m - 1 because if the routes are the same apart from the destination, it's
					// just the destination that's changed, and that's recorded separately below
					for i := 0; i < (m - 1); i++ {
						if !reflect.DeepEqual(route[i], e.lastRoute[tf.Alias][i]) {
							e.routeChanges.WithLabelValues(tf.Alias, tf.Target, strconv.Itoa(i)).Inc()
						}
					}
				}
			}
			e.lastRoute[tf.Alias] = route
			if e.lastDest[tf.Alias] != nil && !reflect.DeepEqual(destination, e.lastDest[tf.Alias]) {
				e.destinationChanges.WithLabelValues(tf.Alias, tf.Target, e.lastDest[tf.Alias].String(), destination.String()).Inc()
			}
			e.lastDest[tf.Alias] = destination
		}

		if config.Sleep > 0 {
			log.Infof("Sleeping for %d seconds between runs...", config.Sleep)
			time.Sleep(time.Duration(config.Sleep) * time.Second)
		}
	}
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.sent.Collect(ch)
	e.received.Collect(ch)
	e.latency.Collect(ch)
	e.best.Collect(ch)
	e.worst.Collect(ch)
	e.meanJitter.Collect(ch)
	e.worstJitter.Collect(ch)
	e.interarrivalJitter.Collect(ch)
	e.routeChanges.Collect(ch)
	e.destinationChanges.Collect(ch)
	e.failed.Collect(ch)
	return
}

func trace(host Host, results chan<- *TargetFeedback) error {
	// run MTR and wait for it to complete
	a := mtr.New(config.Cycles, host.Name, config.Arguments...)
	<-a.Done

	// output result
	if a.Error == nil {
		results <- &TargetFeedback{
			Target: host.Name,
			Alias:  host.Alias,
			Hosts:  a.Hosts,
		}
	}
	return a.Error
}

func worker(id int, host Host, results chan<- *TargetFeedback, wg *sync.WaitGroup) error {
	defer wg.Done()
	return trace(host, results)
}

func main() {
	var (
		configFile    = flag.String("config.file", "mtr.yaml", "MTR exporter configuration file.")
		listenAddress = flag.String("web.listen-address", ":9116", "The address to listen on for HTTP requests.")
		showVersion   = flag.Bool("version", false, "Print version information.")
	)

	flag.Parse()

	if *showVersion {
		fmt.Fprintln(os.Stdout, version.Print("mtr_exporter"))
		os.Exit(0)
	}

	log.Infoln("Starting mtr_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	yamlFile, err := ioutil.ReadFile(*configFile)

	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		log.Fatalf("Error parsing config file: %s", err)
	}

	prometheus.MustRegister(version.NewCollector("mtr_exporter"))
	exporter := NewExporter()
	prometheus.MustRegister(exporter)

	go exporter.collect()

	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head><title>MTR Exporter</title></head>
            <body>
            <h1>MTR Exporter</h1>
            <p><a href="/metrics">Metrics</a></p>
            </body>
            </html>`))
	})

	log.Infoln("Listening on", *listenAddress)
	if err := http.ListenAndServe(*listenAddress, nil); err != nil {
		log.Fatalf("Error starting HTTP server: %s", err)
	}
}
