package ospf

import (
	"container/heap"
	"github.com/IrineSistiana/mosdns/v5/pkg/ospf_cnn"
	"go.uber.org/zap"
	"net"
	"sync"
	"time"
)

// IpEntry represents an IP address along with its expiration time.
type IpEntry struct {
	ip             net.IPNet
	expirationTime time.Time
	domain         string
	queueIndex     int // The index of the entry in the priority queue
}

// PriorityQueue is a heap-based priority queue that orders IPs by their expiration time.
type PriorityQueue []*IpEntry

func (pq PriorityQueue) Len() int { return len(pq) }
func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].expirationTime.Before(pq[j].expirationTime)
}
func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].queueIndex = i
	pq[j].queueIndex = j
}

func (pq *PriorityQueue) Push(x interface{}) {
	ip := x.(*IpEntry)
	*pq = append(*pq, ip)
	ip.queueIndex = len(*pq) - 1
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	item.queueIndex = -1 // Reset the queue index when item is removed
	return item
}

// IpPool manages a pool of IP addresses and their expiration times.
type IpPool struct {
	ttl    time.Duration
	pool   map[string]map[string]*IpEntry // domain -> ip -> IpEntry
	pq     PriorityQueue                  // Priority queue for IPs
	router *ospf_cnn.Router
	logger *zap.Logger
	mux    sync.Mutex
}

// NewIpPool creates a new IpPool with the given TTL and router.
func NewIpPool(ttl uint, router *ospf_cnn.Router, logger *zap.Logger) *IpPool {
	return &IpPool{
		ttl:    time.Duration(ttl) * time.Second,
		pool:   make(map[string]map[string]*IpEntry),
		pq:     make(PriorityQueue, 0),
		router: router,
		logger: logger,
	}
}

// AddIps adds or updates IPs for a given domain in the pool.
func (r *IpPool) AddIps(domain string, ips []net.IPNet) {
	r.mux.Lock()
	defer r.mux.Unlock()

	// Initialize the domain entry if it doesn't exist
	if _, exists := r.pool[domain]; !exists {
		r.pool[domain] = make(map[string]*IpEntry)
	}

	for _, ip := range ips {
		ipStr := ip.String()
		expirationTime := time.Now().Add(r.ttl)

		// If the IP exists, update its expiration time
		if entry, exists := r.pool[domain][ipStr]; exists {
			entry.expirationTime = expirationTime
			heap.Fix(&r.pq, entry.queueIndex) // Update the position in the heap
			r.logger.Info("Updated IP expiration", zap.String("domain", domain), zap.String("ip", ipStr), zap.Time("expiration", expirationTime))
		} else {
			// Otherwise, add the new IP to the pool and priority queue
			newEntry := &IpEntry{
				ip:             ip,
				expirationTime: expirationTime,
				domain:         domain,
			}
			r.pool[domain][ipStr] = newEntry
			heap.Push(&r.pq, newEntry)
			r.logger.Info("Added new IP to pool", zap.String("domain", domain), zap.String("ip", ipStr), zap.Time("expiration", expirationTime))
		}
	}
}

// startExpireChecker starts a background goroutine that checks for expired IPs every second.
func (r *IpPool) startExpireChecker() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		r.cleanExpiredEntries()
	}
}

// cleanExpiredEntries removes expired IPs from the pool and revokes them from the router.
func (r *IpPool) cleanExpiredEntries() {
	r.mux.Lock()
	defer r.mux.Unlock()

	now := time.Now()
	var revokedIps []net.IPNet

	// Check the top of the priority queue for expired IPs
	for len(r.pq) > 0 && r.pq[0].expirationTime.Before(now) {
		// Remove the expired IP from the heap
		expiredIp := heap.Pop(&r.pq).(*IpEntry)
		delete(r.pool[expiredIp.domain], expiredIp.ip.String()) // Remove from the pool
		revokedIps = append(revokedIps, expiredIp.ip)
		r.logger.Info("Removed expired IP", zap.String("domain", expiredIp.domain), zap.String("ip", expiredIp.ip.String()), zap.Time("expiration", expiredIp.expirationTime))
	}

	// If there are revoked IPs, notify the router
	if len(revokedIps) > 0 {
		r.router.RevokeASBRRoute(revokedIps)
		r.logger.Info("Revoked expired IPs", zap.Int("count", len(revokedIps)))
	}
}

// Init Initialize the IpPool and start the background expiration checker.
func (r *IpPool) Init() {
	r.logger.Info("IpPool initialized", zap.Duration("ttl", r.ttl))
	go r.startExpireChecker()
}
