package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"gopkg.in/yaml.v3"
)

//go:embed templates/*
var templateFS embed.FS

var (
	dockerClient *client.Client
	labConfigs   map[string]LabConfig
	statsTracker *StatsTracker
	monitor      *Monitor
	labLocks     = NewLabLocks()
	labBindIP    = "127.0.0.1" // безопасный дефолт для уязвимых лабов; переопределяется LAB_BIND_IP
)

// ─────────────────────────── Конфигурация ───────────────────────────

// Duration — обёртка, чтобы yaml.v3 понимал строки вида "10s", "1m30s".
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	d.Duration = parsed
	return nil
}

// HealthcheckConfig — описание Docker-native healthcheck в YAML лаба:
//
//	healthcheck:
//	  test: "curl -fsS http://localhost:80/ || exit 1"
//	  interval: 10s
//	  timeout: 5s
//	  retries: 3
//	  start_period: 15s
type HealthcheckConfig struct {
	Test        string   `yaml:"test" json:"test"`
	Interval    Duration `yaml:"interval" json:"-"`
	Timeout     Duration `yaml:"timeout" json:"-"`
	Retries     int      `yaml:"retries" json:"retries"`
	StartPeriod Duration `yaml:"start_period" json:"-"`
}

type LabConfig struct {
	Name        string             `yaml:"name" json:"name"`
	Image       string             `yaml:"image" json:"image"`
	Description string             `yaml:"description" json:"description"`
	Category    string             `yaml:"category" json:"category"`
	Ports       []PortMapping      `yaml:"ports" json:"ports"`
	Env         map[string]string  `yaml:"env" json:"env"`
	Volumes     []string           `yaml:"volumes" json:"volumes"`
	Difficulty  string             `yaml:"difficulty" json:"difficulty"`
	Tags        []string           `yaml:"tags" json:"tags"`
	Healthcheck *HealthcheckConfig `yaml:"healthcheck" json:"healthcheck,omitempty"`
}

type PortMapping struct {
	Container string `yaml:"container" json:"container"`
	Host      string `yaml:"host" json:"host"`
}

// loadConfigs читает configs/*.yaml и configs/*.yml.
// Поддерживаются два формата:
//   - один лаб на файл;
//   - несколько лабов в одном файле, разделённых строкой "---"
//     (multi-document YAML). Несколько лабов подряд БЕЗ "---" — это
//     невалидный YAML (duplicate keys), такой файл будет отклонён.
func loadConfigs() error {
	labConfigs = make(map[string]LabConfig)

	files, err := filepath.Glob("configs/*.yaml")
	if err != nil {
		return err
	}
	if ymlFiles, err := filepath.Glob("configs/*.yml"); err == nil {
		files = append(files, ymlFiles...)
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			log.Printf("⚠️  Failed to open %s: %v", file, err)
			continue
		}

		dec := yaml.NewDecoder(f)
		docNum := 0
		for {
			var config LabConfig
			err := dec.Decode(&config)
			if err != nil {
				if errors.Is(err, io.EOF) {
					break
				}
				log.Printf("⚠️  Failed to parse %s (document #%d): %v", file, docNum+1, err)
				break // после ошибки парсинга остаток файла не читаем
			}
			docNum++

			// БАГФИКС: пустое имя раньше молча создавало запись с ключом ""
			if config.Name == "" || config.Image == "" {
				log.Printf("⚠️  Skipping %s (document #%d): 'name' and 'image' are required", file, docNum)
				continue
			}
			if _, dup := labConfigs[config.Name]; dup {
				log.Printf("⚠️  Duplicate lab name %q in %s, skipping", config.Name, file)
				continue
			}

			labConfigs[config.Name] = config
			log.Printf("✅ Loaded config: %s (%s)", config.Name, config.Image)
		}
		f.Close()
	}

	return nil
}

// ─────────────────────────── Статистика лабов ───────────────────────────

type LabStats struct {
	TotalStarts  int       `json:"total_starts"`
	LastStarted  time.Time `json:"last_started"`
	TotalRuntime int64     `json:"total_runtime_sec"`
	SuccessCount int       `json:"success_count"`
	FailureCount int       `json:"failure_count"`
}

type StatsTracker struct {
	mu        sync.RWMutex
	stats     map[string]*LabStats
	startedAt map[string]time.Time // для подсчёта TotalRuntime
}

func NewStatsTracker() *StatsTracker {
	return &StatsTracker{
		stats:     make(map[string]*LabStats),
		startedAt: make(map[string]time.Time),
	}
}

func (st *StatsTracker) RecordStart(labName string, success bool) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if st.stats[labName] == nil {
		st.stats[labName] = &LabStats{}
	}

	s := st.stats[labName]
	s.TotalStarts++
	s.LastStarted = time.Now()
	if success {
		s.SuccessCount++
		st.startedAt[labName] = time.Now()
	} else {
		s.FailureCount++
	}
}

// RecordStop накапливает время работы лаба (раньше TotalRuntime не заполнялся вовсе).
func (st *StatsTracker) RecordStop(labName string) {
	st.mu.Lock()
	defer st.mu.Unlock()

	if started, ok := st.startedAt[labName]; ok {
		if s := st.stats[labName]; s != nil {
			s.TotalRuntime += int64(time.Since(started).Seconds())
		}
		delete(st.startedAt, labName)
	}
}

// GetStats возвращает ГЛУБОКУЮ КОПИЮ.
// БАГФИКС: раньше возвращалась внутренняя map — JSON-сериализация читала её
// уже после снятия RLock, что при параллельном RecordStart приводило к панике
// "concurrent map read and map write".
func (st *StatsTracker) GetStats() map[string]LabStats {
	st.mu.RLock()
	defer st.mu.RUnlock()

	out := make(map[string]LabStats, len(st.stats))
	for name, s := range st.stats {
		out[name] = *s // копия значения, не указатель
	}
	return out
}

// ─────────────────────────── Per-lab мьютексы ───────────────────────────

// БАГФИКС: два одновременных POST /start одного лаба проходили проверку
// "не запущен" и оба пытались создать контейнер с одним именем.
type LabLocks struct {
	mu    sync.Mutex
	locks map[string]*sync.Mutex
}

func NewLabLocks() *LabLocks {
	return &LabLocks{locks: make(map[string]*sync.Mutex)}
}

func (l *LabLocks) Get(name string) *sync.Mutex {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.locks[name] == nil {
		l.locks[name] = &sync.Mutex{}
	}
	return l.locks[name]
}

// ─────────────────────────── Docker ───────────────────────────

func initDocker() {
	var err error
	dockerClient, err = client.NewClientWithOpts(
		client.FromEnv,
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		log.Printf("⚠️  Docker client init error: %v", err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err = dockerClient.Ping(ctx); err != nil {
		log.Printf("⚠️  Docker daemon not available: %v", err)
		dockerClient = nil
	} else {
		log.Println("✅ Docker daemon: connected")
	}
}

// findContainerExact ищет контейнер по ТОЧНОМУ имени.
// БАГФИКС: фильтр "name" в Docker API — это поиск по подстроке, поэтому
// "web-lab" раньше совпадал с "web-lab-2" и код мог снести чужой контейнер.
func findContainerExact(ctx context.Context, name string) (*types.Container, error) {
	containers, err := dockerClient.ContainerList(ctx, types.ContainerListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", name)),
	})
	if err != nil {
		return nil, err
	}
	for i := range containers {
		for _, n := range containers[i].Names {
			if strings.TrimPrefix(n, "/") == name {
				return &containers[i], nil
			}
		}
	}
	return nil, nil
}

// ensureImage тянет образ только если его нет локально и разбирает ошибки
// из JSON-стрима.
// БАГФИКС: io.Copy(io.Discard, ...) глотал ошибки — Docker сообщает о
// проблемах pull внутри стрима, а не через возврат ImagePull.
func ensureImage(ctx context.Context, imageName string) error {
	if _, _, err := dockerClient.ImageInspectWithRaw(ctx, imageName); err == nil {
		return nil // образ уже есть — не тратим время на pull
	}

	log.Printf("📥 Pulling image %s...", imageName)
	reader, err := dockerClient.ImagePull(ctx, imageName, types.ImagePullOptions{})
	if err != nil {
		return err
	}
	defer reader.Close()

	dec := json.NewDecoder(reader)
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, context.DeadlineExceeded) || err.Error() == "EOF" {
				break
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			break // EOF или конец стрима
		}
		if msg.Error != "" {
			return errors.New(msg.Error)
		}
	}
	return nil
}

// ReadyResult — итог ожидания готовности контейнера.
type ReadyResult struct {
	Healthy bool   // проба Docker дошла до "healthy"
	Health  string // "healthy" | "unhealthy" | "starting" | "none"
}

// waitForContainerReady ждёт готовности контейнера после старта.
//
// Философия для пентест-полигона: стенд готов, когда его порт начинает
// отвечать С ХОСТА — именно так его видит пользователь. На внутренний
// Docker HEALTHCHECK не полагаемся: он часто ложноотрицательный (нет
// curl/wget/node в образе, приложение слушает другой интерфейс и т.п.),
// при том что снаружи стенд уже полностью доступен.
//
// Ошибку возвращаем только если контейнер реально упал. Если порт так и не
// ответил до таймаута, но контейнер жив — отдаём degraded, а не ошибку.
func waitForContainerReady(ctx context.Context, id, hostPort string, timeout time.Duration) (ReadyResult, error) {
	deadline := time.Now().Add(timeout)

	for {
		inspect, err := dockerClient.ContainerInspect(ctx, id)
		if err != nil {
			return ReadyResult{}, err
		}
		if inspect.State == nil || !inspect.State.Running {
			return ReadyResult{}, errors.New("container stopped unexpectedly right after start")
		}

		// Нет проброшенного порта — проверить доступность снаружи нечем,
		// полагаемся на то, что процесс жив.
		if hostPort == "" {
			return ReadyResult{Healthy: true, Health: "none"}, nil
		}

		// Основной критерий: порт отвечает с хоста.
		if probePort(hostPort) {
			return ReadyResult{Healthy: true, Health: "healthy"}, nil
		}

		// Время вышло — контейнер жив, но порт пока молчит.
		// Не ошибка старта: возвращаем degraded, стенд считается запущенным.
		if !time.Now().Before(deadline) {
			return ReadyResult{Healthy: false, Health: "starting"}, nil
		}

		select {
		case <-ctx.Done():
			return ReadyResult{}, ctx.Err()
		case <-time.After(time.Second):
		}
	}
}

// ─────────────────────────── Фоновый монитор ───────────────────────────

type SystemStats struct {
	CPU      float64 `json:"cpu"`
	RAM      float64 `json:"ram"`
	RAMUsed  uint64  `json:"ram_used_mb"`
	RAMTotal uint64  `json:"ram_total_mb"`
}

type ContainerInfo struct {
	Status       string `json:"status"`
	Health       string `json:"health,omitempty"`        // итоговое состояние для дашборда
	DockerHealth string `json:"docker_health,omitempty"` // "сырой" статус Docker HEALTHCHECK (для отладки)
	Reachable    bool   `json:"reachable"`               // порт реально отвечает с хоста
	IP           string `json:"ip"`
	Port         string `json:"port"`
	URL          string `json:"url"`
	LabName      string `json:"lab_name"`
}

// probePort проверяет, слушает ли кто-то опубликованный порт лаба, с той же
// стороны, с которой к стенду обращается пользователь — с хоста.
// Это надёжнее внутриконтейнерного HEALTHCHECK: не зависит от наличия
// curl/wget/node в образе и от того, на каком интерфейсе слушает приложение.
func probePort(hostPort string) bool {
	if hostPort == "" {
		return false
	}
	// Порты публикуются на labBindIP; если это 0.0.0.0 — стучимся в loopback.
	dialIP := labBindIP
	if dialIP == "0.0.0.0" || dialIP == "" {
		dialIP = "127.0.0.1"
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(dialIP, hostPort), 1500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// Monitor раз в interval собирает метрики в фоне и кэширует их.
// ПРОИЗВОДИТЕЛЬНОСТЬ: /api/status теперь отдаёт кэш мгновенно, вместо того
// чтобы на каждый HTTP-запрос ходить в Docker и делать N последовательных
// ContainerInspect. Заодно CPU меряется с честным интервалом в 1 секунду
// (cpu.Percent(0, ...) на первом вызове возвращал мусор).
type Monitor struct {
	mu         sync.RWMutex
	system     SystemStats
	containers []ContainerInfo
	interval   time.Duration
}

func NewMonitor(interval time.Duration) *Monitor {
	return &Monitor{interval: interval, containers: []ContainerInfo{}}
}

func (m *Monitor) Run(ctx context.Context) {
	m.collect(ctx) // первый сбор сразу, чтобы кэш не был пустым
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Monitor stopped")
			return
		case <-ticker.C:
			m.collect(ctx)
		}
	}
}

func (m *Monitor) collect(ctx context.Context) {
	var (
		wg      sync.WaitGroup
		sys     SystemStats
		conts   []ContainerInfo
	)

	// Системные метрики и контейнеры собираем параллельно.
	wg.Add(2)

	go func() {
		defer wg.Done()
		// В фоне можно позволить себе блокирующий замер — так точнее.
		if pct, err := cpu.PercentWithContext(ctx, time.Second, false); err == nil && len(pct) > 0 {
			sys.CPU = pct[0]
		}
		if vm, err := mem.VirtualMemory(); err == nil && vm != nil {
			sys.RAM = vm.UsedPercent
			sys.RAMUsed = vm.Used / (1024 * 1024)
			sys.RAMTotal = vm.Total / (1024 * 1024)
		}
	}()

	go func() {
		defer wg.Done()
		conts = collectContainers(ctx)
	}()

	wg.Wait()

	m.mu.Lock()
	m.system = sys
	m.containers = conts
	m.mu.Unlock()
}

func collectContainers(ctx context.Context) []ContainerInfo {
	if dockerClient == nil {
		return []ContainerInfo{}
	}

	listCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	containers, err := dockerClient.ContainerList(listCtx, types.ContainerListOptions{All: true})
	if err != nil {
		log.Printf("Container list error: %v", err)
		return []ContainerInfo{}
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		result []ContainerInfo
	)

	for _, c := range containers {
		labName := ""
		for _, name := range c.Names {
			n := strings.TrimPrefix(name, "/")
			if _, ok := labConfigs[n]; ok {
				labName = n
				break
			}
		}
		if labName == "" {
			continue
		}

		if c.State != "running" {
			mu.Lock()
			result = append(result, ContainerInfo{LabName: labName, Status: "stopped"})
			mu.Unlock()
			continue
		}

		// ПРОИЗВОДИТЕЛЬНОСТЬ: inspect каждого контейнера — в своей горутине,
		// раньше они шли последовательно (N+1 запросов к Docker).
		wg.Add(1)
		go func(id, labName string) {
			defer wg.Done()

			info := ContainerInfo{LabName: labName, Status: "running"}
			inspect, err := dockerClient.ContainerInspect(listCtx, id)
			if err == nil {
				info.IP = inspect.NetworkSettings.IPAddress
				// БАГФИКС: в кастомных сетях IPAddress пустой — берём из Networks.
				if info.IP == "" {
					for _, netw := range inspect.NetworkSettings.Networks {
						if netw.IPAddress != "" {
							info.IP = netw.IPAddress
							break
						}
					}
				}
				if inspect.State != nil && inspect.State.Health != nil {
					info.DockerHealth = inspect.State.Health.Status
				}
				if cfg, ok := labConfigs[labName]; ok && len(cfg.Ports) > 0 {
					info.Port = cfg.Ports[0].Host
					info.URL = fmt.Sprintf("http://localhost:%s", info.Port)
				}
			}

			// Ground truth: отвечает ли порт с хоста. Именно это ощущает
			// пользователь как "стенд работает".
			info.Reachable = probePort(info.Port)

			// Итоговый Health для дашборда:
			//  - порт отвечает            → healthy (стенд пригоден);
			//  - не отвечает, Docker ещё
			//    рапортует "starting"      → starting (даём время подняться);
			//  - иначе                     → unhealthy.
			switch {
			case info.Reachable:
				info.Health = "healthy"
			case info.DockerHealth == "starting":
				info.Health = "starting"
			case info.Port == "":
				// у лаба нет проброшенного порта — полагаемся на Docker (или "none")
				if info.DockerHealth != "" {
					info.Health = info.DockerHealth
				} else {
					info.Health = "healthy" // running без порта и без пробы — считаем ок
				}
			default:
				info.Health = "unhealthy"
			}

			mu.Lock()
			result = append(result, info)
			mu.Unlock()
		}(c.ID, labName)
	}

	wg.Wait()
	if result == nil {
		result = []ContainerInfo{}
	}
	return result
}

func (m *Monitor) Snapshot() (SystemStats, []ContainerInfo) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// Копия среза, чтобы кэш нельзя было изменить снаружи.
	conts := make([]ContainerInfo, len(m.containers))
	copy(conts, m.containers)
	return m.system, conts
}

// ─────────────────────────── HTTP-хендлеры ───────────────────────────

type StatusResponse struct {
	System     SystemStats     `json:"system"`
	Containers []ContainerInfo `json:"containers"`
	Message    string          `json:"message,omitempty"`
}

// healthzHandler — healthcheck самого приложения (для мониторинга,
// докеровского HEALTHCHECK, k8s liveness probe и т.п.).
func healthzHandler(c *gin.Context) {
	status := http.StatusOK
	checks := gin.H{
		"configs_loaded": len(labConfigs),
		"docker":         "ok",
	}

	if dockerClient == nil {
		checks["docker"] = "unavailable"
		status = http.StatusServiceUnavailable
	} else {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if _, err := dockerClient.Ping(ctx); err != nil {
			checks["docker"] = fmt.Sprintf("ping failed: %v", err)
			status = http.StatusServiceUnavailable
		}
	}

	checks["status"] = map[bool]string{true: "ok", false: "degraded"}[status == http.StatusOK]
	c.JSON(status, checks)
}

func listLabsHandler(c *gin.Context) {
	labs := make([]LabConfig, 0, len(labConfigs))
	for _, config := range labConfigs {
		labs = append(labs, config)
	}
	c.JSON(http.StatusOK, labs)
}

func startContainerHandler(c *gin.Context) {
	labName := c.Param("name")

	config, exists := labConfigs[labName]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Lab '%s' not found", labName)})
		return
	}

	if dockerClient == nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker is not available"})
		return
	}

	// Сериализуем операции над конкретным лабом.
	lock := labLocks.Get(labName)
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	existing, err := findContainerExact(ctx, config.Name)
	if err != nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to list containers: %v", err)})
		return
	}
	if existing != nil {
		if existing.State == "running" {
			c.JSON(http.StatusOK, gin.H{"message": "Container already running"})
			return
		}
		if err := dockerClient.ContainerRemove(ctx, existing.ID, types.ContainerRemoveOptions{Force: true}); err != nil {
			statsTracker.RecordStart(labName, false)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove stale container: %v", err)})
			return
		}
	}

	if err := ensureImage(ctx, config.Image); err != nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to pull image: %v", err)})
		return
	}

	// Порты. БАГФИКС/БЕЗОПАСНОСТЬ: раньше был bind на 0.0.0.0 —
	// уязвимые лабы торчали наружу во всю сеть.
	portBindings := nat.PortMap{}
	exposedPorts := nat.PortSet{}
	for _, port := range config.Ports {
		contPort := nat.Port(port.Container)
		exposedPorts[contPort] = struct{}{}
		portBindings[contPort] = []nat.PortBinding{
			{HostIP: labBindIP, HostPort: port.Host},
		}
	}

	hostConfig := &container.HostConfig{
		PortBindings: portBindings,
		Binds:        config.Volumes, // БАГФИКС: Volumes читались из YAML, но не подключались
	}

	env := make([]string, 0, len(config.Env))
	for k, v := range config.Env {
		env = append(env, fmt.Sprintf("%s=%s", k, v))
	}

	containerConfig := &container.Config{
		Image:        config.Image,
		ExposedPorts: exposedPorts,
		Env:          env,
	}

	// Docker-native healthcheck из YAML.
	if hc := config.Healthcheck; hc != nil && hc.Test != "" {
		containerConfig.Healthcheck = &container.HealthConfig{
			Test:        []string{"CMD-SHELL", hc.Test},
			Interval:    hc.Interval.Duration,
			Timeout:     hc.Timeout.Duration,
			Retries:     hc.Retries,
			StartPeriod: hc.StartPeriod.Duration,
		}
	}

	resp, err := dockerClient.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, config.Name)
	if err != nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to create container: %v", err)})
		return
	}

	if err := dockerClient.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to start container: %v", err)})
		return
	}

	// Порт, по которому проверяем доступность стенда с хоста.
	hostPort := ""
	if len(config.Ports) > 0 {
		hostPort = config.Ports[0].Host
	}

	// Дожидаемся готовности: стенд готов, когда порт отвечает с хоста.
	ready, err := waitForContainerReady(ctx, resp.ID, hostPort, 90*time.Second)
	if err != nil {
		statsTracker.RecordStart(labName, false)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("Container failed to start: %v", err),
		})
		return
	}

	statsTracker.RecordStart(labName, true)

	msg := fmt.Sprintf("🚀 %s запущен и отвечает", config.Name)
	if !ready.Healthy {
		// Процесс поднялся, но порт ещё не ответил в отведённое окно.
		msg = fmt.Sprintf("🚀 %s запущен — порт пока не ответил, стенд может ещё подниматься", config.Name)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": msg,
		"health":  ready.Health,
		"lab":     config,
	})
}

func stopContainerHandler(c *gin.Context) {
	labName := c.Param("name")

	if _, exists := labConfigs[labName]; !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Lab '%s' not found", labName)})
		return
	}
	if dockerClient == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Docker is not available"})
		return
	}

	lock := labLocks.Get(labName)
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// БАГФИКС: раньше ошибки игнорировались и хендлер всегда отвечал успехом,
	// даже если контейнера не существовало.
	existing, err := findContainerExact(ctx, labName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to list containers: %v", err)})
		return
	}
	if existing == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Container is not running"})
		return
	}

	if err := dockerClient.ContainerStop(ctx, existing.ID, container.StopOptions{}); err != nil {
		log.Printf("⚠️  Stop error for %s (will force remove): %v", labName, err)
	}
	if err := dockerClient.ContainerRemove(ctx, existing.ID, types.ContainerRemoveOptions{Force: true}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to remove container: %v", err)})
		return
	}

	statsTracker.RecordStop(labName)
	c.JSON(http.StatusOK, gin.H{"message": "Container stopped and removed"})
}

func statusHandler(c *gin.Context) {
	system, containers := monitor.Snapshot() // мгновенный ответ из кэша

	resp := StatusResponse{
		System:     system,
		Containers: containers,
	}
	if dockerClient == nil {
		resp.Message = "Docker is not available."
	}

	c.JSON(http.StatusOK, resp)
}

func adminStatsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"labs":      statsTracker.GetStats(),
		"timestamp": time.Now(),
	})
}

func serveTemplate(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := templateFS.ReadFile("templates/" + name)
		if err != nil {
			c.String(http.StatusInternalServerError, "Template error: %v", err)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}
}

// ─────────────────────────── main ───────────────────────────

func main() {
	gin.SetMode(gin.ReleaseMode)

	statsTracker = NewStatsTracker()

	if ip := os.Getenv("LAB_BIND_IP"); ip != "" {
		labBindIP = ip
	}

	log.Println("📋 Loading lab configurations...")
	if err := loadConfigs(); err != nil {
		log.Printf("⚠️  Failed to load configs: %v", err)
	}

	log.Println("🐳 Initializing Docker client...")
	initDocker()

	// Контекст, который отменяется по SIGINT/SIGTERM — им живут фоновые горутины.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	monitor = NewMonitor(3 * time.Second)
	go monitor.Run(ctx)

	r := gin.Default()

	r.GET("/", serveTemplate("index.html"))
	r.GET("/admin", serveTemplate("admin.html"))

	// API endpoints
	r.GET("/healthz", healthzHandler)
	r.GET("/api/status", statusHandler)
	r.GET("/api/labs", listLabsHandler)
	r.POST("/api/lab/:name/start", startContainerHandler)
	r.POST("/api/lab/:name/stop", stopContainerHandler)
	r.GET("/api/admin/stats", adminStatsHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	srv := &http.Server{
		Addr:              "0.0.0.0:" + port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		log.Printf("")
		log.Printf("═══════════════════════════════════════════")
		log.Printf("🚀  CyberRange MVP запущен!")
		log.Printf("🌐  Dashboard:        http://localhost:%s", port)
		log.Printf("📊  Admin Panel:      http://localhost:%s/admin", port)
		log.Printf("❤️   Healthcheck:      http://localhost:%s/healthz", port)
		log.Printf("📋  Loaded %d lab configs", len(labConfigs))
		log.Printf("🔒  Lab port bind IP: %s", labBindIP)
		log.Printf("═══════════════════════════════════════════")
		log.Printf("")

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// Graceful shutdown: раньше r.Run() убивался жёстко, обрывая
	// запросы и фоновые операции на середине.
	<-ctx.Done()
	log.Println("🛑 Shutting down gracefully...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("⚠️  Shutdown error: %v", err)
	}
	log.Println("👋 Bye")
}	