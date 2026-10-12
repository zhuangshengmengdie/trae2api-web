// Package scheduler 定时任务：每日签到 + token 预刷新。
// 签到成功后重新查积分，积分 > 0 的冷却账号自动解冻。
//
// 自动签到保障：
//  1. 每日定时（CheckinHour）触发；
//  2. 启动后补签（RunCheckinOnStartup）：服务重启错过整点时不再漏签当天；
//  3. 签到前自动刷新临期 token；失败指数退避重试。
package scheduler

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"trae2api-web/internal/auth"
	"trae2api-web/internal/pool"
	"trae2api-web/internal/upstream"
)

// Config 调度器依赖。
type Config struct {
	Pool         *pool.Pool
	Upstream     *upstream.Client
	CheckinHour  int           // 每日签到小时，默认 9
	RefreshHours []int         // token 预刷新小时，默认 [3]
	RefreshSkew  time.Duration // 预刷新窗口，默认 24h
	// CheckinRetryBackoff 签到失败重试的基准退避，指数增长（backoff * 2^attempt），默认 10s。
	// 测试时可设为毫秒级。
	CheckinRetryBackoff time.Duration
	// CheckinMaxRetries 单账号签到最大重试次数（不含首次），默认 3。
	CheckinMaxRetries int
}

// CheckinResult 单账号签到结果。
type CheckinResult struct {
	UID    string `json:"uid"`
	Nick   string `json:"nick,omitempty"`
	Status string `json:"status"` // ok | already | failed | skipped | auth_invalid
	Detail string `json:"detail,omitempty"`
	Remain int64  `json:"remain,omitempty"`
}

// Scheduler 调度器。
type Scheduler struct {
	cfg Config
	mu  sync.Mutex // 串行化签到，避免定时/手动/启动补签并发
}

// New 构建。
func New(cfg Config) *Scheduler {
	if cfg.CheckinHour < 0 {
		cfg.CheckinHour = 9
	}
	if len(cfg.RefreshHours) == 0 {
		cfg.RefreshHours = []int{3}
	}
	if cfg.RefreshSkew <= 0 {
		cfg.RefreshSkew = 24 * time.Hour
	}
	if cfg.CheckinRetryBackoff <= 0 {
		cfg.CheckinRetryBackoff = 10 * time.Second
	}
	if cfg.CheckinMaxRetries <= 0 {
		cfg.CheckinMaxRetries = 3
	}
	return &Scheduler{cfg: cfg}
}

// nextFire 返回 now 之后最近的一个整点触发时间；hours 为本地小时（0-23）。
func nextFire(now time.Time, hours []int) time.Time {
	var earliest time.Time
	for _, h := range hours {
		t := time.Date(now.Year(), now.Month(), now.Day(), h, 0, 0, 0, now.Location())
		if !t.After(now) {
			t = t.Add(24 * time.Hour)
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	return earliest
}

// Run 主循环，阻塞直到 ctx 取消。
func (s *Scheduler) Run(ctx context.Context) {
	all := append(append([]int{}, s.cfg.RefreshHours...), s.cfg.CheckinHour)
	for {
		next := nextFire(time.Now(), all)
		timer := time.NewTimer(time.Until(next))
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			h := time.Now().Hour()
			if contains(s.cfg.RefreshHours, h) {
				s.RunRefreshNow()
			}
			if s.cfg.CheckinHour == h {
				s.RunCheckinNow()
			}
		}
	}
}

func contains(hours []int, h int) bool {
	for _, v := range hours {
		if v == h {
			return true
		}
	}
	return false
}

// RunCheckinOnStartup 启动后补签：等待 delay 让服务就绪，然后执行一次签到。
// CheckinStatus 本身幂等（已签到则跳过），因此服务在签到整点之后重启也不会漏签当天。
// ctx 取消则直接返回。
func (s *Scheduler) RunCheckinOnStartup(ctx context.Context, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	log.Printf("startup checkin: running catch-up checkin")
	results := s.RunCheckinNow()
	ok, already, fail := 0, 0, 0
	for _, r := range results {
		switch r.Status {
		case "ok":
			ok++
		case "already":
			already++
		default:
			fail++
		}
	}
	log.Printf("startup checkin: done ok=%d already=%d fail=%d", ok, already, fail)
}

// RunCheckinNow 立即对所有账号执行签到 + 积分刷新 + 解冻，返回逐账号结果。
// 冷却中的账号也参与（签到就是为了解冻它们）；禁用的跳过。
// 签到前若 token 在 2h 内过期则先刷新；单账号失败指数退避重试。
// 并发调用会被串行化。
func (s *Scheduler) RunCheckinNow() []CheckinResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	var results []CheckinResult
	for _, st := range s.cfg.Pool.List() {
		if st.Disabled {
			continue
		}
		a := s.cfg.Pool.AuthByUID(st.UID)
		if a == nil || a.RefreshTokenValue() == "" {
			continue
		}
		results = append(results, s.checkinOne(a, st.UID))
	}
	return results
}

// checkinOne 单账号签到全流程：预刷新 token → 查签到状态（重试）→ 未签则领取（重试）→ 查积分 + 解冻。
func (s *Scheduler) checkinOne(a *auth.Auth, uid string) CheckinResult {
	res := CheckinResult{UID: uid, Nick: a.Nickname}

	// 1. 签到前预刷新临期 token（2h 窗口），与 cmd/signin 保持一致。
	refreshed, err := s.cfg.Upstream.RefreshTokenIfNeeded(a, 2*time.Hour)
	if err != nil {
		var ue *upstream.Error
		if errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead {
			s.cfg.Pool.Disable(uid, "session dead (checkin pre-refresh)")
			res.Status = "auth_invalid"
			res.Detail = "refresh: " + err.Error()
			log.Printf("checkin %s: session dead, disabled", uid)
			return res
		}
		res.Status = "failed"
		res.Detail = "refresh: " + err.Error()
		log.Printf("checkin %s: pre-refresh failed: %v", uid, err)
		return res
	}
	if refreshed {
		if err := a.SaveAtomic(); err != nil {
			log.Printf("checkin %s: save refreshed token: %v", uid, err)
		} else {
			log.Printf("checkin %s: token pre-refreshed", uid)
		}
	}

	// 2. 查签到状态（重试）
	var checkedIn, enable bool
	var serr error
	for attempt := 0; ; attempt++ {
		checkedIn, _, enable, serr = s.cfg.Upstream.CheckinStatus(a)
		if serr == nil || attempt >= s.cfg.CheckinMaxRetries {
			break
		}
		backoff := s.cfg.CheckinRetryBackoff * time.Duration(1<<attempt)
		log.Printf("checkin status %s: %v (retry %d/%d in %v)", uid, serr, attempt+1, s.cfg.CheckinMaxRetries, backoff)
		time.Sleep(backoff)
	}
	if serr != nil {
		res.Status = "failed"
		res.Detail = "status: " + serr.Error()
		log.Printf("checkin status %s: %v", uid, serr)
		return res
	}
	if checkedIn {
		res.Status = "already"
		res.Detail = "already checked in"
		log.Printf("checkin %s: already checked in", uid)
	} else if !enable {
		res.Status = "skipped"
		res.Detail = "checkin disabled"
		log.Printf("checkin %s: checkin disabled, skipped", uid)
	} else {
		// 3. 领取（重试）
		var cerr error
		for attempt := 0; ; attempt++ {
			cerr = s.cfg.Upstream.CheckinClaim(a)
			if cerr == nil || attempt >= s.cfg.CheckinMaxRetries {
				break
			}
			backoff := s.cfg.CheckinRetryBackoff * time.Duration(1<<attempt)
			log.Printf("checkin claim %s: %v (retry %d/%d in %v)", uid, cerr, attempt+1, s.cfg.CheckinMaxRetries, backoff)
			time.Sleep(backoff)
		}
		if cerr != nil {
			res.Status = "failed"
			res.Detail = "claim: " + cerr.Error()
			log.Printf("checkin claim %s: %v", uid, cerr)
			return res
		}
		res.Status = "ok"
		log.Printf("checkin %s: ok", uid)
	}

	// 4. 查积分 + 解冻
	remain, err := s.cfg.Upstream.UserEntUsage(a)
	if err != nil {
		log.Printf("ent-usage %s: %v", uid, err)
		return res
	}
	res.Remain = remain
	s.cfg.Pool.ReenableIfCredits(uid, remain)
	return res
}

// RunRefreshNow 立即对所有账号刷新 token；session 失效的自动禁用。
func (s *Scheduler) RunRefreshNow() {
	for _, st := range s.cfg.Pool.List() {
		if st.Disabled {
			continue
		}
		a := s.cfg.Pool.AuthByUID(st.UID)
		if a == nil || a.RefreshTokenValue() == "" {
			continue
		}
		if !a.NeedsRefresh(s.cfg.RefreshSkew) {
			continue
		}
		if err := s.cfg.Upstream.RefreshToken(a); err != nil {
			log.Printf("refresh %s: %v", st.UID, err)
			var ue *upstream.Error
			if errors.As(err, &ue) && ue.Kind == upstream.ErrSessionDead {
				s.cfg.Pool.Disable(st.UID, "session dead")
			}
			continue
		}
		if err := a.SaveAtomic(); err != nil {
			log.Printf("refresh %s save: %v", st.UID, err)
		}
	}
}
