package server

import (
	"math/rand"
	"time"
)

const timeout = 10

type ChallengeRecord struct {
	Time      time.Time
	Challenge uint64
}

type ChallengePool struct {
	timer    *time.Timer
	stop     chan struct{}
	sessions map[string]ChallengeRecord
}

func NewChallengePool() *ChallengePool {
	pool := &ChallengePool{
		timer:    time.NewTimer(time.Second * timeout * 5),
		stop:     make(chan struct{}),
		sessions: make(map[string]ChallengeRecord)}

	go func(pool *ChallengePool) {
		select {
		case <-pool.timer.C:
			pool.ClearTimeoutSessions()

		case <-pool.stop:
			break
		}
	}(pool)
	return pool
}

func (p *ChallengePool) ApplyChallenge(session string) (uint64, error) {
	record := ChallengeRecord{Time: time.Now(), Challenge: rand.Uint64()}
	p.sessions[session] = record
	return record.Challenge, nil
}

func (p *ChallengePool) CheckChallenge(session string, challenge uint64) bool {
	c1, exists := p.sessions[session]
	if exists == false {
		return false
	}
	//delete(p.sessions, session)

	if c1.Challenge != challenge {
		return false
	}

	t := time.Now()
	if t.UnixMilli()-c1.Time.UnixMilli() > timeout*1000 {
		return false
	}

	return true
}

func (p *ChallengePool) ClearTimeoutSessions() {
	t := time.Now()
	for session, c := range p.sessions {
		if t.UnixMilli()-c.Time.UnixMilli() > timeout*1000 {
			delete(p.sessions, session)
		}
	}
}

func (p *ChallengePool) StopPool() {
	p.stop <- struct{}{}
}
