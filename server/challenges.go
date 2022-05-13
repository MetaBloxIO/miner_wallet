package server

import (
	"errors"
	"math/rand"
	"time"
)

const timeout = 10

type ChallengeRecord struct {
	Time            time.Time
	SelfChallenge   uint64
	TargetChallenge uint64
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

func (p *ChallengePool) ApplyChallenge(session string, targetChallenge uint64) (uint64, error) {
	record := ChallengeRecord{Time: time.Now(), SelfChallenge: rand.Uint64(), TargetChallenge: targetChallenge}
	p.sessions[session] = record
	return record.SelfChallenge, nil
}

func (p *ChallengePool) CheckChallenge(session string, challenge uint64) bool {
	c1, exists := p.sessions[session]
	if exists == false {
		return false
	}
	//delete(p.sessions, session)

	if c1.SelfChallenge != challenge {
		return false
	}

	t := time.Now()
	if t.UnixMilli()-c1.Time.UnixMilli() > timeout*1000 {
		return false
	}

	return true
}

func (p *ChallengePool) GetTargetChallenge(session string) (uint64, error) {
	c1, exists := p.sessions[session]
	if exists == false {
		return 0, errors.New("SessionNotFound")
	}

	return c1.TargetChallenge, nil
}

func (p *ChallengePool) IncrSelfChallenge(session string) error {
	c1, exists := p.sessions[session]
	if exists == false {
		return errors.New("SessionNotFound")
	}

	c1.SelfChallenge++
	return nil
}

func (p *ChallengePool) IncrTargetChallenge(session string) error {
	c1, exists := p.sessions[session]
	if exists == false {
		return errors.New("SessionNotFound")
	}

	c1.TargetChallenge++
	return nil
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
