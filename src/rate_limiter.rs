use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct RateLimiter {
    states: HashMap<IpAddr, State>,
}

impl RateLimiter {
    const BLOCK_DURATION_SECS: i64 = 60 * 10;
    const WINDOW_SECS: i64 = 60;
    const RATE_LIMIT: u8 = 100;
    const MAX_SIZE: usize = 100;

    pub fn new() -> Self {
        RateLimiter {
            states: HashMap::new(),
        }
    }

    pub fn increment(&mut self, src_addr: IpAddr) -> RateLimitResult {
        let now = now_secs();

        let starting_len = self.states.len();
        if starting_len >= Self::MAX_SIZE {
            self.cleanup(now);
            if self.states.len() >= Self::MAX_SIZE {
                log::trace!(addr:% = src_addr; "shortcircuiting blocked (at capacity)");
                return RateLimitResult::Block;
            }
            if self.states.len() != starting_len {
                let count = starting_len - self.states.len();
                log::trace!(count; "purged all expired entries");
            }
        }

        let entry = self
            .states
            .entry(src_addr)
            .or_insert(State::KnownSince(now, 0));
        match entry {
            State::KnownSince(start, count) => {
                if now > *start + Self::WINDOW_SECS {
                    *entry = State::KnownSince(now, 1);
                    log::trace!(addr:% = src_addr; "resetting expired counter");
                    return RateLimitResult::Ok;
                }

                *count += 1;

                if *count >= Self::RATE_LIMIT {
                    let until = now + Self::BLOCK_DURATION_SECS;
                    *entry = State::BlockedUntil(until);
                    log::warn!(addr:% = src_addr, until; "blocking new IP");
                    return RateLimitResult::Block;
                }

                log::trace!(addr:% = src_addr, count = *count; "request rate within limits");
                return RateLimitResult::Ok;
            }
            State::BlockedUntil(end) => {
                if now > *end {
                    *entry = State::KnownSince(now, 1);
                    log::trace!(addr:% = src_addr; "resetting expired block");
                    return RateLimitResult::Ok;
                } else {
                    log::trace!(addr:% = src_addr; "request rate exceeded limits");
                    return RateLimitResult::Block;
                }
            }
        }
    }

    fn cleanup(&mut self, now: i64) {
        self.states.retain(|_, state| match state {
            State::KnownSince(start, _) => now < *start + Self::WINDOW_SECS,
            State::BlockedUntil(end) => now < *end,
        });
    }
}

#[derive(Debug)]
enum State {
    KnownSince(i64, u8),
    BlockedUntil(i64),
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RateLimitResult {
    Ok,
    Block,
}

fn now_secs() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(e) => e.duration().as_secs() as i64 * -1,
    }
}

#[cfg(test)]
mod test {
    use super::{RateLimitResult, RateLimiter, State, now_secs};
    use std::assert_matches;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn allows_a_new_ip() {
        let mut rate_limiter = RateLimiter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let result = rate_limiter.increment(addr);
        assert_eq!(result, RateLimitResult::Ok);
    }

    #[test]
    fn blocks_a_known_ip_after_limit() {
        let mut rate_limiter = RateLimiter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let mut result = RateLimitResult::Ok;
        for _ in 0..RateLimiter::RATE_LIMIT as usize {
            result = rate_limiter.increment(addr);
        }
        assert_eq!(result, RateLimitResult::Block);
    }

    #[test]
    fn resets_count_after_timeout() {
        let mut rate_limiter = RateLimiter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let time_in_the_past = now_secs() - RateLimiter::WINDOW_SECS * 2;
        rate_limiter.states.insert(
            addr,
            State::KnownSince(time_in_the_past, RateLimiter::RATE_LIMIT),
        );
        let result = rate_limiter.increment(addr);
        assert_eq!(result, RateLimitResult::Ok);
        assert_matches!(rate_limiter.states[&addr], State::KnownSince(_, 1));
    }

    #[test]
    fn resets_a_block_after_timeout() {
        let mut rate_limiter = RateLimiter::new();
        let addr = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let time_in_the_past = now_secs() - RateLimiter::BLOCK_DURATION_SECS * 2;
        rate_limiter
            .states
            .insert(addr, State::BlockedUntil(time_in_the_past));
        let result = rate_limiter.increment(addr);
        assert_eq!(result, RateLimitResult::Ok);
        assert_matches!(rate_limiter.states[&addr], State::KnownSince(_, 1));
    }

    #[test]
    fn short_circuits_blocked_at_max_capacity() {
        let mut rate_limiter = RateLimiter::new();
        for n in 0..RateLimiter::MAX_SIZE as u8 {
            let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, n));
            rate_limiter.increment(addr);
        }
        assert_eq!(rate_limiter.states.len(), RateLimiter::MAX_SIZE);
        let addr = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 255));
        let result = rate_limiter.increment(addr);
        assert_eq!(result, RateLimitResult::Block);
    }

    #[test]
    fn cleans_up_old_entries_at_max_capacity() {
        let mut rate_limiter = RateLimiter::new();
        for n in 0..RateLimiter::MAX_SIZE as u8 {
            let addr = IpAddr::V4(Ipv4Addr::new(0, 0, 0, n));
            rate_limiter.increment(addr);
        }
        assert_eq!(rate_limiter.states.len(), RateLimiter::MAX_SIZE);
        for state in rate_limiter.states.values_mut() {
            match state {
                State::KnownSince(time, _) => *time -= RateLimiter::WINDOW_SECS * 2,
                State::BlockedUntil(time) => *time -= RateLimiter::BLOCK_DURATION_SECS * 2,
            }
        }
        let addr = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 255));
        let result = rate_limiter.increment(addr);
        assert_eq!(result, RateLimitResult::Ok);
        assert!(rate_limiter.states.len() < RateLimiter::MAX_SIZE);
    }
}
