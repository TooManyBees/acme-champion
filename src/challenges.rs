use std::collections::LinkedList;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    pub domain: String,
    pub name: String,
    pub value: String,
}

impl Challenge {
    pub fn matches(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

#[derive(Debug)]
pub struct Challenges(LinkedList<Challenge>);

impl Challenges {
    const MAX_LEN: usize = 100;

    pub fn new() -> Challenges {
        Challenges(LinkedList::new())
    }

    pub fn any(&self, name: &str) -> bool {
        for c in &self.0 {
            if c.matches(name) {
                return true;
            }
        }
        false
    }

    pub fn named(&self, name: &str) -> impl Iterator<Item = &str> {
        self.0
            .iter()
            .filter(|c| c.matches(name))
            .map(|c| c.value.as_str())
    }

    pub fn set(&mut self, challenge: Challenge) {
        self.0.push_back(challenge);
        if self.0.len() > Self::MAX_LEN {
            self.0.pop_front();
        }
    }

    pub fn cleanup(&mut self, challenge: &Challenge) {
        self.0.extract_if(|c| c == challenge).for_each(drop);
    }
}

#[cfg(test)]
mod test {
    use super::{Challenge, Challenges};

    #[test]
    fn any() {
        let mut challenges = Challenges::new();

        challenges.set(Challenge {
            domain: "domain".into(),
            name: "incorrect_name".into(),
            value: "value".into(),
        });

        assert!(!challenges.any("name"));

        challenges.set(Challenge {
            domain: "domain".into(),
            name: "name".into(),
            value: "value".into(),
        });

        assert!(challenges.any("name"));
    }

    #[test]
    fn named() {
        let mut challenges = Challenges::new();

        challenges.set(Challenge {
            domain: "wrong.example".into(),
            name: "_acme-challenge.wrong.example.com".into(),
            value: "wrong value".into(),
        });

        challenges.set(Challenge {
            domain: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "correct value 1".into(),
        });

        challenges.set(Challenge {
            domain: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "correct value 2".into(),
        });

        let mut result = challenges.named("_acme-challenge.example.com");
        assert_eq!(result.next(), Some("correct value 1"));
        assert_eq!(result.next(), Some("correct value 2"));
        assert_eq!(result.next(), None);
    }

    #[test]
    fn cleanup() {
        let mut challenges = Challenges::new();

        let challenge = Challenge {
            domain: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "value".into(),
        };

        let other_challenge_1 = Challenge {
            domain: "wrong.example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "value".into(),
        };

        let other_challenge_2 = Challenge {
            domain: "example.com".into(),
            name: "_acme-challenge.example.com".into(),
            value: "wrong value".into(),
        };

        let other_challenge_3 = Challenge {
            domain: "example.com".into(),
            name: "_acme-challenge.wrong.example.com".into(),
            value: "value".into(),
        };

        challenges.set(challenge.clone());
        challenges.set(other_challenge_1.clone());
        challenges.set(other_challenge_2.clone());
        challenges.set(other_challenge_3.clone());
        challenges.cleanup(&challenge);

        let mut challenges = challenges.0.into_iter();
        assert_eq!(challenges.next(), Some(other_challenge_1));
        assert_eq!(challenges.next(), Some(other_challenge_2));
        assert_eq!(challenges.next(), Some(other_challenge_3));
        assert_eq!(challenges.next(), None);
    }

    #[test]
    fn does_not_exceed_max_length() {
        let mut challenges = Challenges::new();

        for _ in 0..(Challenges::MAX_LEN + 5) {
            challenges.set(Challenge {
                domain: "domain".into(),
                name: "name".into(),
                value: "value".into(),
            });
        }

        assert_eq!(challenges.0.len(), Challenges::MAX_LEN);
    }
}
