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

    pub fn named(&self, name: &str) -> Vec<String> {
        let mut matching = Vec::with_capacity(1);
        for c in &self.0 {
            if c.matches(name) {
                matching.push(c.value.clone())
            }
        }
        matching
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
