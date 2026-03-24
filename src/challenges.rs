use std::collections::LinkedList;
use tokio::sync::{Mutex, MutexGuard};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    pub domain: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct Challenges(Mutex<LinkedList<Challenge>>);

impl Challenges {
    pub fn new() -> Challenges {
        Challenges(Mutex::new(LinkedList::new()))
    }

    pub async fn all(&self) -> MutexGuard<'_, LinkedList<Challenge>> {
        self.0.lock().await
    }

    pub async fn any(&self, name: &str) -> bool {
        let cs = self.0.lock().await;
        for c in cs.iter() {
            if c.name == name {
                return true;
            }
        }
        false
    }

    pub async fn named(&self, name: &str) -> Vec<String> {
        let cs = self.0.lock().await;
        let mut matching = Vec::with_capacity(1);
        for c in cs.iter() {
            if c.name == name {
                matching.push(c.value.clone())
            }
        }
        matching
    }

    pub async fn set(&self, challenge: Challenge) {
        let mut cs = self.0.lock().await;
        cs.push_back(challenge);
    }

    pub async fn cleanup(&self, challenge: &Challenge) {
        let mut cs = self.0.lock().await;
        cs.extract_if(|c| c == challenge).for_each(drop);
    }
}
