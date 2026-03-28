use std::collections::LinkedList;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Challenge {
    pub domain: String,
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct Challenges(RwLock<LinkedList<Challenge>>);

impl Challenges {
    pub fn new() -> Challenges {
        Challenges(RwLock::new(LinkedList::new()))
    }

    fn read(&self) -> RwLockReadGuard<'_, LinkedList<Challenge>> {
        self.0
            .read()
            .expect("lock can't be poisoned in a single-threaded program")
    }

    fn write(&self) -> RwLockWriteGuard<'_, LinkedList<Challenge>> {
        self.0
            .write()
            .expect("lock can't be poisoned in a single-threaded program")
    }

    pub fn all(&self) -> RwLockReadGuard<'_, LinkedList<Challenge>> {
        self.read()
    }

    pub fn any(&self, name: &str) -> bool {
        for c in self.read().iter() {
            if c.name == name {
                return true;
            }
        }
        false
    }

    pub fn named(&self, name: &str) -> Vec<String> {
        let mut matching = Vec::with_capacity(1);
        for c in self.read().iter() {
            if c.name == name {
                matching.push(c.value.clone())
            }
        }
        matching
    }

    pub fn set(&self, challenge: Challenge) {
        let mut cs = self.write();
        cs.push_back(challenge);
    }

    pub fn cleanup(&self, challenge: &Challenge) {
        let mut cs = self.write();
        cs.extract_if(|c| c == challenge).for_each(drop);
    }
}
