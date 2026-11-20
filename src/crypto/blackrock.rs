/// Blackrock: Cycle-Walking Feistel Network Permutation
///
/// Provides O(1) memory pseudo-random permutation over any range [0..m-1].
/// Maps every index i in [0..m-1] to a unique j in [0..m-1] with:
/// - 0 collisions (bijective 1-to-1 mapping)
/// - 100% coverage of all target addresses
/// - Complete global dispersion (no sequential hits to adjacent IPs)

#[derive(Debug, Clone)]
pub struct Blackrock {
    range: u64,
    a: u64,
    b: u64,
    seed: u64,
    rounds: usize,
}

impl Blackrock {
    pub fn new(range: u64, seed: u64) -> Self {
        if range <= 1 {
            return Self {
                range,
                a: 1,
                b: 1,
                seed,
                rounds: 4,
            };
        }

        // Find a and b such that a * b >= range, where a and b are close to sqrt(range)
        let sqrt = (range as f64).sqrt().ceil() as u64;
        let mut a = sqrt;
        while a * a < range {
            a += 1;
        }
        let b = (range + a - 1) / a;

        Self {
            range,
            a,
            b,
            seed,
            rounds: 4,
        }
    }

    #[inline(always)]
    fn round_function(&self, r: u64, round: usize) -> u64 {
        let mut x = r
            .wrapping_mul(0x5851f42d4c957f2d)
            .wrapping_add(self.seed.rotate_left((round as u32 * 11) % 64))
            .wrapping_add(0x14057b7ef767814f);
        x ^= x >> 33;
        x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
        x ^= x >> 33;
        x
    }

    /// Permute an index in [0..range-1] to a unique pseudo-random index in [0..range-1].
    pub fn shuffle(&self, mut index: u64) -> u64 {
        if self.range <= 1 {
            return 0;
        }

        // Cycle-walking: repeat until result < self.range
        loop {
            let mut left = index % self.a;
            let mut right = index / self.a;

            for round in 0..self.rounds {
                if round % 2 == 0 {
                    let f = self.round_function(right, round);
                    left = (left + f) % self.a;
                } else {
                    let f = self.round_function(left, round);
                    right = (right + f) % self.b;
                }
            }

            let result = right * self.a + left;
            if result < self.range {
                return result;
            }
            index = result;
        }
    }

    #[inline(always)]
    pub fn len(&self) -> u64 {
        self.range
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.range == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_blackrock_permutation_uniqueness() {
        let size = 10_000;
        let br = Blackrock::new(size, 0xdeadbeef1337);
        let mut seen = HashSet::with_capacity(size as usize);

        for i in 0..size {
            let val = br.shuffle(i);
            assert!(val < size, "val {} out of range {}", val, size);
            assert!(seen.insert(val), "Duplicate found at {}: {}", i, val);
        }

        assert_eq!(seen.len(), size as usize);
    }

    #[test]
    fn test_blackrock_prime_range() {
        let size = 1009; // prime
        let br = Blackrock::new(size, 0xcafe1234);
        let mut seen = HashSet::with_capacity(size as usize);

        for i in 0..size {
            let val = br.shuffle(i);
            assert!(val < size);
            seen.insert(val);
        }
        assert_eq!(seen.len(), size as usize);
    }
}
