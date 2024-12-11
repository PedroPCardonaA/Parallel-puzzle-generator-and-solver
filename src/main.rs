//! This example demonstrates a simplified proof-of-work style puzzle solver that uses
//! a multi-threaded approach to find a nonce value that meets certain difficulty criteria.
//!
//! The puzzle is considered solved when the first two bytes of the SHA-256 hash of the
//! data and the nonce produce a value less than the specified difficulty. The work is
//! split evenly across multiple CPU cores, and once a solution is found, all other threads
//! stop searching.

use sha2::{Sha256, Digest};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering}
};
use std::thread;

use num_cpus;

const DIFFICULTY: u64 = 1;

/// A puzzle represents a proof-of-work style problem.
/// 
/// The puzzle is defined by:
/// - A `difficulty` which represents the target threshold for a valid hash.
/// - Arbitrary `data` whose hash, combined with a `nonce`, must be below the difficulty threshold.
/// - A `nonce` which is the value we try to find that makes the hash valid.
#[derive(Clone)]
struct Puzzle {
    /// Difficulty threshold for the puzzle.
    /// Lower values make it much harder to find a valid nonce.
    difficulty: u64,
    /// Arbitrary data (e.g., a block's header, transaction data, or a message).
    data: String,
    /// A nonce is the variable part we adjust to find a hash meeting the difficulty.
    nonce: u64,
}

fn main() {
    // Create a puzzle with a given difficulty and some arbitrary data.
    // Initially, the nonce is zero (unused) and will be incremented by the solver.
    let puzzle = Puzzle {
        difficulty: DIFFICULTY,
        data: "Some data".to_string(),
        nonce: 0,
    };

    // Attempt to solve the puzzle in parallel, using multiple CPU cores.
    let found_nonce = parallel_mine(&puzzle);

    // Print out the discovered nonce that solves the puzzle.
    println!("Found nonce (multi-thread): {}", found_nonce);
}

/// Validates whether a given nonce produces a hash below the puzzle difficulty.
///
/// # Parameters
///
/// - `puzzle`: The puzzle definition containing the difficulty and data.
/// - `nonce`: The nonce to test against the puzzle data.
///
/// # Returns
///
/// `true` if the resulting hash (first two bytes interpreted as a `u16`) is below the difficulty threshold;
/// otherwise, `false`.
fn validate(puzzle: &Puzzle, nonce: u64) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(puzzle.data.as_bytes());
    hasher.update(&nonce.to_be_bytes());
    let result = hasher.finalize();

    // Convert the first two bytes of the SHA-256 hash into a u16.
    // This drastically simplifies the puzzle complexity.
    let result_val = u16::from_be_bytes([result[0], result[1]]);
    result_val < puzzle.difficulty as u16
}

/// Attempts to solve the given puzzle by splitting the search range across multiple CPU cores.
///
/// # Parameters
///
/// - `puzzle`: The puzzle containing difficulty and data. The nonce is initially unused.
///
/// # Returns
///
/// The nonce that solves the puzzle, or `u64::MAX` if no solution is found (which is extremely unlikely if given enough range).
///
/// # Details
///
/// This function:
/// 1. Determines the number of CPU cores.
/// 2. Splits a large range of possible nonces (0 to `max_nonce`) evenly among all threads.
/// 3. Each thread searches its assigned range, validating each nonce until it either finds a valid solution or is notified that another thread found one.
/// 4. Uses an atomic flag `found_flag` to let other threads stop working as soon as a solution is found.
/// 5. Uses a `Mutex<Option<u64>>` to safely store the discovered solution nonce.
fn parallel_mine(puzzle: &Puzzle) -> u64 {
    // Clone the puzzle so it can be shared with multiple threads.
    let puzzle = puzzle.clone();
    let num_cores = num_cpus::get();
    
    // Define a maximum nonce search space.
    // In a real-world scenario, you might want to run indefinitely or use a dynamic approach.
    let max_nonce: u64 = u64::MAX / (num_cores as u64);
    let range_per_thread = max_nonce / num_cores as u64;

    // An atomic flag to signal that a solution has been found.
    let found_flag = Arc::new(AtomicBool::new(false));
    // A mutex-protected optional solution. When a thread finds a solution, it sets this.
    let solution = Arc::new(Mutex::new(None));

    let mut handles = Vec::with_capacity(num_cores);

    for i in 0..num_cores {
        let puzzle_clone = puzzle.clone();
        let found_flag_clone = Arc::clone(&found_flag);
        let solution_clone = Arc::clone(&solution);
        
        // Determine the range of nonces for this thread.
        let start = i as u64 * range_per_thread;
        let end = if i == num_cores - 1 {
            max_nonce
        } else {
            (i as u64 + 1) * range_per_thread
        };

        // Spawn a thread to handle its portion of the search space.
        let handle = thread::spawn(move || {
            for nonce in start..end {
                // If a solution is already found, stop work.
                if found_flag_clone.load(Ordering::Relaxed) {
                    return;
                }

                // Validate whether the current nonce solves the puzzle.
                if validate(&puzzle_clone, nonce) {
                    // If we have a solution, lock and update the shared solution storage.
                    let mut sol = solution_clone.lock().unwrap();
                    if sol.is_none() {
                        *sol = Some(nonce);
                        // Signal other threads that a solution has been found.
                        found_flag_clone.store(true, Ordering::Relaxed);
                    }
                    return;
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all threads to finish (either by finding a solution or exhausting their range).
    for handle in handles {
        let _ = handle.join();
    }

    // Retrieve the found solution, if any.
    let sol = solution.lock().unwrap();
    sol.unwrap_or(u64::MAX)
}
