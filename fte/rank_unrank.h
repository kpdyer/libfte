/*
 * Please see Appendix A of "Protocol Misidentification Made Easy with Format-Transforming Encryption"
 * url: http://dl.acm.org/citation.cfm?id=2516657
 *
 * and
 *
 * "Compression and ranking"
 * url: http://dl.acm.org/citation.cfm?id=22194
 *
 * for details about (un)ranking for regular languages.
 */

#ifndef _RANK_UNRANK_H
#define _RANK_UNRANK_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include <gmpxx.h>

class DFA {

private:
    // The maximum length for which buildTable is computed
    uint32_t _fixed_slice;

    // DFA start state
    uint32_t _start_state;

    // Number of states in the DFA
    uint32_t _num_states;

    // Number of symbols in the DFA alphabet
    uint32_t _num_symbols;

    // Symbols of the DFA alphabet
    std::vector<uint32_t> _symbols;

    // Mapping from symbol index to byte value
    std::unordered_map<uint32_t, char> _sigma;

    // Mapping from byte value to symbol index
    std::unordered_map<char, uint32_t> _sigma_reverse;

    // States in the DFA
    std::vector<uint32_t> _states;

    // Transition table: _delta[state][symbol] = next_state
    std::vector<std::vector<uint32_t>> _delta;

    // Optimization flag: true if all transitions from state go to same destination
    std::vector<bool> _delta_dense;

    // Set of final (accepting) states - unordered_set for O(1) lookup
    std::unordered_set<uint32_t> _final_states;

    // Counting table: _T[q][i] = number of accepting paths of length i from state q
    std::vector<std::vector<mpz_class>> _T;

    // Build the counting table
    void _buildTable();

    // Validate DFA properties, throws on failure
    void _validate();

public:
    // Construct DFA from AT&T FST format string
    DFA(const std::string& dfa_str, uint32_t max_len);

    // Convert integer rank to string (unrank operation)
    std::string unrank(const mpz_class& c) const;

    // Convert string to integer rank (rank operation)
    mpz_class rank(const std::string& X) const;

    // Get number of words in language within length range [min_len, max_len]
    mpz_class getNumWordsInLanguage(uint32_t min_len, uint32_t max_len) const;
};

#endif /* _RANK_UNRANK_H */
