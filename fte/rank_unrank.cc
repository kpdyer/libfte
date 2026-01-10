/*
 * Implementation of DFA-based ranking and unranking.
 * See rank_unrank.h for detailed documentation.
 */

#include "rank_unrank.h"

#include <sstream>
#include <stdexcept>
#include <cassert>

namespace {

// Helper: split string by delimiter
std::vector<std::string> tokenize(const std::string& line, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(line);
    std::string fragment;
    while (std::getline(iss, fragment, delim)) {
        result.push_back(fragment);
    }
    return result;
}

// Exception messages
const char* MSG_INVALID_RANK = "Invalid rank input: string length doesn't match fixed_slice";
const char* MSG_INVALID_UNRANK = "Invalid unrank input: integer out of range";
const char* MSG_INVALID_FST = "Invalid FST format";
const char* MSG_INVALID_STATE = "Invalid DFA: state index out of range";
const char* MSG_INVALID_SYMBOL = "Invalid DFA: symbol not in range 0-255";
const char* MSG_NOT_ACCEPTING = "Input string does not end in accepting state";
const char* MSG_SYMBOL_NOT_IN_SIGMA = "Input contains symbol not in DFA alphabet";

} // anonymous namespace


DFA::DFA(const std::string& dfa_str, uint32_t max_len)
    : _fixed_slice(max_len),
      _start_state(0),
      _num_states(0),
      _num_symbols(0)
{
    // Parse DFA string and collect states, symbols, transitions
    std::unordered_set<uint32_t> states_set;
    std::unordered_set<uint32_t> symbols_set;
    std::vector<std::tuple<uint32_t, uint32_t, uint32_t>> transitions;
    bool start_state_set = false;

    std::istringstream stream(dfa_str);
    std::string line;
    
    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        auto parts = tokenize(line, '\t');
        
        if (parts.size() == 4) {
            // Transition line: src_state, dst_state, input_symbol, output_symbol
            uint32_t src = static_cast<uint32_t>(std::stoul(parts[0]));
            uint32_t dst = static_cast<uint32_t>(std::stoul(parts[1]));
            uint32_t symbol = static_cast<uint32_t>(std::stoul(parts[2]));
            
            states_set.insert(src);
            states_set.insert(dst);
            symbols_set.insert(symbol);
            transitions.emplace_back(src, dst, symbol);
            
            if (!start_state_set) {
                _start_state = src;
                start_state_set = true;
            }
        } else if (parts.size() == 1) {
            // Final state line
            uint32_t final_state = static_cast<uint32_t>(std::stoul(parts[0]));
            _final_states.insert(final_state);
            states_set.insert(final_state);
        } else if (!parts.empty()) {
            throw std::runtime_error(MSG_INVALID_FST);
        }
    }

    // Build sorted symbol and state lists
    _symbols.assign(symbols_set.begin(), symbols_set.end());
    std::sort(_symbols.begin(), _symbols.end());
    
    _states.assign(states_set.begin(), states_set.end());
    std::sort(_states.begin(), _states.end());
    
    // Add dead state
    uint32_t dead_state = static_cast<uint32_t>(_states.size());
    _states.push_back(dead_state);

    _num_symbols = static_cast<uint32_t>(_symbols.size());
    _num_states = static_cast<uint32_t>(_states.size());

    // Build sigma mappings (symbol index <-> byte value)
    _sigma.reserve(_num_symbols);
    _sigma_reverse.reserve(_num_symbols);
    for (uint32_t i = 0; i < _num_symbols; ++i) {
        char byte_val = static_cast<char>(_symbols[i]);
        _sigma[i] = byte_val;
        _sigma_reverse[byte_val] = i;
    }

    // Initialize transition table to dead state
    _delta.resize(_num_states);
    for (uint32_t q = 0; q < _num_states; ++q) {
        _delta[q].assign(_num_symbols, dead_state);
    }

    // Fill transition table
    for (const auto& trans : transitions) {
        uint32_t src = std::get<0>(trans);
        uint32_t dst = std::get<1>(trans);
        uint32_t symbol = std::get<2>(trans);
        auto it = _sigma_reverse.find(static_cast<char>(symbol));
        if (it != _sigma_reverse.end()) {
            _delta[src][it->second] = dst;
        }
    }

    // Compute delta_dense optimization flags
    _delta_dense.resize(_num_states);
    for (uint32_t q = 0; q < _num_states; ++q) {
        _delta_dense[q] = true;
        if (_num_symbols > 0) {
            uint32_t first_dst = _delta[q][0];
            for (uint32_t a = 1; a < _num_symbols; ++a) {
                if (_delta[q][a] != first_dst) {
                    _delta_dense[q] = false;
                    break;
                }
            }
        }
    }

    _validate();
    _buildTable();
}


void DFA::_validate() {
    if (_states.empty()) {
        throw std::runtime_error(MSG_INVALID_FST);
    }
    if (_symbols.empty()) {
        throw std::runtime_error(MSG_INVALID_FST);
    }

    // Verify state indices are valid
    for (uint32_t state : _states) {
        if (state >= _states.size()) {
            throw std::runtime_error(MSG_INVALID_STATE);
        }
    }

    // Verify symbols are in valid byte range
    for (uint32_t symbol : _symbols) {
        if (symbol > 255) {
            throw std::runtime_error(MSG_INVALID_SYMBOL);
        }
    }
}


void DFA::_buildTable() {
    // Initialize counting table
    _T.resize(_num_states);
    for (uint32_t q = 0; q < _num_states; ++q) {
        _T[q].assign(_fixed_slice + 1, 0);
    }

    // Base case: T[q][0] = 1 for all final states
    for (uint32_t q : _final_states) {
        _T[q][0] = 1;
    }

    // Fill table: T[q][i] = sum over symbols a of T[delta[q][a]][i-1]
    for (uint32_t i = 1; i <= _fixed_slice; ++i) {
        for (uint32_t q = 0; q < _num_states; ++q) {
            for (uint32_t a = 0; a < _num_symbols; ++a) {
                uint32_t next_state = _delta[q][a];
                _T[q][i] += _T[next_state][i - 1];
            }
        }
    }
}


std::string DFA::unrank(const mpz_class& c_in) const {
    mpz_class words_in_slice = getNumWordsInLanguage(_fixed_slice, _fixed_slice);
    if (c_in < 0 || c_in >= words_in_slice) {
        throw std::runtime_error(MSG_INVALID_UNRANK);
    }

    std::string result;
    result.reserve(_fixed_slice);

    mpz_class c = c_in;
    uint32_t q = _start_state;

    for (uint32_t i = 1; i <= _fixed_slice; ++i) {
        uint32_t char_idx;
        uint32_t next_state;

        if (_delta_dense[q]) {
            // Optimized path: all transitions go to same state
            next_state = _delta[q][0];
            const mpz_class& divisor = _T[next_state][_fixed_slice - i];
            
            mpz_class quotient;
            mpz_fdiv_qr(quotient.get_mpz_t(), c.get_mpz_t(),
                        c.get_mpz_t(), divisor.get_mpz_t());
            char_idx = quotient.get_ui();
        } else {
            // Standard Goldberg-Sipser unranking
            char_idx = 0;
            next_state = _delta[q][char_idx];
            
            while (mpz_cmp(c.get_mpz_t(), _T[next_state][_fixed_slice - i].get_mpz_t()) >= 0) {
                mpz_sub(c.get_mpz_t(), c.get_mpz_t(),
                        _T[next_state][_fixed_slice - i].get_mpz_t());
                ++char_idx;
                next_state = _delta[q][char_idx];
            }
        }

        result += _sigma.at(char_idx);
        q = next_state;
    }

    // Verify we ended in a final state
    if (_final_states.find(q) == _final_states.end()) {
        throw std::runtime_error(MSG_NOT_ACCEPTING);
    }

    return result;
}


mpz_class DFA::rank(const std::string& X) const {
    if (X.length() != _fixed_slice) {
        throw std::runtime_error(MSG_INVALID_RANK);
    }

    mpz_class result = 0;
    uint32_t q = _start_state;
    uint32_t n = static_cast<uint32_t>(X.size());

    for (uint32_t i = 1; i <= n; ++i) {
        char byte_val = X[i - 1];
        auto it = _sigma_reverse.find(byte_val);
        if (it == _sigma_reverse.end()) {
            throw std::runtime_error(MSG_SYMBOL_NOT_IN_SIGMA);
        }
        uint32_t symbol_idx = it->second;

        if (_delta_dense[q]) {
            // Optimized path: all transitions go to same state
            uint32_t next_state = _delta[q][0];
            
            mpz_class tmp;
            mpz_mul_ui(tmp.get_mpz_t(), _T[next_state][n - i].get_mpz_t(), symbol_idx);
            mpz_add(result.get_mpz_t(), result.get_mpz_t(), tmp.get_mpz_t());
        } else {
            // Standard Goldberg-Sipser ranking
            for (uint32_t j = 0; j < symbol_idx; ++j) {
                uint32_t state = _delta[q][j];
                mpz_add(result.get_mpz_t(), result.get_mpz_t(),
                        _T[state][n - i].get_mpz_t());
            }
        }

        q = _delta[q][symbol_idx];
    }

    // Verify we ended in a final state
    if (_final_states.find(q) == _final_states.end()) {
        throw std::runtime_error(MSG_NOT_ACCEPTING);
    }

    return result;
}


mpz_class DFA::getNumWordsInLanguage(uint32_t min_len, uint32_t max_len) const {
    assert(min_len <= max_len);
    assert(max_len <= _fixed_slice);

    mpz_class count = 0;
    for (uint32_t len = min_len; len <= max_len; ++len) {
        count += _T[_start_state][len];
    }
    return count;
}
