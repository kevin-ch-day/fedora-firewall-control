#pragma once

#include "ffc/command_runner.hpp"

#include <iostream>
#include <string>
#include <utility>
#include <vector>

namespace ffc::test {
inline int failures = 0;

inline void expect(bool value, const char* text) {
    if (!value) { std::cerr << "FAILED: " << text << '\n'; ++failures; }
}

class StubCommandRunner final : public CommandRunner {
public:
    explicit StubCommandRunner(CommandResult result) : result_(std::move(result)) {}
    CommandResult run(const std::vector<std::string>&) const override { return result_; }
private:
    CommandResult result_;
};

class SequencedCommandRunner final : public CommandRunner {
public:
    explicit SequencedCommandRunner(std::vector<CommandResult> results) : results_(std::move(results)) {}
    CommandResult run(const std::vector<std::string>& arguments) const override {
        calls.push_back(arguments);
        if (next_ == results_.size()) return {-1, {}, "unexpected command"};
        return results_[next_++];
    }
    mutable std::vector<std::vector<std::string>> calls;
private:
    std::vector<CommandResult> results_;
    mutable std::size_t next_{0};
};
} // namespace ffc::test
