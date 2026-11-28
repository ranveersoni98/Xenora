// SPDX-License-Identifier: GPL-3.0-or-later

#include <cstdint>
#include <cstdio>
#include <vector>

namespace {
unsigned attempts;
unsigned throw_on;
unsigned live;
unsigned constructed;
unsigned destroyed;
unsigned phase_trace;

void mark(unsigned phase) {
    phase_trace = phase_trace * 10 + phase;
}

struct Record {
    unsigned id;

    explicit Record(unsigned value) : id(value) {
        ++constructed;
        ++live;
    }

    Record(const Record &source) : id(source.id) {
        ++attempts;
        if (attempts == throw_on) {
            mark(2);
            throw 71;
        }
        if (throw_on)
            mark(1);
        ++constructed;
        ++live;
    }

    ~Record() {
        if (throw_on)
            mark(3);
        ++destroyed;
        --live;
    }
};

bool original_order(const std::vector<Record> &items) {
    return items.size() == 3 && items[0].id == 11 &&
           items[1].id == 22 && items[2].id == 33;
}

unsigned run() {
    std::vector<Record> items;
    items.reserve(3);
    items.emplace_back(11);
    items.emplace_back(22);
    items.emplace_back(33);
    if (attempts != 0 || live != 3 || constructed != 3 || destroyed != 0)
        return 10;

    const auto old_capacity = items.capacity();
    const auto old_address = reinterpret_cast<std::uintptr_t>(items.data());
    const auto requested = old_capacity + 5;
    throw_on = 2;
    try {
        items.reserve(requested);
        return 11;
    } catch (int value) {
        if (value != 71)
            return 12;
        mark(4);
    }
    if (attempts != 2 || live != 3 || constructed != 4 || destroyed != 1 ||
        phase_trace != 1234)
        return 13;
    if (items.capacity() != old_capacity ||
        reinterpret_cast<std::uintptr_t>(items.data()) != old_address ||
        !original_order(items))
        return 14;

    throw_on = 0;
    items.reserve(requested);
    mark(5);
    if (items.capacity() < requested ||
        reinterpret_cast<std::uintptr_t>(items.data()) == old_address ||
        !original_order(items))
        return 15;
    if (attempts != 5 || live != 3 || constructed != 7 || destroyed != 4)
        return 16;
    return 0;
}
} // namespace

int main() {
    if (attempts || live || constructed || destroyed || phase_trace)
        return 20;
    const unsigned status = run();
    if (status)
        return static_cast<int>(status);
    mark(6);
    if (phase_trace != 123456 || live != 0 || constructed != 7 || destroyed != 7)
        return 21;
    std::puts("vector: throw rollback, retry, 7 constructions and 7 destructions");
    return 0;
}
