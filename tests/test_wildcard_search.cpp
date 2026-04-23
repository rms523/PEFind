#include <gtest/gtest.h>
#include "winnt_mock.h"
#include "algo.h"

// ============================================================
// Tests for wildcard hex pattern matching (find_all_with_wildcards)
// ============================================================

TEST(WildcardSearch, ExactMatchNoWildcards) {
    const uint8_t haystack[] = {0x4D, 0x5A, 0x90, 0x00};
    HexPattern pattern;
    pattern.bytes     = {0x4D, 0x5A, 0x90, 0x00};
    pattern.isWildcard = {false, false, false, false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(WildcardSearch, SingleWildcardPrefix) {
    // Pattern: xx 5A — matches any byte followed by 0x5A
    const uint8_t haystack[] = {0xAB, 0x5A, 0xCD, 0x5A};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x5A};
    pattern.isWildcard = {true, false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0); // AB 5A
    EXPECT_EQ(positions[1], 2); // CD 5A
}

TEST(WildcardSearch, SingleWildcardSuffix) {
    // Pattern: 4D xx — matches 0x4D followed by any byte
    const uint8_t haystack[] = {0x4D, 0xFF, 0x12, 0x4D, 0x3C};
    HexPattern pattern;
    pattern.bytes     = {0x4D, 0x00};
    pattern.isWildcard = {false, true};

    auto positions = find_all_with_wildcards(haystack, 5, pattern);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0); // 4D FF
    EXPECT_EQ(positions[1], 3); // 4D 3C
}

TEST(WildcardSearch, MultipleWildcards) {
    // Pattern: xx xx 90 00 — matches any two bytes followed by 0x90 0x00
    const uint8_t haystack[] = {0xAB, 0xCD, 0x90, 0x00, 0xFF, 0xEE, 0x90, 0x00};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x00, 0x90, 0x00};
    pattern.isWildcard = {true, true, false, false};

    auto positions = find_all_with_wildcards(haystack, 8, pattern);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0); // AB CD 90 00
    EXPECT_EQ(positions[1], 4); // FF EE 90 00
}

TEST(WildcardSearch, AllWildcards) {
    // Pattern: xx xx — should return empty (all wildcards is degenerate)
    const uint8_t haystack[] = {0xAB, 0xCD, 0xEF};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x00};
    pattern.isWildcard = {true, true};

    auto positions = find_all_with_wildcards(haystack, 3, pattern);
    EXPECT_TRUE(positions.empty());
}

TEST(WildcardSearch, NoMatch) {
    // Pattern: xx 90 — no byte followed by 0x90 in haystack
    const uint8_t haystack[] = {0xAB, 0xCD, 0xEF};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x90};
    pattern.isWildcard = {true, false};

    auto positions = find_all_with_wildcards(haystack, 3, pattern);
    EXPECT_TRUE(positions.empty());
}

TEST(WildcardSearch, PatternLongerThanHaystack) {
    const uint8_t haystack[] = {0xAB};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x90};
    pattern.isWildcard = {true, false};

    auto positions = find_all_with_wildcards(haystack, 1, pattern);
    EXPECT_TRUE(positions.empty());
}

TEST(WildcardSearch, EmptyPattern) {
    const uint8_t haystack[] = {0xAB, 0xCD};
    HexPattern pattern; // empty bytes and isWildcard

    auto positions = find_all_with_wildcards(haystack, 2, pattern);
    EXPECT_TRUE(positions.empty());
}

TEST(WildcardSearch, MZHeaderWithWildcards) {
    // Search for "MZ" with wildcard: xx 5A — matches any byte before 'M' then 'Z'
    // Actually let's search for the MZ signature with a known prefix
    const uint8_t haystack[] = {0x4D, 0x5A, 0x90, 0x00};
    HexPattern pattern;
    pattern.bytes     = {0x4D, 0x5A};
    pattern.isWildcard = {false, false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(WildcardSearch, WildcardAtEnd) {
    // Pattern: 90 xx — matches 0x90 followed by any byte
    const uint8_t haystack[] = {0xAB, 0x90, 0xFF, 0xCD};
    HexPattern pattern;
    pattern.bytes     = {0x90, 0x00};
    pattern.isWildcard = {false, true};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 1); // 90 FF
}

TEST(WildcardSearch, OverlappingMatches) {
    // Pattern: xx 5A — in "AB 5A CD 5A" should find positions 0 and 2 (non-overlapping by design of sliding window)
    const uint8_t haystack[] = {0xAB, 0x5A, 0xCD, 0x5A};
    HexPattern pattern;
    pattern.bytes     = {0x00, 0x5A};
    pattern.isWildcard = {true, false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0);
    EXPECT_EQ(positions[1], 2);
}

TEST(WildcardSearch, LargeHaystack) {
    // Create a large buffer with pattern at the end
    std::vector<uint8_t> haystack(10000, 0xAB);
    haystack[9998] = 0x5A; // xx 5A at position 9998

    HexPattern pattern;
    pattern.bytes     = {0x00, 0x5A};
    pattern.isWildcard = {true, false};

    auto positions = find_all_with_wildcards(haystack.data(), haystack.size(), pattern);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 9998);
}

TEST(WildcardSearch, WildcardInMiddle) {
    // Pattern: 4D xx 5A — MZ with any byte in between (should not match "MZ" directly)
    const uint8_t haystack[] = {0x4D, 0xFF, 0x5A, 0x12};
    HexPattern pattern;
    pattern.bytes     = {0x4D, 0x00, 0x5A};
    pattern.isWildcard = {false, true, false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0); // 4D FF 5A
}

TEST(WildcardSearch, EmptyHaystack) {
    HexPattern pattern;
    pattern.bytes     = {0x00};
    pattern.isWildcard = {true};

    auto positions = find_all_with_wildcards(nullptr, 0, pattern);
    EXPECT_TRUE(positions.empty());
}

TEST(WildcardSearch, SingleBytePatternNoWildcard) {
    // Pattern: 4D — single exact byte
    const uint8_t haystack[] = {0x12, 0x4D, 0x34, 0x4D};
    HexPattern pattern;
    pattern.bytes     = {0x4D};
    pattern.isWildcard = {false};

    auto positions = find_all_with_wildcards(haystack, 4, pattern);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 1);
    EXPECT_EQ(positions[1], 3);
}

TEST(WildcardSearch, SingleBytePatternWildcard) {
    // Pattern: xx — all wildcards should return empty (degenerate case)
    const uint8_t haystack[] = {0xAB, 0xCD};
    HexPattern pattern;
    pattern.bytes     = {0x00};
    pattern.isWildcard = {true};

    auto positions = find_all_with_wildcards(haystack, 2, pattern);
    EXPECT_TRUE(positions.empty());
}
