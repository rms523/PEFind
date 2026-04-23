#include <gtest/gtest.h>
#include "winnt_mock.h"
#include "algo.h"

// ============================================================
// Tests for Boyer-Moore-Horspool search algorithm
// ============================================================

TEST(BMHSearch, SingleMatchAtStart) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'H', 'e'};
    
    int pos = search_bmh(haystack, 5, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 0);
}

TEST(BMHSearch, SingleMatchAtEnd) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'l', 'o'};
    
    int pos = search_bmh(haystack, 5, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 3);
}

TEST(BMHSearch, SingleMatchInMiddle) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    const uint8_t needle[]   = {'W', 'o', 'r', 'l', 'd'};
    
    int pos = search_bmh(haystack, 11, needle, 5, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 6);
}

TEST(BMHSearch, NoMatch) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'x', 'y'};
    
    int pos = search_bmh(haystack, 5, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, -1);
}

TEST(BMHSearch, EmptyNeedle) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    
    int pos = search_bmh(haystack, 5, nullptr, 0, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, -1);
}

TEST(BMHSearch, NeedleLongerThanHaystack) {
    const uint8_t haystack[] = {'H', 'e'};
    const uint8_t needle[]   = {'H', 'e', 'l', 'l', 'o'};
    
    int pos = search_bmh(haystack, 2, needle, 5, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, -1);
}

TEST(BMHSearch, SingleByteNeedle) {
    const uint8_t haystack[] = {'a', 'b', 'c', 'b', 'd'};
    
    int pos = search_bmh(haystack, 5, &haystack[3], 1, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 1);
}

TEST(BMHSearch, AllSameBytes) {
    const uint8_t haystack[] = {'a', 'a', 'a', 'a', 'a'};
    const uint8_t needle[]   = {'a', 'a'};
    
    int pos = search_bmh(haystack, 5, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 0);
}

TEST(BMHSearch, OverlappingPatternInData) {
    // Pattern "aba" appears at position 0 and overlaps with position 2
    const uint8_t haystack[] = {'a', 'b', 'a', 'b', 'a'};
    const uint8_t needle[]   = {'a', 'b', 'a'};
    
    int pos = search_bmh(haystack, 5, needle, 3, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_EQ(pos, 0);
}

// ============================================================
// Tests for find_all_bmh (all occurrences)
// ============================================================

TEST(BMHFindAll, SingleOccurrence) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'l', 'l'};
    
    auto positions = find_all_bmh(haystack, 5, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 2);
}

TEST(BMHFindAll, MultipleNonOverlappingOccurrences) {
    const uint8_t haystack[] = {'a', 'b', 'c', 'a', 'b', 'c', 'x'};
    const uint8_t needle[]   = {'a', 'b', 'c'};
    
    auto positions = find_all_bmh(haystack, 7, needle, 3, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0);
    EXPECT_EQ(positions[1], 3);
}

TEST(BMHFindAll, NoOccurrences) {
    const uint8_t haystack[] = {'a', 'b', 'c'};
    const uint8_t needle[]   = {'x', 'y'};
    
    auto positions = find_all_bmh(haystack, 3, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_TRUE(positions.empty());
}

TEST(BMHFindAll, SingleByteMultipleMatches) {
    const uint8_t haystack[] = {'a', 'b', 'a', 'c', 'a'};
    
    auto positions = find_all_bmh(haystack, 5, &haystack[0], 1, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 3u);
    EXPECT_EQ(positions[0], 0);
    EXPECT_EQ(positions[1], 2);
    EXPECT_EQ(positions[2], 4);
}

TEST(BMHFindAll, EmptyNeedle) {
    const uint8_t haystack[] = {'a', 'b', 'c'};
    
    auto positions = find_all_bmh(haystack, 3, nullptr, 0, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_TRUE(positions.empty());
}

TEST(BMHFindAll, NeedleLongerThanHaystack) {
    const uint8_t haystack[] = {'a', 'b'};
    const uint8_t needle[]   = {'a', 'b', 'c'};
    
    auto positions = find_all_bmh(haystack, 2, needle, 3, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_TRUE(positions.empty());
}

TEST(BMHFindAll, OverlappingPatternNonOverlappingResult) {
    // Pattern "aaa" in "aaaaa": non-overlapping search should find the first full occurrence only.
    const uint8_t haystack[] = {'a', 'a', 'a', 'a', 'a'};
    const uint8_t needle[]   = {'a', 'a', 'a'};
    
    auto positions = find_all_bmh(haystack, 5, needle, 3, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, CaseSensitiveByDefault) {
    const uint8_t haystack[] = {'A', 'b', 'C', 'a', 'B', 'c'};
    const uint8_t needle[]   = {'a', 'b'};
    
    auto positions = find_all_bmh(haystack, 6, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_TRUE(positions.empty());
}

TEST(BMHFindAll, MZHeaderSearch) {
    // Simulate searching for "MZ" in a buffer that starts with it
    const uint8_t haystack[] = {'M', 'Z', 0x90, 0x00};
    const uint8_t needle[]   = {'M', 'Z'};
    
    auto positions = find_all_bmh(haystack, 4, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, LargeDataPerformance) {
    // Create a large haystack with pattern at the end
    std::vector<uint8_t> haystack(10000, 'x');
    const uint8_t needle[] = {'a', 'b', 'c'};
    
    // Place needle near the end
    size_t pos = 9997;
    memcpy(&haystack[pos], needle, 3);
    
    auto positions = find_all_bmh(haystack.data(), haystack.size(), needle, 3, 
                                   [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], static_cast<int>(pos));
}

TEST(BMHFindAll, PatternAtEveryPosition) {
    // "aaaa" in "aaaaaaaa" — non-overlapping should find positions 0, 4
    const uint8_t haystack[] = {'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a'};
    const uint8_t needle[]   = {'a', 'a', 'a', 'a'};
    
    auto positions = find_all_bmh(haystack, 8, needle, 4, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0);
    EXPECT_EQ(positions[1], 4);
}

TEST(BMHFindAll, CaseInsensitiveSearch) {
    const uint8_t haystack[] = {'H', 'e', 'L', 'l', 'O'};
    const uint8_t needle[]   = {'h', 'e', 'l', 'l', 'o'};
    
    auto positions = find_all_bmh(haystack, 5, needle, 5, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, CaseInsensitivePartialMatch) {
    const uint8_t haystack[] = {'H', 'e', 'L', 'l', 'O', ' ', 'W', 'o', 'R', 'l', 'D'};
    const uint8_t needle[]   = {'h', 'e', 'l', 'l', 'o'};
    
    auto positions = find_all_bmh(haystack, 11, needle, 5, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, UnicodeNullTerminated) {
    // Search for "AB\0" in a buffer (like searching for unicode strings)
    const uint8_t haystack[] = {'A', 'B', '\0', 'X', 'Y', 'Z'};
    const uint8_t needle[]   = {'A', 'B', '\0'};
    
    auto positions = find_all_bmh(haystack, 6, needle, 3, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, ZeroBytePattern) {
    const uint8_t haystack[] = {'\0', 'a', '\0', 'b'};
    const uint8_t needle[]   = {'\0'};
    
    auto positions = find_all_bmh(haystack, 4, needle, 1, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0);
    EXPECT_EQ(positions[1], 2);
}

TEST(BMHFindAll, BinaryDataWithNullBytes) {
    // Simulate PE file content with null bytes
    const uint8_t haystack[] = {0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00};
    const uint8_t needle[]   = {0x90, 0x00, 0x03, 0x00};
    
    auto positions = find_all_bmh(haystack, 8, needle, 4, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 2); // MZ header offset + 2
}

TEST(BMHFindAll, RepeatedSingleByte) {
    const uint8_t haystack[] = {'a', 'a', 'a', 'a'};
    
    auto positions = find_all_bmh(haystack, 4, &haystack[0], 1, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 4u);
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(positions[i], i);
    }
}

TEST(BMHFindAll, PatternMatchesEntireData) {
    const uint8_t data[] = {'a', 'b', 'c'};
    
    auto positions = find_all_bmh(data, 3, data, 3, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(BMHFindAll, EmptyHaystack) {
    const uint8_t needle[] = {'a', 'b'};
    
    auto positions = find_all_bmh(nullptr, 0, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    EXPECT_TRUE(positions.empty());
}

TEST(BMHFindAll, TwoBytePatternAtBoundary) {
    const uint8_t haystack[] = {'a', 'b'};
    const uint8_t needle[]   = {'a', 'b'};
    
    auto positions = find_all_bmh(haystack, 2, needle, 2, [](uint8_t a, uint8_t b) { return a == b; });
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}

TEST(MatchSelection, ZeroReturnsAllMatches) {
    std::vector<uint64_t> offsets = {10, 20, 30};
    auto selected = select_nth_match(offsets, 0);
    EXPECT_EQ(selected, offsets);
}

TEST(MatchSelection, OneReturnsFirstMatch) {
    std::vector<uint64_t> offsets = {10, 20, 30};
    auto selected = select_nth_match(offsets, 1);
    ASSERT_EQ(selected.size(), 1u);
    EXPECT_EQ(selected[0], 10u);
}

TEST(MatchSelection, NReturnsNthMatch) {
    std::vector<uint64_t> offsets = {10, 20, 30};
    auto selected = select_nth_match(offsets, 2);
    ASSERT_EQ(selected.size(), 1u);
    EXPECT_EQ(selected[0], 20u);
}

TEST(MatchSelection, OutOfRangeReturnsNoMatches) {
    std::vector<uint64_t> offsets = {10, 20, 30};
    auto selected = select_nth_match(offsets, 4);
    EXPECT_TRUE(selected.empty());
}

TEST(BMHFindAll, BMHAdvantageOverNaive) {
    // Create data where BMH should skip many positions: 
    // haystack = "aaaa...aaa" + "b", needle = "aaaaa"
    std::vector<uint8_t> haystack(1000, 'a');
    haystack[999] = 'b';
    const uint8_t needle[] = {'a', 'a', 'a', 'a', 'a'};
    
    auto positions = find_all_bmh(haystack.data(), 1000, needle, 5, 
                                   [](uint8_t a, uint8_t b) { return a == b; });
    // Should find matches at 0, 5, 10, ... (non-overlapping)
    EXPECT_GT(positions.size(), 0u);
    for (size_t i = 1; i < positions.size(); ++i) {
        EXPECT_EQ(positions[i] - positions[i-1], 5); // Non-overlapping spacing
    }
}
