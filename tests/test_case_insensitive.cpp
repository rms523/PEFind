#include <gtest/gtest.h>
#include "winnt_mock.h"
#include "algo.h"

// ============================================================
// Tests for case-insensitive byte comparison (bytes_equal_ci)
// ============================================================

TEST(CaseInsensitive, ExactLowercaseMatch) {
    EXPECT_TRUE(bytes_equal_ci('a', 'a'));
}

TEST(CaseInsensitive, ExactUppercaseMatch) {
    EXPECT_TRUE(bytes_equal_ci('A', 'A'));
}

TEST(CaseInsensitive, MixedCaseMatch) {
    EXPECT_TRUE(bytes_equal_ci('A', 'a'));
    EXPECT_TRUE(bytes_equal_ci('a', 'A'));
}

TEST(CaseInsensitive, DifferentLettersNoMatch) {
    EXPECT_FALSE(bytes_equal_ci('a', 'b'));
}

TEST(CaseInsensitive, DigitAndLetterNoMatch) {
    EXPECT_FALSE(bytes_equal_ci('1', 'a'));
}

TEST(CaseInsensitive, SpecialCharacterNoMatch) {
    EXPECT_FALSE(bytes_equal_ci('@', 'A'));
}

TEST(CaseInsensitive, NullByte) {
    EXPECT_TRUE(bytes_equal_ci(0x00, 0x00));
    EXPECT_FALSE(bytes_equal_ci(0x00, 0x41));
}

TEST(CaseInsensitive, HighBytes) {
    // Bytes above ASCII range should compare directly (tolower has no effect)
    EXPECT_TRUE(bytes_equal_ci(0xFF, 0xFF));
    EXPECT_FALSE(bytes_equal_ci(0xFF, 0xFE));
}

// ============================================================
// Tests for case-insensitive BMH search
// ============================================================

TEST(CaseInsensitiveBMH, SingleMatchLowercasePattern) {
    const uint8_t haystack[] = {'H', 'e', 'L', 'l', 'O'};
    const uint8_t needle[]   = {'h', 'e', 'l', 'l', 'o'};

    int pos = search_bmh(haystack, 5, needle, 5, bytes_equal_ci);
    EXPECT_EQ(pos, 0);
}

TEST(CaseInsensitiveBMH, SingleMatchUppercasePattern) {
    const uint8_t haystack[] = {'h', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'H', 'E', 'L', 'L', 'O'};

    int pos = search_bmh(haystack, 5, needle, 5, bytes_equal_ci);
    EXPECT_EQ(pos, 0);
}

TEST(CaseInsensitiveBMH, MixedCaseMatch) {
    const uint8_t haystack[] = {'H', 'e', 'L', 'l', 'O'};
    const uint8_t needle[]   = {'h', 'E', 'l', 'o'}; // partial match — only 4 bytes

    int pos = search_bmh(haystack, 5, needle, 4, bytes_equal_ci);
    EXPECT_EQ(pos, 0);
}

TEST(CaseInsensitiveBMH, NoCaseMismatch) {
    const uint8_t haystack[] = {'A', 'B', 'C'};
    const uint8_t needle[]   = {'X', 'Y', 'Z'};

    int pos = search_bmh(haystack, 3, needle, 3, bytes_equal_ci);
    EXPECT_EQ(pos, -1);
}

TEST(CaseInsensitiveBMH, CaseSensitiveStillWorks) {
    const uint8_t haystack[] = {'A', 'b', 'C'};
    const uint8_t needle[]   = {'a', 'b'};

    // With case-sensitive comparison, should NOT match at position 0 (A != a)
    int pos = search_bmh(haystack, 3, needle, 2, [](uint8_t a, BYTE b) { return a == b; });
    EXPECT_EQ(pos, -1);

    // With case-insensitive comparison, should match at position 0
    pos = search_bmh(haystack, 3, needle, 2, bytes_equal_ci);
    EXPECT_EQ(pos, 0);
}

TEST(CaseInsensitiveBMHFindAll, MultipleMixedCaseMatches) {
    const uint8_t haystack[] = {'A', 'B', 'a', 'b', 'C', 'c'};
    const uint8_t needle[]   = {'a', 'b'};

    auto positions = find_all_bmh(haystack, 6, needle, 2, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0); // AB
    EXPECT_EQ(positions[1], 2); // ab
}

TEST(CaseInsensitiveBMHFindAll, NoFalsePositives) {
    const uint8_t haystack[] = {'A', 'B', 'C', 'D'};
    const uint8_t needle[]   = {'a', 'b', 'c', 'd'};

    auto positions = find_all_bmh(haystack, 4, needle, 4, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 1u); // Should match all of them case-insensitively
    EXPECT_EQ(positions[0], 0);
}

TEST(CaseInsensitiveBMHFindAll, PartialCaseMismatch) {
    const uint8_t haystack[] = {'A', 'B', 'C'};
    const uint8_t needle[]   = {'a', 'X', 'c'};

    auto positions = find_all_bmh(haystack, 3, needle, 3, bytes_equal_ci);
    EXPECT_TRUE(positions.empty()); // B != X even case-insensitively
}

TEST(CaseInsensitiveBMHFindAll, EmptyNeedle) {
    const uint8_t haystack[] = {'a', 'b'};

    auto positions = find_all_bmh(haystack, 2, nullptr, 0, bytes_equal_ci);
    EXPECT_TRUE(positions.empty());
}

TEST(CaseInsensitiveBMHFindAll, SingleByteCaseInsensitive) {
    const uint8_t haystack[] = {'a', 'A', 'b', 'B'};
    const uint8_t needle[]   = {'a'};

    auto positions = find_all_bmh(haystack, 4, needle, 1, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 2u);
    EXPECT_EQ(positions[0], 0); // a
    EXPECT_EQ(positions[1], 1); // A
}

// ============================================================
// Tests for case-insensitive Unicode search simulation
// ============================================================

TEST(CaseInsensitiveUnicode, NullTerminatedString) {
    // Simulate searching for "ab\0" in unicode data (each char is 2 bytes + null)
    const uint8_t haystack[] = {'a', 'b', '\0', 'X', 'Y', '\0'};
    const uint8_t needle[]   = {'A', 'B', '\0'};

    auto positions = find_all_bmh(haystack, 6, needle, 3, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0); // Case-insensitive match at start
}

TEST(CaseInsensitiveUnicode, MixedCaseUnicode) {
    const uint8_t haystack[] = {'H', 'e', 'l', 'l', 'o'};
    const uint8_t needle[]   = {'h', 'E', 'L', 'l', 'O'};

    auto positions = find_all_bmh(haystack, 5, needle, 5, bytes_equal_ci);
    ASSERT_EQ(positions.size(), 1u);
    EXPECT_EQ(positions[0], 0);
}
