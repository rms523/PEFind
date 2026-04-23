#include <gtest/gtest.h>
#include "winnt_mock.h"
#include "algo.h"

// ============================================================
// Tests for parse_hex_pattern()
// ============================================================

TEST(ParseHexPattern, BasicExactBytes) {
    auto pat = parse_hex_pattern("4D5A9000");
    ASSERT_EQ(pat.bytes.size(), 4u);
    ASSERT_EQ(pat.isWildcard.size(), 4u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
    EXPECT_EQ(pat.bytes[1], 0x5A);
    EXPECT_EQ(pat.bytes[2], 0x90);
    EXPECT_EQ(pat.bytes[3], 0x00);
    for (size_t i = 0; i < pat.isWildcard.size(); ++i) {
        EXPECT_FALSE(pat.isWildcard[i]);
    }
}

TEST(ParseHexPattern, SpacesIgnored) {
    auto pat1 = parse_hex_pattern("4D5A9000");
    auto pat2 = parse_hex_pattern("4D 5A 90 00");
    ASSERT_EQ(pat1.bytes.size(), pat2.bytes.size());
    for (size_t i = 0; i < pat1.bytes.size(); ++i) {
        EXPECT_EQ(pat1.bytes[i], pat2.bytes[i]);
    }
}

TEST(ParseHexPattern, Wildcards) {
    auto pat = parse_hex_pattern("xx xx 90 00");
    ASSERT_EQ(pat.bytes.size(), 4u);
    EXPECT_TRUE(pat.isWildcard[0]);
    EXPECT_TRUE(pat.isWildcard[1]);
    EXPECT_FALSE(pat.isWildcard[2]);
    EXPECT_FALSE(pat.isWildcard[3]);
    EXPECT_EQ(pat.bytes[2], 0x90);
    EXPECT_EQ(pat.bytes[3], 0x00);
}

TEST(ParseHexPattern, MixedExactAndWildcards) {
    auto pat = parse_hex_pattern("4D xx 5A");
    ASSERT_EQ(pat.bytes.size(), 3u);
    EXPECT_FALSE(pat.isWildcard[0]);
    EXPECT_TRUE(pat.isWildcard[1]);
    EXPECT_FALSE(pat.isWildcard[2]);
    EXPECT_EQ(pat.bytes[0], 0x4D);
    EXPECT_EQ(pat.bytes[2], 0x5A);
}

TEST(ParseHexPattern, CaseInsensitiveHexDigits) {
    auto pat = parse_hex_pattern("4d5a9000");
    ASSERT_EQ(pat.bytes.size(), 4u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
    EXPECT_EQ(pat.bytes[1], 0x5A);
}

TEST(ParseHexPattern, CaseInsensitiveWildcards) {
    auto pat1 = parse_hex_pattern("xx xx");
    auto pat2 = parse_hex_pattern("XX XX");
    auto pat3 = parse_hex_pattern("Xx Xx");
    
    for (size_t i = 0; i < pat1.isWildcard.size(); ++i) {
        EXPECT_TRUE(pat1.isWildcard[i]);
        EXPECT_TRUE(pat2.isWildcard[i]);
        EXPECT_TRUE(pat3.isWildcard[i]);
    }
}

TEST(ParseHexPattern, EmptyString) {
    auto pat = parse_hex_pattern("");
    EXPECT_TRUE(pat.bytes.empty());
    EXPECT_TRUE(pat.isWildcard.empty());
}

TEST(ParseHexPattern, SingleCharSkipped) {
    // "4" alone has no pair — should be skipped
    auto pat = parse_hex_pattern("4");
    EXPECT_TRUE(pat.bytes.empty());
}

TEST(ParseHexPattern, OddLengthHex) {
    // "4D5" → "4D" is valid, "5" is leftover and skipped
    auto pat = parse_hex_pattern("4D5");
    ASSERT_EQ(pat.bytes.size(), 1u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
}

TEST(ParseHexPattern, AllWildcards) {
    auto pat = parse_hex_pattern("xx xx xx");
    ASSERT_EQ(pat.bytes.size(), 3u);
    for (size_t i = 0; i < pat.isWildcard.size(); ++i) {
        EXPECT_TRUE(pat.isWildcard[i]);
    }
}

TEST(ParseHexPattern, MultipleSpaces) {
    auto pat = parse_hex_pattern("4D  5A   90  00");
    ASSERT_EQ(pat.bytes.size(), 4u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
    EXPECT_EQ(pat.bytes[1], 0x5A);
    EXPECT_EQ(pat.bytes[2], 0x90);
    EXPECT_EQ(pat.bytes[3], 0x00);
}

TEST(ParseHexPattern, ZeroBytes) {
    auto pat = parse_hex_pattern("00 00 00");
    ASSERT_EQ(pat.bytes.size(), 3u);
    for (size_t i = 0; i < pat.bytes.size(); ++i) {
        EXPECT_EQ(pat.bytes[i], 0x00);
    }
}

TEST(ParseHexPattern, FFBytes) {
    auto pat = parse_hex_pattern("FF ff Ff");
    ASSERT_EQ(pat.bytes.size(), 3u);
    for (size_t i = 0; i < pat.bytes.size(); ++i) {
        EXPECT_EQ(pat.bytes[i], 0xFF);
    }
}

TEST(ParseHexPattern, RealMZHeader) {
    // MZ header starts with bytes 4D 5A
    auto pat = parse_hex_pattern("4D5A");
    ASSERT_EQ(pat.bytes.size(), 2u);
    EXPECT_EQ(pat.bytes[0], 'M');   // 0x4D
    EXPECT_EQ(pat.bytes[1], 'Z');   // 0x5A
}

TEST(ParseHexPattern, RealPEHeader) {
    // PE\0\0 = 50 45 00 00
    auto pat = parse_hex_pattern("50450000");
    ASSERT_EQ(pat.bytes.size(), 4u);
    EXPECT_EQ(pat.bytes[0], 'P');   // 0x50
    EXPECT_EQ(pat.bytes[1], 'E');   // 0x45
    EXPECT_EQ(pat.bytes[2], 0x00);
    EXPECT_EQ(pat.bytes[3], 0x00);
}

TEST(ParseHexPattern, WildcardWithExact) {
    auto pat = parse_hex_pattern("xx xx 50 45");
    ASSERT_EQ(pat.bytes.size(), 4u);
    EXPECT_TRUE(pat.isWildcard[0]);
    EXPECT_TRUE(pat.isWildcard[1]);
    EXPECT_FALSE(pat.isWildcard[2]);
    EXPECT_FALSE(pat.isWildcard[3]);
    EXPECT_EQ(pat.bytes[2], 'P');
    EXPECT_EQ(pat.bytes[3], 'E');
}

TEST(ParseHexPattern, LongPattern) {
    auto pat = parse_hex_pattern("4D5A900090000000");
    ASSERT_EQ(pat.bytes.size(), 8u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
    EXPECT_EQ(pat.bytes[1], 0x5A);
    EXPECT_EQ(pat.bytes[2], 0x90);
    EXPECT_EQ(pat.bytes[3], 0x00);
}

TEST(ParseHexPattern, InvalidCharsSkipped) {
    // "GG" is not valid hex — both chars are skipped
    auto pat = parse_hex_pattern("GG4D");
    ASSERT_EQ(pat.bytes.size(), 1u);
    EXPECT_EQ(pat.bytes[0], 0x4D);
}

TEST(ParseHexPattern, PatternSize) {
    auto pat = parse_hex_pattern("4D5A9000");
    EXPECT_EQ(pat.size(), 4u);
}
