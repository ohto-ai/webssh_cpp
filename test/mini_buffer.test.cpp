#include <catch2/catch_test_macros.hpp>
#include <mini_buffer.hpp>
#include <cstring>

TEST_CASE("mini_buffer default constructor", "[mini_buffer]") {
    ohtoai::mini_buffer buf;
    REQUIRE(buf.data == nullptr);
    REQUIRE(buf.size == 0);
    REQUIRE(buf.capacity == 0);
}

TEST_CASE("mini_buffer capacity constructor", "[mini_buffer]") {
    ohtoai::mini_buffer buf(128);
    REQUIRE(buf.data != nullptr);
    REQUIRE(buf.size == 0);
    REQUIRE(buf.capacity == 128);
}

TEST_CASE("mini_buffer reserve", "[mini_buffer]") {
    SECTION("reserve grows capacity") {
        ohtoai::mini_buffer buf(64);
        buf.reserve(256);
        REQUIRE(buf.capacity == 256);
        REQUIRE(buf.size == 0);
    }

    SECTION("reserve smaller than current capacity is a no-op") {
        ohtoai::mini_buffer buf(256);
        buf.reserve(64);
        REQUIRE(buf.capacity == 256);
    }

    SECTION("reserve preserves existing data") {
        ohtoai::mini_buffer buf(64);
        const char *text = "hello";
        std::memcpy(buf.data, text, 5);
        buf.size = 5;
        buf.reserve(256);
        REQUIRE(std::memcmp(buf.data, text, 5) == 0);
    }
}

TEST_CASE("mini_buffer resize", "[mini_buffer]") {
    SECTION("resize within capacity only changes size") {
        ohtoai::mini_buffer buf(128);
        buf.resize(64);
        REQUIRE(buf.size == 64);
        REQUIRE(buf.capacity >= 64);
    }

    SECTION("resize larger than capacity grows the buffer") {
        ohtoai::mini_buffer buf(64);
        buf.resize(256);
        REQUIRE(buf.size == 256);
        REQUIRE(buf.capacity >= 256);
    }

    SECTION("resize to zero") {
        ohtoai::mini_buffer buf(64);
        buf.resize(0);
        REQUIRE(buf.size == 0);
    }
}

TEST_CASE("mini_buffer clear", "[mini_buffer]") {
    ohtoai::mini_buffer buf(128);
    buf.resize(64);
    REQUIRE(buf.size == 64);

    buf.clear();
    REQUIRE(buf.size == 0);
    REQUIRE(buf.capacity == 128);
    REQUIRE(buf.data != nullptr);
}

TEST_CASE("mini_buffer append", "[mini_buffer]") {
    SECTION("append raw data") {
        ohtoai::mini_buffer buf(64);
        const char *text = "hello";
        buf.append(text, 5);
        REQUIRE(buf.size == 5);
        REQUIRE(std::memcmp(buf.data, text, 5) == 0);
    }

    SECTION("append std::string") {
        ohtoai::mini_buffer buf(64);
        std::string text = "world";
        buf.append(text);
        REQUIRE(buf.size == 5);
        REQUIRE(std::memcmp(buf.data, text.data(), 5) == 0);
    }

    SECTION("multiple appends accumulate data") {
        ohtoai::mini_buffer buf(64);
        buf.append("foo", 3);
        buf.append("bar", 3);
        REQUIRE(buf.size == 6);
        REQUIRE(std::memcmp(buf.data, "foobar", 6) == 0);
    }

    SECTION("append another mini_buffer") {
        ohtoai::mini_buffer src(64);
        src.append("data", 4);

        ohtoai::mini_buffer dst(64);
        dst.append(src);
        REQUIRE(dst.size == 4);
        REQUIRE(std::memcmp(dst.data, "data", 4) == 0);
    }

    SECTION("append triggers resize when exceeding capacity") {
        ohtoai::mini_buffer buf(4);
        buf.append("hello world!", 12);
        REQUIRE(buf.size == 12);
        REQUIRE(buf.capacity >= 12);
        REQUIRE(std::memcmp(buf.data, "hello world!", 12) == 0);
    }
}

TEST_CASE("mini_buffer move semantics", "[mini_buffer]") {
    SECTION("move constructor transfers ownership") {
        ohtoai::mini_buffer src(128);
        src.append("test", 4);
        char *original_data = src.data;

        ohtoai::mini_buffer dst(std::move(src));
        REQUIRE(dst.data == original_data);
        REQUIRE(dst.size == 4);
        REQUIRE(dst.capacity == 128);
        REQUIRE(src.data == nullptr);
        REQUIRE(src.size == 0);
        REQUIRE(src.capacity == 0);
    }

    SECTION("move assignment transfers ownership") {
        ohtoai::mini_buffer src(128);
        src.append("test", 4);
        char *original_data = src.data;

        ohtoai::mini_buffer dst(64);
        dst = std::move(src);
        REQUIRE(dst.data == original_data);
        REQUIRE(dst.size == 4);
        REQUIRE(dst.capacity == 128);
        REQUIRE(src.data == nullptr);
    }
}

TEST_CASE("mini_buffer implicit char* conversion", "[mini_buffer]") {
    ohtoai::mini_buffer buf(64);
    buf.append("hello", 5);

    char *ptr = buf;
    REQUIRE(ptr == buf.data);

    const ohtoai::mini_buffer &cbuf = buf;
    const char *cptr = cbuf;
    REQUIRE(cptr == cbuf.data);
}
