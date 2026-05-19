#pragma once
#ifndef OHTOAI_MINI_BUFFER_HPP
#define OHTOAI_MINI_BUFFER_HPP

#include <string>
#include <cstring>

namespace ohtoai
{
    namespace detail {
        struct mini_buffer {
            char *data;
            size_t size;
            size_t capacity;

            mini_buffer() : data(nullptr), size(0), capacity(0) {}
            mini_buffer(size_t capacity) : data(nullptr), size(0), capacity(capacity) {
                data = new char[capacity];
            }

            mini_buffer(const mini_buffer&) = delete;
            mini_buffer& operator=(const mini_buffer&) = delete;

            mini_buffer(mini_buffer&& other) noexcept
                : data(other.data), size(other.size), capacity(other.capacity) {
                other.data = nullptr;
                other.size = 0;
                other.capacity = 0;
            }
            mini_buffer& operator=(mini_buffer&& other) noexcept {
                if (this != &other) {
                    delete[] data;
                    data = other.data;
                    size = other.size;
                    capacity = other.capacity;
                    other.data = nullptr;
                    other.size = 0;
                    other.capacity = 0;
                }
                return *this;
            }

            ~mini_buffer() {
                delete[] data;
            }

            char* ptr() { return data; }
            const char* ptr() const { return data; }

            void reserve(size_t new_capacity) {
                if (new_capacity <= this->capacity) {
                    return;
                }
                char *new_data = new char[new_capacity];
                if (data && size > 0) {
                    std::memcpy(new_data, data, size);
                }
                delete[] data;
                data = new_data;
                this->capacity = new_capacity;
            }

            void resize(size_t new_size) {
                reserve(new_size);
                this->size = new_size;
            }

            void clear() {
                size = 0;
            }

            void append(const char *src, size_t len) {
                reserve(this->size + len);
                std::memcpy(this->data + this->size, src, len);
                this->size += len;
            }

            void append(const std::string &str) {
                append(str.data(), str.size());
            }

            void append(const mini_buffer &other) {
                if (this != &other) {
                    append(other.data, other.size);
                }
            }
        };
    }
    using detail::mini_buffer;
}

#endif //OHTOAI_MINI_BUFFER_HPP
