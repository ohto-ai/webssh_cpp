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


            ~mini_buffer() {
                delete[] data;
            }

            operator char*(){
                return data;
            }
            operator const char*() const{
                return data;
            }

            void reserve(size_t capacity) {
                if (capacity <= this->capacity) {
                    return;
                }
                char *new_data = new char[capacity];
                std::memcpy(new_data, data, size);
                delete[] data;
                data = new_data;
                this->capacity = capacity;
            }

            void resize(size_t size) {
                reserve(size);
                this->size = size;
            }

            void clear() {
                size = 0;
            }

            void append(const char *data, size_t size) {
                reserve(this->size + size);
                memcpy(this->data + this->size, data, size);
                this->size += size;
            }

            void append(const std::string &data) {
                append(data.data(), data.size());
            }

            void append(const mini_buffer &buffer) {
                append(buffer.data, buffer.size);
            }
        };
    }
    using detail::mini_buffer;
}

#endif //OHTOAI_MINI_BUFFER_HPP
