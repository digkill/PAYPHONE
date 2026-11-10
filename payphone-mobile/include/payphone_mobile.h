#ifndef PAYPHONE_MOBILE_H
#define PAYPHONE_MOBILE_H
#include <stdint.h>
#include <stddef.h>
uint64_t pp_open(const uint8_t *key, const uint8_t *pin, size_t pin_len);
int32_t pp_socket_fd(uint64_t handle);
uint32_t pp_remote_ipv4(uint64_t handle);
int32_t pp_connect(uint64_t handle, const uint8_t *address, size_t address_len,
                   const uint8_t *sni, size_t sni_len);
int32_t pp_send(uint64_t handle, const uint8_t *data, size_t len);
int32_t pp_receive(uint64_t handle, uint8_t *out, size_t capacity);
void pp_close(uint64_t handle);
#endif
