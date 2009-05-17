interface Primitive
{
  command result_t MAC (uint8_t *key, uint8_t *in, uint16_t len, uint8_t *out);
  command result_t verifyMAC(uint8_t *key, uint8_t *in, uint16_t len, 
                             uint8_t *mac);
  command result_t PRF(uint8_t *key, uint16_t x, uint8_t *out);
  command result_t PRG(uint8_t *out);
  command uint16_t rand(uint16_t start, uint16_t end);
  command result_t generate_key_from(uint8_t *key, long d, long x, 
				     uint8_t *out);
}
