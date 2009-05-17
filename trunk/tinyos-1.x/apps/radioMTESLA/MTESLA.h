
/* global macro */
enum {
  MAX_LEVEL = 2,
  DATA_SIZE = 8,
  TESLA_DELAY = 2,
  NUM_CDM_BUFFER = 39,
  NUM_DATA_BUFFER = 3,
  MTESLA_MSG=4,
  TICK_INTERVAL=50,
  DATA_RATE=600,
  REBROADCAST_RATE= 3000, //ms
  ATTACK_RATE = 157
};

/* network description */
enum {
  CLOCK_DISCREPANCY=10,  // ms
  LOSS_RATE=50 // from 0 to 100;
};
typedef struct Data_Packet_t {
  uint8_t level;
  long index;
  uint8_t data[DATA_SIZE];
  uint8_t mac[8];
  uint8_t dis[8];
} Data_Packet_t;

typedef struct CDM_Packet_t {
  uint8_t level;
  long index;
  uint8_t kc_2_0[8];
  uint8_t mac[8];
  uint8_t dis[8];
} CDM_Packet_t;

typedef struct Sender_Config_t {
  uint8_t MT_key[8];
  long kc_len[MAX_LEVEL];
  long kc_int[MAX_LEVEL];
  long long start_time;
} Sender_Config_t;

typedef struct KCC_t {
  long index;
  uint8_t key[8];
} KCC_t;

typedef struct LC_t {
  long chain;
  KCC_t commit[3]; 
} LC_t;

typedef struct Receiver_Config_t {
  long kc_len[MAX_LEVEL];
  long kc_int[MAX_LEVEL];
  long long start_time;
  long delta;
  long delay;
  LC_t lc[MAX_LEVEL];
} Receiver_Config_t;
