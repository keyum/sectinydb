
includes MTESLA;
interface Sender
{
  command void init(Sender_Config_t *p);
  command result_t generateCDM(uint8_t lvl, long long snd_time, 
			       CDM_Packet_t *p);
  command result_t authenticateData(long long snd_time, Data_Packet_t *p);
  command void generateConf(Receiver_Config_t *p);
}
