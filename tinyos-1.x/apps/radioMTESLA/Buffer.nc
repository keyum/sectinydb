
includes MTESLA;

interface Buffer
{
  command void init();
  command uint8_t dataNum();
  command uint8_t nextData(Data_Packet_t *data_packet );
  command void bufferData(Data_Packet_t *data_packet);
  command void delCurrentData();
  command void clearCDM(int level);
  command uint8_t nextCDM(int level, int id, CDM_Packet_t *cdm_packet);
  command void bufferCDM(CDM_Packet_t *p);
}
