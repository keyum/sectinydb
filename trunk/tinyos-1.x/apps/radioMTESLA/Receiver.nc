
includes MTESLA;
interface Receiver
{
  command void init(Receiver_Config_t *c);
  command void ProcessData(Data_Packet_t *p, long long rcv_time);
  command void ProcessCDM(CDM_Packet_t *p, long long rcv_time);
  event result_t authenticDataReady(Data_Packet_t *pData, long auth_delay);
}
