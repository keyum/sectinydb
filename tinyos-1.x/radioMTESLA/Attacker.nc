
includes MTESLA;
interface Attacker
{
  command result_t init();
  command void ListenData(Data_Packet_t *p, long long rcv_time);
  command void ListenCDM(CDM_Packet_t *p, long long rcv_time);
  command void InsertData(Data_Packet_t *p);
  command void InsertCDM(CDM_Packet_t *p);
}
