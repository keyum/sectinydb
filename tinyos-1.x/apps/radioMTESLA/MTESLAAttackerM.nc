/**
 *By Donggang Liu, dliu@unity.ncsu.edu
 */

includes MTESLA;

module MTESLAAttackerM {
  provides {
    interface Attacker;
  }
}

implementation
{
  Data_Packet_t d_packet;
  CDM_Packet_t c_packet;

  command result_t Attacker.init()
    {
      return SUCCESS;
    }	
  command void Attacker.ListenData(Data_Packet_t *p, long long rcv_time)
    {
      memcpy((uint8_t *)&d_packet,p,sizeof(Data_Packet_t));
    }

  command void Attacker.ListenCDM(CDM_Packet_t *p, long long rcv_time)
    {
      memcpy((uint8_t *)&c_packet,p,sizeof(CDM_Packet_t));
    }

  command void Attacker.InsertData(Data_Packet_t *p)
    {
      memcpy(p,(uint8_t *)&d_packet,sizeof(Data_Packet_t));
      memset(p->data,0,DATA_SIZE); //simply set to zero, you can
				   //change to whatever you want

    }
  
  command void Attacker.InsertCDM(CDM_Packet_t *p)
    {
      memcpy(p,(uint8_t *)&c_packet,sizeof(CDM_Packet_t));
      memset((uint8_t *)p->kc_2_0,0,16);//simply set to zero, you can
				        //change to whatever you want
    }
}
