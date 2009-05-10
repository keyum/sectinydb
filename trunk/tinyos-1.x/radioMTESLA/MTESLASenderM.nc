/**
 *By Donggang Liu, dliu@unity.ncsu.edu
 */

includes MTESLA;

#define KEYGEN Primitive.generate_key_from
#define MACGEN Primitive.MAC

module MTESLASenderM {
  provides {
    interface Sender;
  }
  uses {
    interface Primitive;
  }
}

implementation
{
  Sender_Config_t sc;

  /**
   * Initialize the sender. 
   * @param: c point to the sender configuration
   */

  command void Sender.init(Sender_Config_t *c)
    {
      memcpy(&sc,c,sizeof(Sender_Config_t));
      return;
    }	
  
  /**
   * try to get a specific key, the function is an on-line generation
   * version. The sender do not need to keep more buffer, but need to
   * perform a lots of Pseudo random function operations.
   * @param: lvl, which key chain level
   * @param: chn, which chain in this level
   * @param: idx, which key in this chain
   * @param: key, where to put the key
   * @return: FAIL, not able to get the key
   * @return: SUCCESS, get the key successfully
   */

  result_t get_key(uint8_t lvl, long chn, long idx, uint8_t *key)
    {
      uint8_t tmp[8];

      //if the highest level, directly generate the key
      if(lvl==0) {
	if(chn!=1) return FAIL;
	return call KEYGEN(sc.MT_key, sc.kc_len[lvl]-idx,lvl,key);
      }
      
      //get the high level key that can be used to generate the key we want
      if(!get_key(lvl-1,1+chn/sc.kc_len[lvl-1],1+chn%sc.kc_len[lvl-1],tmp)) 
        return FAIL;

      call Primitive.PRF(tmp,0xffff-lvl,tmp); //perform F_{01} in tmp
      
      //generated the key we want
      return call KEYGEN(tmp,sc.kc_len[lvl]-idx+1,lvl,key);
    }
  
  /**
   * try to generate a CDM packet for a specific level
   * @param: lvl, which key chain level
   * @param: snd_time, the time when the sender try to generate the CDM packet
   * @param: packet, point to the buffer to store the generated CDM packet
   * @return: FAIL, generation FAIL, used up all the keys
   * @return: SUCCESS, successfully generate a CDM packet
   */
  
  command result_t Sender.generateCDM(uint8_t lvl, long long snd_time, 
                                      CDM_Packet_t *packet)
    {
      uint8_t tmp[8];
      long seq=1+(long)((snd_time-sc.start_time)/sc.kc_int[lvl]);
      long chn=1+(seq-1)/sc.kc_len[lvl];
      long idx=1+(seq-1)%sc.kc_len[lvl];

      packet->level = lvl;
      packet->index = seq;

      // get the key commitment K_{i+2,0}
      if(!get_key(lvl+1,seq+2,0,packet->kc_2_0)) return FAIL;
      // get the key to generate MAC
      if(!get_key(lvl,chn,idx,tmp)) return FAIL;

      call Primitive.PRF(tmp,0xffff,tmp); //generate K'_i in tmp

      if(!call MACGEN(tmp,(uint8_t *)&(packet->index),12,packet->mac)) 
	return FAIL;

      // get the disclosed key
      if(seq==1) return get_key(lvl,1,0,packet->dis);
      if(idx >1) return get_key(lvl,chn,idx-1,packet->dis);
      if(chn >1) return get_key(lvl,chn-1,sc.kc_len[lvl],packet->dis);
      return FAIL;
    }
  
  /**
   * try to authenticate a raw data packet, the raw data are already
   * filled in packet.data
   * @param: snd_time, the time when the sender authenticate the data packet
   * @param: packet, point to the buffer to store the authenticated data packet
   * @return: FAIL, generation FAIL, used up all the keys
   * @return: SUCCESS, successfully generate a CDM packet
   */

  command result_t Sender.authenticateData(long long snd_time, Data_Packet_t *packet)
    {
      uint8_t tmp[8];
      long seq=1+(snd_time-sc.start_time)/sc.kc_int[MAX_LEVEL-1];
      long chn=1+(seq-1)/sc.kc_len[MAX_LEVEL-1];
      long idx=1+(seq-1)%sc.kc_len[MAX_LEVEL-1];

      packet->level=MAX_LEVEL-1;
      packet->index=seq;

      // get the key to generate the MAC value
      if(!get_key(MAX_LEVEL-1,chn,idx,tmp)) return FAIL;

      call Primitive.PRF(tmp,0xffff,tmp); //generate K'_i in tmp

      if(!call MACGEN(tmp,(uint8_t *)&(packet->index),4+DATA_SIZE,
                             packet->mac)) return FAIL;
      // fill in the disclosed key
      if(seq<=TESLA_DELAY) return get_key(MAX_LEVEL-1,1,0,packet->dis);
      chn=1+(seq-TESLA_DELAY-1)/sc.kc_len[MAX_LEVEL-1];
      idx=1+(seq-TESLA_DELAY-1)%sc.kc_len[MAX_LEVEL-1];
      return get_key(MAX_LEVEL-1, chn, idx, packet->dis);
    }
  
  
  /**
   * generate the configuration of the receiver for this sender
   * @param: p, point to the buffer to store configuration
   */
  command void Sender.generateConf(Receiver_Config_t *p)
    {
      int i;
      memcpy(p,(uint8_t *)sc.kc_len,sizeof(Sender_Config_t)-8);
      p->delay=TESLA_DELAY;
      for(i=0;i<MAX_LEVEL;i++){
	p->lc[i].chain=1;
	p->lc[i].commit[0].index=-1;
        p->lc[i].commit[1].index=0;
	p->lc[i].commit[2].index=-1;
        get_key(i,1,0,p->lc[i].commit[1].key);
	if(i>0) {
 	  p->lc[i].commit[2].index=0;
	  get_key(i,2,0,p->lc[i].commit[2].key);
	}
      }
      return;
    }
}
