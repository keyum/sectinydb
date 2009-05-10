/**
 * Author: Donggang Liu 
 * Data: 02/23/03
 */

includes MTESLA;

#define KEYGEN call Primitive.generate_key_from
#define VERMAC call Primitive.verifyMAC

module MTESLAReceiverM {
  provides {
    interface Receiver;
  }
  uses {
    interface Primitive;
    interface Buffer;
  }
}

implementation
{

  uint8_t tmp[8];
  Receiver_Config_t rc;
  
  /**
   * Initialize the Receiver . 
   * @param: c point to the receiver configuration
   */

  command void Receiver.init(Receiver_Config_t *c)
    {
      call Buffer.init(); // Initialize the buffer module
      memcpy(&rc,c,sizeof(Receiver_Config_t));
                          // Store the configuation for receiver
      return;
    }

  /**
   * Move the key commitment buffer for each level so that it point
   * to the specific time interval
   * @param: lvl, which key chain level you want to move
   * @param: chn, which time interval you want to move to
   */

  void refresh_lc(uint8_t lvl, long chn)
    {
      uint8_t i;
      if(rc.lc[lvl].chain>=chn) return;

      i=chn-rc.lc[lvl].chain;
      switch(i) {
      case 2:
        memcpy((uint8_t *)&(rc.lc[lvl].commit[0]),
	       (uint8_t *)&(rc.lc[lvl].commit[2]),
	       sizeof(KCC_t));
        rc.lc[lvl].commit[1].index=-1;
        rc.lc[lvl].commit[2].index=-1;
	break;
      case 1:
        memcpy((uint8_t *)&(rc.lc[lvl].commit[0]),
	       (uint8_t *)&(rc.lc[lvl].commit[1]),
	       sizeof(KCC_t));
        memcpy((uint8_t *)&(rc.lc[lvl].commit[1]),
	       (uint8_t *)&(rc.lc[lvl].commit[2]),
	       sizeof(KCC_t));
        rc.lc[lvl].commit[2].index=-1;
        break;
      default:
        rc.lc[lvl].commit[0].index=-1;
        rc.lc[lvl].commit[1].index=-1;
        rc.lc[lvl].commit[2].index=-1;
        break;
      }
      rc.lc[lvl].chain=chn;
    }
  
  /**
   * Verify a new disclosed key based on the saved key commitment
   * @param: lvl, which key chain level 
   * @param: seq, the index of the key we try to verify
   * @param: new, point to the key we try to verify
   * @return: 0, verification fail
   * @return: 1, successfully verified key
   * @return: 2, unable to verify, the receiver don't have the commitment
   */

  uint8_t verify_key(uint8_t lvl, long seq, uint8_t* new)
    {
      uint8_t i;
      long chn=1+(seq-1)/rc.kc_len[lvl];// which key chain in this level
      long idx=1+(seq-1)%rc.kc_len[lvl];// which index in the key chain


      // if seq is 0, it means the first chain and the 0th key
      if(seq==0) {chn=1;idx=0;} 

      // move the key commitment, make it point to the commitment we concern
      refresh_lc(lvl,chn); 

      // if the receiver don't have the commitment,
      if(rc.lc[lvl].commit[1].index<0) return 2; 

      // generate the key by perform a number of pseudo random function
      KEYGEN(new, idx-rc.lc[lvl].commit[1].index, lvl, tmp);

      // if inconsistant key
      for(i=0;i<8;i++) if(tmp[i]!=rc.lc[lvl].commit[1].key[i])  return 0; 

      //save the newly verified key
      rc.lc[lvl].commit[1].index=idx;
      memcpy(rc.lc[lvl].commit[1].key,new,8);
      return 1;
    }
    
  /**
   * try to get a specific key
   * @param: lvl, which key chain level
   * @param: chn, which chain in this level
   * @param: idx, which key in this chain
   * @param: key, where to put the key
   * @return: FAIL, not able to get the key
   * @return: SUCCESS, get the key successfully
   */

  result_t get_key(uint8_t lvl, long chn, long idx, uint8_t *key) 
    {
      long i=rc.lc[lvl].chain-chn; 

      refresh_lc(lvl,chn);  

      // if the following condition is satisfied, we can get the
      // key from the saved key commitment.
      if((i==0 || i==1) && rc.lc[lvl].commit[1-i].index>=idx)
	return KEYGEN(rc.lc[lvl].commit[1-i].key, 
		      rc.lc[lvl].commit[1-i].index-idx,lvl,key);

      // if it is the highest level and cannot get the key from the commitment
      if(lvl==0) return FAIL;
      
      // try to get a high level key
      if(!get_key(lvl-1,1+chn/rc.kc_len[lvl-1],1+chn%rc.kc_len[lvl-1],tmp)) 
        return FAIL;

      call Primitive.PRF(tmp,0xffff-lvl,tmp); //perform F_{01} in tmp

      // generate the key we want from a high level key
      return KEYGEN(tmp,rc.kc_len[lvl]-idx+1, lvl,key);
    }

  /**
   * try to authenticate the buffered data packet
   * @param: auth_time, what time we perform this authentication
   */

  void authenticate_buffered_data(long long auth_time)
    {
      uint8_t i;
      uint8_t num;
      long when;
      Data_Packet_t packet;

      num=call Buffer.dataNum();// get the total number of data having buffered

      dbg(DBG_PACKET,"total number of buffered data packet %d\n",num);

      for(i=0;i<num;i++){

	call Buffer.nextData(&packet); // get the next buffered data
	dbg(DBG_PACKET,"get data packet for index %d\n",packet.index);

	// try to get key to authenticate this data packet
	if(get_key(MAX_LEVEL-1, 1+(packet.index-1)/rc.kc_len[MAX_LEVEL-1]
		   , 1+(packet.index-1)%rc.kc_len[MAX_LEVEL-1],tmp)) 
	{
	  //successfully get the key and try to verify the MAC value

	  call Primitive.PRF(tmp,0xffff,tmp); //generate K'_i in tmp

	  if(VERMAC(tmp,(uint8_t *)&(packet.index),4+DATA_SIZE,packet.mac)) 
	  {
	    //verify successfully, we find a authentic data packet
            when=1+(auth_time-rc.start_time+rc.delta)/rc.kc_int[MAX_LEVEL-1];

            //signal a event that a data packet is authenticated, wait for
            // futher processing
	    signal Receiver.authenticDataReady(&packet,when-packet.index);
	  } else dbg(DBG_PACKET,"get key but invalid MAC value\n");

	  //delete the this data packet from the buffer
	  call Buffer.delCurrentData();
	}
      }
    }
  
  /**
   * process the newly received data packet
   * @param: p, point to the buffer to store this data packet
   * @param: rcv_time, when the receiver received this packet
   */

  command void Receiver.ProcessData(Data_Packet_t *p, long long rcv_time)
    {
      char state;

      // check whether this packet is safe or not
      if(1+(rcv_time-rc.start_time+rc.delta)/rc.kc_int[MAX_LEVEL-1]
	 >=p->index+rc.delay) {
//	dbg(DBG_USR1,"unsafe data packet\n");
	return;
      } 

      // check the disclosed key in data packet
      if(p->index>=TESLA_DELAY) {
	state=verify_key(MAX_LEVEL-1,p->index-TESLA_DELAY,p->dis); 
	if(state==0) return;
	if(state==1) authenticate_buffered_data(rcv_time);
      } 
     
      // if disclosed key is verified or unable to verify because of
      // no commitment, the receiver save this data packet
      call Buffer.bufferData(p);
    }
  
  /**
   * process the newly received data packet
   * @param: p, point to the buffer to store this CDM packet
   * @param: rcv_time, when the receiver received this packet
   */
  command void Receiver.ProcessCDM(CDM_Packet_t *p, long long rcv_time)
    {
      char state;
      CDM_Packet_t packet;
      
      // check whether this packet is safe or not
      if((rcv_time-rc.start_time+rc.delta)/rc.kc_int[p->level]>=p->index) {
	//dbg(DBG_USR1,"unsafe cdm packet\n");
	return;
      }

      refresh_lc(p->level+1,p->index); 

      // try to verify the disclosed key
      if(!(state=verify_key(p->level,p->index-1,p->dis))) return;
      if(state==1) { // if disclosed key is verified
	dbg(DBG_PACKET,"Begin to authenticate previously saved CDM\n");

	//check all the buffered CDM packet 
	while(call Buffer.nextCDM(p->level,p->index-1,&packet)){
	  //Verify the MAC value using the disclosed key
   
          call Primitive.PRF(p->dis,0xffff,tmp); //generate K'_i in tmp

	  if(VERMAC(tmp,(uint8_t *)&(packet.index),12,packet.mac)){
	    dbg(DBG_USR1,"Find valid Mac for index %d\n",packet.index);

	    //if we find one authentic copy, no need to check the left CDMs
	    call Buffer.clearCDM(p->level);

	    //save the related information
	    rc.lc[p->level+1].commit[2].index=0;
	    memcpy(rc.lc[p->level+1].commit[2].key,packet.kc_2_0,8);
	  }
	}

	dbg(DBG_PACKET,"begin to authenticate previously saved Data\n");
	authenticate_buffered_data(rcv_time);
      }
      call Buffer.bufferCDM(p);
    }
}
