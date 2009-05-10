includes MTESLA;

module simM {
  provides {
    interface StdControl;
  }
  uses {
    interface Sender;
    interface Receiver;
    interface Attacker;
    interface Random;
    interface Timer;
    interface StdControl as RadioControl;
    interface BareSendMsg as RadioSend;
    interface ReceiveMsg as RadioReceive;
  }
}
implementation {
	
  long node_ID;
  long rnd;
  bool simstop;

  long authentic_CDM_num;
  long forged_CDM_num;
  long authenticated_data_num;
  long received_data_num;
  long generated_data_num;	
  long node_loss_rate;
  long long authentication_delay;

  CDM_Packet_t pCDM;
  Data_Packet_t pData;

  TOS_Msg buffer; 
  TOS_MsgPtr ourBuffer;
  bool sendPending;

  result_t bs_send()
    {
      rnd=call Random.rand();
      if(rnd%REBROADCAST_RATE<TICK_INTERVAL){

	if(call Sender.generateCDM(0,tos_state.tos_time/4000,&pCDM)) {
	  buffer.data[0]=pCDM.level;
	  memcpy(buffer.data+1,(uint8_t *)&(pCDM.index),28);
	  buffer.addr=TOS_BCAST_ADDR;
	  buffer.length=29;

	  dbg(DBG_PACKET,"base station send first part of CDM packet\n");
	  sendPending=TRUE;
	  authentic_CDM_num++;
	  return call RadioSend.send(ourBuffer);
	} else simstop=TRUE; 
      }
      
      rnd=call Random.rand();
      if(rnd%DATA_RATE<TICK_INTERVAL){

	if(call Sender.authenticateData(tos_state.tos_time/4000,&pData)) {
	  buffer.data[0]=1;
	  memcpy(buffer.data+1,(uint8_t *)&(pData.index),28);
	  buffer.addr=TOS_BCAST_ADDR;
	  buffer.length=29;
	  dbg(DBG_PACKET,"base station send Data packet\n");
	  sendPending=TRUE;
          generated_data_num++;
	  return call RadioSend.send(ourBuffer);
	}
      }
      return SUCCESS;
    } 

  result_t at_send()
    {
      rnd=call Random.rand();
      if(rnd%ATTACK_RATE<TICK_INTERVAL){


	call Attacker.InsertCDM(&pCDM);
	buffer.data[0]=pCDM.level;
	memcpy(buffer.data+1,(uint8_t *)&(pCDM.index),28);
	buffer.addr=TOS_BCAST_ADDR;
	buffer.length=29;

	dbg(DBG_PACKET,"attacker send forged CDM packet\n");
	sendPending=TRUE;
        forged_CDM_num++;
	return call RadioSend.send(ourBuffer);
      }
      return SUCCESS;
    }
  
  
  task void simu()
    {
      switch(node_ID) {
      case 0: //base station
	bs_send();
	break;
      case 1: //attacker
	at_send();
	break;
      default:
	break;
      }
    }
  
  command result_t StdControl.init() {
    Sender_Config_t sndcon;
    Receiver_Config_t rcvcon;

    simstop=FALSE;
    authenticated_data_num=0;
    received_data_num=0;
    authentic_CDM_num=0;
    forged_CDM_num=0;
    generated_data_num=0;
    authentication_delay=0;
    node_loss_rate=LOSS_RATE;

    ourBuffer = &buffer;
    sendPending = FALSE;
    node_ID=TOS_LOCAL_ADDRESS;
    memset((uint8_t*)&sndcon,0,sizeof(Sender_Config_t));

    // master MTESLA key
    sndcon.MT_key[0]=0x21;
    sndcon.MT_key[1]=0xe2;
    sndcon.MT_key[2]=0xf3;
    sndcon.MT_key[3]=0x04;
    sndcon.MT_key[4]=0x51;
    sndcon.MT_key[5]=0xd6;
    sndcon.MT_key[6]=0xe1;
    sndcon.MT_key[7]=0x08;

    sndcon.kc_len[0]=200;
    sndcon.kc_len[1]=600;
    sndcon.kc_int[1]=100;
    sndcon.kc_int[0]=sndcon.kc_int[1]*sndcon.kc_len[1];
    sndcon.start_time=tos_state.tos_time/4000;
    call Random.init();
    call Sender.init(&sndcon);
    call Sender.generateConf(&rcvcon);
    rcvcon.delta=CLOCK_DISCREPANCY;
    call Receiver.init(&rcvcon);
    return call RadioControl.init();
  }

  command result_t StdControl.start() {
    call Timer.start(TIMER_REPEAT, TICK_INTERVAL);
    return call RadioControl.start();
  }

  command result_t StdControl.stop() {
    call Timer.stop();
    return call RadioControl.stop();
  }

  event result_t Receiver.authenticDataReady(Data_Packet_t *p, long auth_delay)
  {
    authenticated_data_num++;
    authentication_delay+=auth_delay;
    if(node_ID>1){
	dbg(DBG_PACKET,"received packet: %d\n",received_data_num);
	dbg(DBG_PACKET,"authenti packet: %d\n",authenticated_data_num);
    }
    return SUCCESS;
  }

  event TOS_MsgPtr RadioReceive.receive(TOS_MsgPtr data) {
    if(data->data[0]>1) simstop=TRUE;

    rnd=call Random.rand();
    if(rnd%100<node_loss_rate) return data;

    if(data->data[0]==0) { //CDM packet
      pCDM.level=0;
      memcpy((uint8_t *)&(pCDM.index),data->data+1,28);
      if(node_ID==1) {
//	dbg(DBG_USR1,"forged CDM packet: %d\n",forged_CDM_num);
	call Attacker.ListenCDM(&pCDM,tos_state.tos_time/4000);
      }
      if(node_ID>1) call Receiver.ProcessCDM(&pCDM,tos_state.tos_time/4000);
    } else { // Data Packet
      received_data_num++;
      memcpy((uint8_t *)&(pData.index),data->data+1,28);
      if(node_ID==1) call Attacker.ListenData(&pData,tos_state.tos_time/4000);
      if(node_ID>1) call Receiver.ProcessData(&pData,tos_state.tos_time/4000);
    }
    return data;
  }
  
  event result_t RadioSend.sendDone(TOS_MsgPtr msg, result_t success) {
    sendPending=FALSE;
    return SUCCESS;
  }

  event result_t Timer.fired()
  {
    if(!sendPending&&!simstop) post simu();
    if(simstop) {
      call StdControl.stop();
      if(node_ID==0){
	dbg(DBG_USR1,"authentic CDM packet: %d\n",authentic_CDM_num);
	dbg(DBG_USR1,"generated Data packet: %d\n",generated_data_num);
        buffer.data[0]=2;
	buffer.addr=TOS_BCAST_ADDR;
	buffer.length=1;
	dbg(DBG_PACKET,"base station send stop signal\n");
	sendPending=TRUE;
	return call RadioSend.send(ourBuffer);
      }
      if(node_ID==1){
	dbg(DBG_USR1,"forged CDM packet: %d\n",forged_CDM_num);
      }
      if(node_ID>1){
//	dbg(DBG_USR1,"loss rate %d\%\n",node_loss_rate);
//	dbg(DBG_USR1,"received packet: %d\n",received_data_num);
//	dbg(DBG_USR1,"authenti packet: %d\n",authenticated_data_num);
	dbg(DBG_USR1,"%d:authentication rate: %d\%\n",1+((node_ID-2)/4)*2,(authenticated_data_num*100)/received_data_num);
//	dbg(DBG_USR1,"authentication delay: %d ms\n",(authentication_delay*100)/authenticated_data_num);
      }
    }
    return SUCCESS;
  }

}


