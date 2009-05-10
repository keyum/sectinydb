/**
 *By Donggang Liu, dliu@unity.ncsu.edu
 */

includes MTESLA;

module Simple_BufferM {
  provides {
    interface Buffer;
  }
  uses {
    interface Primitive;
  }
}
implementation
{

  //buffer to store a single CDM packet
  typedef struct CDM_Buffer_Unit_t {
    uint8_t kc_2_0[8];
    uint8_t mac[8];
  } CDM_Buffer_Unit_t;
  
  //buffer to store a single Data packet
  typedef struct Data_Buffer_Unit_t {
    long index;
    uint8_t data[DATA_SIZE];
    uint8_t mac[8];
  } Data_Buffer_Unit_t;
  
  //the buffer to store all CDM packets
  typedef struct CDM_Buffer_t {
    long index; // the index of CDM packets stored in this buffer
    uint8_t counter;// the number of CDM packet stored
    uint8_t pos;
    CDM_Buffer_Unit_t buf[NUM_CDM_BUFFER];
  } CDM_Buffer_t;
  
  typedef struct Data_Buffer_t {
    long index;// the position of of previous scanned data packet
    uint8_t counter;// the number of data packet stored
    Data_Buffer_Unit_t buf[NUM_DATA_BUFFER];
  } Data_Buffer_t;
  
  Data_Buffer_t data_buffer[1];
  CDM_Buffer_t cdm_buffer[MAX_LEVEL-1];
  
  /**
   * Initialize the buffer. set all to zero 
   */
 
  uint8_t cdm_buffer_to_use;
  uint8_t data_buffer_to_use;  

  command void Buffer.init()
  {
     data_buffer_to_use=NUM_DATA_BUFFER;
     cdm_buffer_to_use=NUM_CDM_BUFFER;
     memset((uint8_t *)data_buffer,0,sizeof(Data_Buffer_t));
     memset((uint8_t *)cdm_buffer,0,sizeof(CDM_Buffer_t)*(MAX_LEVEL-1));
  }

  /**
   * get the number of data packets buffered
   * @return: the number of buffered data packets 
   */

  command uint8_t Buffer.dataNum()
    {
      return data_buffer[0].counter;
    }

  /**
   * get the next buffered data packet start from the previous scanned position
   * @param: data_packet, point to the buffer to store the data packet
   * @return: 0: no more data packet
   *          1: get one data packet 
   */

  command uint8_t Buffer.nextData(Data_Packet_t *data_packet )
    {
      int i,j;

      //begin to search the next data packet, start from the previous 
      //scanned position
      for(i=1;i<=data_buffer_to_use;i++) {
	j=(i+data_buffer[0].index)%data_buffer_to_use;
	if(data_buffer[0].buf[j].index>0)
	  {
	    //if a valid data packet contained, copy to the buffer 
	    //at *data_packet
	    data_buffer[0].index=j;
	    data_packet->index=data_buffer[0].buf[j].index;
	    dbg(DBG_PACKET,"find data at pos:%d\n",j);
	    memcpy(data_packet->data,data_buffer[0].buf[j].data,8+DATA_SIZE);
	    return 1;
	  }
      }
      return 0;
    }

  /**
   * delete the data previous scanned
   */

  command void Buffer.delCurrentData()
    {
      data_buffer[0].buf[data_buffer[0].index].index=-1;
      //decrease the counter which indicates the number of data packet stored
      data_buffer[0].counter--;
    }
  
  /**
   * store a new data packet in buffer, if buffer is full, replace the oldest
   * data packet, which has the smallest index value
   * @param: data_packet,point to the new data packet 
   */
  
  command void Buffer.bufferData(Data_Packet_t *data_packet)
    {
      int i,min,idx;

      // find the oldest data packet buffered or a empty position
      min=data_buffer[0].buf[0].index;
      idx=0;
      for(i=1;i<data_buffer_to_use;i++) {
	if(data_buffer[0].buf[i].index<min)
	  {
	     min=data_buffer[0].buf[i].index;
	     idx=i;
	  }
      }
      
      // store the data packet
      data_buffer[0].buf[idx].index=data_packet->index;
      if(min<=0) data_buffer[0].counter++;
      dbg(DBG_PACKET,"buffer data at pos: %d,index=%d\n",
	  idx,data_buffer[0].buf[idx].index);
      memcpy(data_buffer[0].buf[idx].data,data_packet->data,8+DATA_SIZE);
    }

  /**
   * clear the whole CDM buffer for a specific level
   * @param: level, which level to clear
   */

  command void Buffer.clearCDM(int level)
    {
      cdm_buffer[level].counter=0;
      cdm_buffer[level].pos=0;
    }
  
  /**
   * get the next buffered CDM packet for a specific level
   * @param: cdm_packet, point to the buffer to store the cdm packet
   * @return: 0: no more cdm packet
   *          1: get one cdm packet 
   */

  command uint8_t Buffer.nextCDM(int level, int id, CDM_Packet_t *cdm_packet)
    {
      // if the index of saved cdm packet is what we want, then find one.
      // if the index of saved cdm packet is smaller than what we want, then
      // just clear all CDM buffer. otherwise, do nothing
      if(cdm_buffer[level].counter==0) return 0;

      if(cdm_buffer[level].index==id) {
        cdm_packet->level=level;
        cdm_packet->index=id;
	memcpy(cdm_packet->kc_2_0,cdm_buffer[level].buf[cdm_buffer[level].pos].kc_2_0,16);
	cdm_buffer[level].pos++;
	cdm_buffer[level].counter--;
	return 1;
      } else if(cdm_buffer[level].index<id) call Buffer.clearCDM(level);
      return 0;
    }
  
  /**
   * store a new CDM packet in buffer, using multiple random selection 
   * strategy discussed in our paper.
   * @param: data_packet,point to the new CDM packet 
   */

  command void Buffer.bufferCDM(CDM_Packet_t *p)
    {
      uint8_t i;

      //if the index of saved CDM packet is less than the new CDM packet,
      //then, clear the buffer 
      if(cdm_buffer[p->level].index<p->index) {
	call Buffer.clearCDM(p->level);
	cdm_buffer[p->level].index=p->index;
      }

      //if the buffer still has empty position, just save it there
      if(cdm_buffer[p->level].counter<cdm_buffer_to_use) {
	memcpy(cdm_buffer[p->level].buf[cdm_buffer[p->level].counter].kc_2_0,
	       p->kc_2_0,16);
	dbg(DBG_PACKET,"buffer new received CDM packet at pos %d\n",
            cdm_buffer[p->level].counter);
	cdm_buffer[p->level].counter++;
      } else if(call Primitive.rand(1,cdm_buffer[p->level].counter)
		<=cdm_buffer_to_use){
	//if buffer is full, save it at a particular probability,
	//and then, random select one position and replace the buffer there
	i=call Primitive.rand(1,cdm_buffer_to_use)-1;
        dbg(DBG_PACKET,"replace old received CDM packet at pos %d\n",i);
	memcpy(cdm_buffer[p->level].buf[i].kc_2_0, p->kc_2_0,16);
      }
    }
}
