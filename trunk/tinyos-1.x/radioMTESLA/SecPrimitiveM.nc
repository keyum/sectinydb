/**
 *By Donggang Liu, dliu@unity.ncsu.edu
 */

module SecPrimitiveM {
  provides {
    interface Primitive;
  }
  uses {	
    interface MAC;
  }
}
implementation
{
  uint8_t random_key[8];
  uint32_t counter;
 
  command result_t Primitive.MAC (uint8_t *key, uint8_t *in, 
				  uint16_t len, uint8_t *out)
    {
      MACContext context; 
      call MAC.init(&context, 8, key);
      return call MAC.MAC (&context, in, len, out, 8);
    }

  command result_t Primitive.verifyMAC(uint8_t *key, uint8_t *in, uint16_t len,
                                       uint8_t *mac)
  {
      uint8_t i;
      MACContext context; 
      uint8_t tmp[8];
      call MAC.init(&context, 8, key);
      call MAC.MAC (&context, in, len, tmp, 8);
      for(i=0;i<8;i++) if(tmp[i]!=mac[i]) return FAIL;
      return SUCCESS;
  }

  command result_t Primitive.PRF(uint8_t *key, uint16_t x, uint8_t *out)
    {
      return call Primitive.MAC(key,(uint8_t *)&x, 2, out);
    }

  command result_t Primitive.PRG(uint8_t *out)
    {
      counter++;
      return call Primitive.MAC(random_key,(uint8_t *)&counter, 4, out);
    }

  command uint16_t Primitive.rand(uint16_t start, uint16_t end)
    {
      uint16_t tmp[4];
      if(!call Primitive.PRG((uint8_t *)tmp)) return FAIL;
      return start+tmp[0]%end;
    }
  
  command result_t Primitive.generate_key_from(uint8_t *key, long d, 
					       long x, uint8_t *out)
    {
      uint16_t i;
      if(d<0) return FAIL;
      memcpy(out,key,8);
      for(i=0;i<d;i++){
	if(!call Primitive.PRF(out,x,out)) return FAIL;
      }
      return SUCCESS;
    }
}
