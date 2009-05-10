includes MTESLA;
configuration sim {
}
implementation {
  components Main, simM, 
             MTESLASenderM, MTESLAReceiverM, MTESLAAttackerM,
             Simple_BufferM, SecPrimitiveM, 
             CBCMAC, RC5M, RandomLFSR, TimerC,
	     RadioCRCPacket as Comm;

  Main.StdControl -> simM.StdControl;

  simM.Sender -> MTESLASenderM;
  simM.Receiver -> MTESLAReceiverM;
  simM.Attacker -> MTESLAAttackerM;
  simM.Random->RandomLFSR;
  simM.RadioControl -> Comm;
  simM.RadioSend -> Comm;
  simM.RadioReceive -> Comm;
  simM.Timer -> TimerC.Timer[unique("Timer")];

  MTESLASenderM.Primitive -> SecPrimitiveM;
  MTESLAReceiverM.Primitive ->SecPrimitiveM;
  MTESLAReceiverM.Buffer -> Simple_BufferM;
  Simple_BufferM.Primitive-> SecPrimitiveM;
  SecPrimitiveM.MAC -> CBCMAC;
  CBCMAC.BlockCipher -> RC5M;
  CBCMAC.BlockCipherInfo -> RC5M;

}

