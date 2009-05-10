1;

#Given current battery lifetime, information about the cost to sample, the number of messages
#required per sample, the epoch duration (input sample rate), and the number of samples
#aggregated per packet (sent once per ed/#samples), compute sensor lifetime

function lifetime = computeLifetime(curVReading, sampleTimeMs, sampleCostUa, numMsgs, epochDur, overSample)
  uaActive = 5000; #current draw` when active, no radio
  uaListen = 10000; # current draw when listening
  uaXmit = 13000; #current draw when xmitting
  uaSleep = 500; #current draw when sleeping
  msXmit = 32; #ms radio is on per transmission
  mahCapacity = 6000; #battery capacity, mah
  maxVReading = 930; #maximum V reading
  minVReading = 340; #min V reading
  Vdraw = 3; #voltage draw of battery
  sPerListenXmitRound = 1; #number of seconds we must listen per round


  xmitCostJ = ((uaXmit * msXmit * Vdraw))/(1e3*1e6);
  sampleCostJ = ((uaActive + sampleCostUa) * sampleTimeMs * Vdraw * overSample)./ (1e3*1e6);
  mahRemaining = [((curVReading - minVReading)* mahCapacity)/(maxVReading - minVReading) ];
  uaAvgActive = (1e6)*(sampleCostJ + xmitCostJ*numMsgs)/(Vdraw * sPerListenXmitRound) + uaListen;

 # this is derived by solving for lifetime hours remaining in uaAvg below (given epochDur)
  lifetime = (1000 * mahRemaining * epochDur) ./ (1000 * sPerListenXmitRound * (uaAvgActive - uaSleep) + uaSleep * epochDur); 

endfunction

#return a triplet of (oversample rate, epoch dur, predicted lifetime) for
# the given lifetime goals
# epoch dur of 0 indicates the lifetime goal is unsatisfiable
function sr=getSR(lifetimeHoursRem,
			       curVReading,
			       sampleTimeMs,
			       sampleCostUa,
			       maxSampleEpochDur,
			       numMsgs,
			       numSamples)
# see comments on constants above
  uaActive = 9000;
  uaListen = 9000;
  uaXmit = 10000;
  uaSleep = 220;
  msXmit = 32;
  mahCapacity = 6000;
  maxVReading = 985;
  minVReading = 370;
  Vdraw = 3;
  sPerListenXmitRound = 1;
  
  
  xmitCostUa = ((uaXmit * msXmit * numMsgs))/(1e3 * sPerListenXmitRound);
  sampleCostUa = ((uaActive + sampleCostUa) * sampleTimeMs * numSamples)/(1e3 *sPerListenXmitRound);
  mahRemaining(1:size(lifetimeHoursRem)(2)) = [((curVReading - minVReading)* mahCapacity)/(maxVReading - minVReading) ];
  uaAvg = ((mahRemaining * 1000)./lifetimeHoursRem);
  uaAvgActive = (sampleCostUa + xmitCostUa) + uaListen;


#derived by setting epochDur = samples/epoch * maxSampleEpochDur
# and solving for samples/epoch in getEpochDur below
  sr(1,:) = ((sPerListenXmitRound*1000) * (xmitCostUa + uaListen))./ \
       ((maxSampleEpochDur * (uaAvg - uaSleep)) - (sPerListenXmitRound*1000)*sampleCostUa);
  sr(2,:) = sr(1,:) * maxSampleEpochDur;

#if any epoch durs are < 0, return 0 (indicates unsatisfiable request)
  for i=1:size(lifetimeHoursRem)(2)
    if (sr(2,i) < 0) 
      sr(2,i) = 0;
    endif
  endfor
#round sample rates to nearest (larger) integer -- guarantee lifetime goal is satisfiable
  sr(1,:) = ceil(sr(1,:));
  sr(3,:) = computeLifetime(curVReading, sampleTimeMs, sampleCostUa, numMsgs, sr(2,:), sr(1,:));
endfunction     


#old way of doing this
function epochDur=getEpochDur(lifetimeHoursRem,
			       curVReading,
			       sampleTimeMs,
			       sampleCostUa,
			       numMsgs,
			       numSamples,
			       oversample) 
  uaActive = 5000;
  uaListen = 10000;
  uaXmit = 13000;
  uaSleep = 500;
  msXmit = 32;
  mahCapacity = 6000;
  maxVReading = 930;
  minVReading = 340;
  Vdraw = 3;
  sPerListenXmitRound = 1;

  xmitCostJ = ((uaXmit * msXmit * Vdraw))/(1e3*1e6);
  sampleCostJ = ((uaActive + sampleCostUa) * sampleTimeMs * Vdraw * oversample)/(1e3*1e6);
  mahRemaining(1:size(lifetimeHoursRem)(2)) = [((curVReading - minVReading)* mahCapacity)/(maxVReading - minVReading) ];
  uaAvg = ((mahRemaining * 1000)/lifetimeHoursRem);
  uaAvgActive = (1e6)*(sampleCostJ*numSamples + xmitCostJ*numMsgs)/(Vdraw * sPerListenXmitRound) + uaListen;
  dutyCycle = ((uaAvg - uaSleep))/(uaAvgActive - uaSleep);
  epochDur = (sPerListenXmitRound*1000)/dutyCycle;
endfunction


function epochDur=plotlifetime(lifetimeHoursRem,
			       curVReading,
			       sampleTimeMs,
			       sampleCostUa,
			       maxSampleEpochDur,
			       numMsgs,
			       numSamples)
  uaActive = 9000;
  uaListen = 10000;
  uaXmit = 13000;
  uaSleep = 500;
  msXmit = 32;
  mahCapacity = 6000;
  maxVReading = 985;
  minVReading = 340;
  Vdraw = 3;
  sPerListenXmitRound = 1;

  
  xmitCostJ = ((uaXmit * msXmit * Vdraw))/(1e3*1e6);
  sampleCostJ = (sampleCostUa * sampleTimeMs * Vdraw)/(1e3*1e6);
  mahRemaining(1:size(lifetimeHoursRem)(2)) = [((curVReading - minVReading)* mahCapacity)/(maxVReading - minVReading) ];
#     printf ("mahRemaining=%d\n", mahRemaining);
  uaAvg = ((mahRemaining * 1000)./lifetimeHoursRem);
#     printf ("uaAvg=%d\n", uaAvg);
     uaAvgActive = (1e6)*(sampleCostJ*numSamples + xmitCostJ*numMsgs)/(Vdraw * sPerListenXmitRound) + uaListen;
#     printf ("uaAvgActive=%d\n", uaAvgActive);
     dutyCycle = ((uaAvg - uaSleep))/(uaAvgActive - uaSleep);
     printf("dutyCycle=%f\n", dutyCycle);
     
     epochDur = ones(2, size(lifetimeHoursRem)(2));
     epochDur(1,:) = (sPerListenXmitRound*1000)./dutyCycle;
     
     for i = 1:size(epochDur)(2)
       if (epochDur(1,i) > maxSampleEpochDur)
	# rate at which we will oversample
         epochDur(2,i) = ceil(epochDur(1,i) / maxSampleEpochDur);
	 # verify that this over sampling wont use too much power
	 lifetime = computeLifetime(curVReading, sampleTimeMs, sampleCostUa, numMsgs, epochDur(1,i), epochDur(2,i) * numSamples);
	 if (lifetime < lifetimeHoursRem(i))
	   epochDur(1,i) = getEpochDur(lifetimeHoursRem(i), curVReading, sampleTimeMs, sampleCostUa, numMsgs, numSamples, epochDur(2,i));
	 endif
       endif
     endfor
endfunction

