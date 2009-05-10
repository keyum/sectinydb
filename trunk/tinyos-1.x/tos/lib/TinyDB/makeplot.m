hold off
for i=100:100:500
range = [24:24:10000];
sr = getSR(range,900,1,100,i,1,1);
tit = sprintf(";V = 900, maxEpochDur = %d;", i);
plot (range/(24 * 7), sr(2,:), tit);
hold on
#sr = getSR([24:24:8000],800,1,100,i,1,1);
#tit = sprintf(";V = 800, maxEpochDur = %d;", i);
#plot (sr(2,:),tit);
#sr = getSR([24:24:6000],700,1,100,i,1,1);
#tit = sprintf(";V = 700, maxEpochDur = %d;", i);
#plot (sr(2,:),tit);
#sr = getSR([24:24:3000],600,1,100,i,1,1);
#tit = sprintf(";V = 600, maxEpochDur = %d;", i);
#plot (sr(2,:),tit);
#sr = getSR([24:24:2000],500,1,100,i,1,1);
#tit = sprintf(";V = 500, maxEpochDur = %d;", i);
#plot (sr(2,:),tit);
xlabel("Query Lifetime, Weeks");
ylabel("Delivery Interval, ms");
title("Maximum Sample Rate vs. Delivery Interval For Varying Query Lifetimes");
endfor
