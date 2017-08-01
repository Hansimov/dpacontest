f = open('mytraces2text.bat','w')
f.write("@echo off\n")
f.write("@echo Launching traces2text.exe...\n")
for i in range(0,10):
    f.write("echo " + "Converting trace 0000" + str(i) + '\n')
    f.write("traces2text.exe v4_RSM ./00000/Z1Trace0000" + str(i) + ".trc.bz2 " + "./mytracetexts/tracetexts0000"+str(i) + '\n')
for i in range(10,100):
    f.write("echo " + "Converting trace 000" + str(i) +'\n')
    f.write("traces2text.exe v4_RSM ./00000/Z1Trace000" + str(i) + ".trc.bz2 " + "./mytracetexts/tracetexts000"+str(i) +'\n')
for i in range(100,200):
    f.write("echo " + "Converting trace 00" + str(i) + '\n')
    f.write("traces2text.exe v4_RSM ./00000/Z1Trace00" + str(i) + ".trc.bz2 " + "./mytracetexts/tracetexts00"+str(i)+'\n')
f.write("pause")
f.close()