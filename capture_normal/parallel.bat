@echo off
REM to concurrently start 10 instances of chrome to collect normal traffic

start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 0 -e 4999
start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 5000 -e 9999
start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 10000 -e 19999
start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 20000 -e 24999
start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 25000 -e 29999
:: start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 30000 -e 34999
:: start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 35000 -e 39999
:: start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 40000 -e 44999
:: start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 45000 -e 49999
:: start cmd /k python C:\Users\Traffic_collection\Desktop\site-sniffing\capture_normal\captureTraffic.py -s 50000 -e 58202

pause