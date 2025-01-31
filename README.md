# Please move to https://github.com/sidd-kishan/pico-webserver for better performance as https://github.com/sidd-kishan/pico-webserver does not use freertos and hence on baremetal and the latest https://github.com/raspberrypi/pico-sdk with latest pico-sdk/lib hence getting phenomenal performance gain and stability and low temps. 

## This repo will get very rare updates most of my focus will be on https://github.com/sidd-kishan/pico-webserver hence removing tags.

### A Driverless RNDIS based wifi adapter based on pi pico w to enable usb wifi wlan on Windows on ARM devices like Windows on Raspberry pi 4 that makes use of the default driver of Windows RNDIS drivers

### pico-rndis-use-freerots
A project for rp2040
Use rndis in tinyusb and use freerots to create usb-related tasks.You can also use socket-related interfaces in this project
## Overview
```
        ---------------------------       -------------------------------                         ----------
       |Full USB 12 Mbps rndis link| --->| PI PICO W ( MCU <-SPI-> WIFI) | <----- 54 Mbps------> |2.4 Ghz AP|
        ---------------------------       -------------------------------                         ----------
               |                                                                                    |
               V                                                                                    V
            Raspberry pi (Windows on ARM)                                                         Client
```
## Installation
It requires a patched version of the `pico-sdk`.

```bash
apt install git build-essential cmake gcc-arm-none-eabi doxygen libstdc++-arm-none-eabi-newlib iperf liblwip-dev unzip ninja-build
git clone --recursive https://github.com/sidd-kishan/pico-rndis-use-freertos.git
cd pico-rndis-use-freertos
git clone https://github.com/sidd-kishan/pico-sdk.git
cd pico-sdk
git submodule update --init
cd lib
git clone https://github.com/sidd-kishan/Rtos_course_project.git
mv Rtos_course_project/FreeRTOS-Kernel/ .
cd ../../
mkdir build
cd build
PICO_SDK_PATH=../pico-sdk cmake ..
make -j$(nproc --all)
netcat 192.168.7.1 2542 -v
getinfo
setwifi ssid:SSS_EXT key:1234567890
getcred
diswifi
```
![image](https://github.com/sidd-kishan/pico-rndis-use-freertos/assets/1007208/c21e79fa-1ccf-4a30-a4f2-ac1f6df0e06b)


### License
This project is distributed by an [GPL-2.0 License](/LICENSE).
### Disclaimer
This project isn't in any way associated with the Raspberry Pi Foundation.
### URLs used while research
https://www.google.com/search?q=pico_cyw43_arch_lwip_sys_freertos&rlz=1C1ONGR_enIN1051IN1051&oq=pico_cyw43_arch_lwip_sys_freertos&gs_lcrp=EgZjaHJvbWUyBggAEEUYOTIGCAEQRRg90gEHNTQ1ajBqN6gCALACAA&sourceid=chrome&ie=UTF-8

https://mcuoneclipse.com/2023/03/19/ble-with-wifi-and-freertos-on-raspberry-pi-pico-w/

https://github.com/ErichStyger/mcuoneclipse/blob/master/Examples/RaspberryPiPico/pico_W_BLE/src/wifi.c

https://forums.raspberrypi.com/viewtopic.php?t=344869

https://github.com/szatmary/picow_dev_template/tree/main

https://www.google.com/search?q=pico+%22multicore_launch_core1%22+wifi&rlz=1C1ONGR_enIN1051IN1051&ei=k-eqZLSVO5ak1e8P6oOZmAk&ved=0ahUKEwj0qubgjIKAAxUWUvUHHepBBpMQ4dUDCA8&uact=5&oq=pico+%22multicore_launch_core1%22+wifi&gs_lcp=Cgxnd3Mtd2l6LXNlcnAQAzIFCAAQogQyBQgAEKIEMgUIABCiBDIFCAAQogQ6CggAEEcQ1gQQsANKBAhBGABKBQhAEgExUM8HWIgeYNEfaAFwAXgAgAHgAYgB4AGSAQMyLTGYAQCgAQHAAQHIAQg&sclient=gws-wiz-serp

https://community.element14.com/products/raspberry-pi/b/blog/posts/four-multicore-c-programs-for-raspberry-pi-pico-using-arduino-ide

https://github.com/raspberrypi/pico-examples/blob/master/multicore/hello_multicore/multicore.c

https://github.com/sidd-kishan?tab=repositories

https://github.com/sidd-kishan/pico-rndis-use-freerots/tree/master

https://wokwi.com/projects/360480722185134081

https://www.google.com/search?q=pico_cyw43_arch_lwip_sys_freertos&rlz=1C1ONGR_enIN1051IN1051&oq=pico_cyw43_arch_lwip_sys_freertos&gs_lcrp=EgZjaHJvbWUqBggAEEUYOzIGCAAQRRg7MgYIARBFGD3SAQc4NDdqMGo5qAIAsAIA&sourceid=chrome&ie=UTF-8

https://forums.raspberrypi.com/viewtopic.php?t=344869

https://www.google.com/search?q=multicore+freertos+pico+w&rlz=1C1ONGR_enIN1051IN1051&oq=multicore+freertos+pico+w&gs_lcrp=EgZjaHJvbWUyBggAEEUYOdIBCDYyMDdqMGo0qAIAsAIA&sourceid=chrome&ie=UTF-8

https://community.element14.com/products/raspberry-pi/b/blog/posts/raspberry-pico---setup-multi-core-freertos-smp

https://community.element14.com/products/raspberry-pi/b/blog/posts/raspberry-pico---create-an-new-multi-core-freertos-smp-project

https://www.freertos.org/a00125.html


### Contributing
Everyone is very welcome to contribute to our project.
