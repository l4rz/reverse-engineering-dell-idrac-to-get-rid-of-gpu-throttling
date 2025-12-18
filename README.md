# Reverse engineering Dell iDRAC to get rid of GPU throttling

## TL;DR
Unsupported GPUs in Dell C4130 get throttled, here's how to prevent this from happening.

*Most of the text contained herein is the original reverse enginnering from 
[l4rz](https://github.com/l4rz/reverse-engineering-dell-idrac-to-get-rid-of-gpu-throttling). The text by [re-l](https://github.com/re-l/re-dell-idrac-8-c4130) is in italics. We build upon his research to provide a GPU throttling fix that does not overwrite support for existing GPUs and cleanly survives iDRAC updates/upgrades/resets.*

## The problem

Dell PowerEdge C4130 ("C4130") is a versatile platform, accomodating up to four GPUs per 1U box. It is readily available on eBay so it could be used for various custom builds, including SXM2 GPUs. One of C4130 options, "Configuration K", comes with NVLink interposer board which provides NVLink interconnection and PCIe uplink for up to four SXM2 Nvidia Tesla GPUs, P100s or V100s.

Generally, adding hardware that is not intended by Dell to be utilized in approved configurations ("not supported by Dell") alters the server's behaviour in some way. E.g. it is well known that adding a third-party PCIe NIC makes fans run at the maximum speed. It's a lot less pleasant when it comes to GPUs. "Not supported by Dell" GPUs end up throttled with clocks reduced 75% or more. For instance, this is what happens when one puts NVidia Tesla V100-SXM2-32GB, Dell p/n `NWWWX` into C4130:


```
Clocks Throttle Reasons
    Idle                              : Not Active
    Applications Clocks Setting       : Not Active
    SW Power Cap                      : Not Active
    HW Slowdown                       : Active
        HW Thermal Slowdown           : Not Active
        HW Power Brake Slowdown       : Active

Clocks
    Graphics                          : 382 MHz
    SM                                : 382 MHz
    Memory                            : 877 MHz
    Video                             : 1372 MHz
```
The same V100-SXM2-32GB `NWWWX` module does not exhibit this behaviour in Dell PowerEdge C4140 since this kind of configuration is "supported by Dell". Switching to a C4140 could be seen as a solution, however C4140s are more scarce and expensive, especially in SXM2 configurations.

Unfortunately Dell [does not provide](https://www.dell.com/community/PowerEdge-Hardware-General/NVIDIA-v100-32GB-SXM2-Dell-p-n-NWWWX-in-Dell-C4130-Configuration/m-p/8051605#M71327) any remedies to that behaviour. It has nothing to do with BIOS/iDRAC versions, power supplies and/or gauge of GPU cables. As a consequence, effectively it's not possible to use 32Gb V100s, as well as some non-Dell OEMed P100s, in a C4130.

Curious about finding a way to counter this behaviour, I did some reverse engineering of Dell Baseboard Management Controller ("BMC") aka iDRAC.

## Searching for the solution

iDRAC image consists of Linux kernel, Linux filesystem and some configuration files, as can be observed by downloading iDRAC self-extracting .EXE for Windows, unzipping it and [binwalking](https://github.com/ReFirmLabs/binwalk). It is possible therefore to gain a root access to a running iDRAC8, either via its serial console ([this requires soldering a serial header to motherboard](https://github.com/Fohdeesha/idrac-7-8-reverse-engineering/)), or over the network connection, by exploiting one of known vulnerabilities (CVE-2018-1207, CVE-2018-15774, and CVE-2018-15776, also cf. [The Unbearable lightness
of BMC, Blackhat 2018](https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf)). Some Russian guy [put together a Python script](https://github.com/KraudSecurity/Exploits/blob/master/CVE-2018-1207/CVE-2018-1207.py) to exploit CVE-2018-1207; this exploit requires gcc cross compiler for SH4 architecture (iDRAC8 is based on  Renesas SH7758), [here's payload.so built for remote (iDRAC) IP 192.168.0.100](http://l4rz.net/payload.so). It works only with iDRAC verions lower than < 2.52.52.52, but it's not really an issue since iDRAC8 can be easily downgraded.

Trying various things in iDRAC shell and closely examining scripts and binaries extracted from iDRAC image allows to shed a light on behavior of iDRAC. The iDRAC main process is `fullfw`; it handles the entirety of BMC logic, from system characterization on startup, to initialization of onboard components and CPLD in particular. It also takes care of supplementary functions, like Dell lifecycle controller and iDRAC web interface.

By enabling debug mode in iDRAC shell:

```  
debugcontrol -l 10
debugcontrol -s 1024
debugcontrol -i start
debugcontrol -g start
```

one can observe numerous messages in `/tmp/idraclogs` related to power and thermal configuration.

During system bootup, iDRAC obtains the configuration of server and reads power and thermal tables from the flash (`/flash/pd0/ipmi/Trailbreaker/platcfgfld.txt` and `/flash/pd0/ipmi/Trailbreaker/thermalconfig.txt` respectively; `Trailbreaker` is the Dell's code for C4130). These files contain PCI vendor/subvendor and device/subdevice IDs for supported PCIe cards, including GPUs. The throttled condidion is being activated[^1] if iDRAC is unable to find a match, for instance, for V100-SXM2-32GB GPU (DID=0x1db5 and SDID=0x1249, while DID=0x1db1 and SDID=0x1212 of the supported V100-SXM2-16GB):

```
grep GetGPGPUPwr /tmp/idraclogs
...
Nov 16 14:26:18 idrac-FFDCWL2 L4, S55 [1075]: GetGPGPUPwr: Looking for VID=0x10de DID=0x1db5 SVID=0x10de SDID=0x1249
Nov 16 14:26:18 idrac-FFDCWL2 L4, S55 [1075]: GetGPGPUPwr: End of table reached (Entry 92). Didn't find a power table match for device
...
```

Checking the power table entries for GPGPUs (executing `readcfg -g20033` in iDRAC shell; 20033 is the GPGPU power table group), it becames evident that there are no entries match the combination of PCI IDs for V100-SXM2-32GB; that's how iDRAC recognizes it as "not supported by Dell". It is possible to undo this by modifying a power table entry. For instance, to replace entry # 90 in GPGPU power table with V100-SXM2-32GB values of DID=0x1db5 and SDID=0x1249 the following should be executed in iDRAC shell:

```
writecfg -r'@@20033:90:1' -v'05 05 DE 10 B5 1D DE 10 49 12 B8 0B B8 0B 01 FF 48'
```

<!-- # this changes line #92 aka 90`--->

The new values are now in the `GPGPU_92_1` entry:

```
readcfg -g20033
...

GPGPU_91_1=5 5 de 10 b3 1d de 10 15 12 b8 b b8 b 1 ff 48
GPGPU_92_1=5 5 de 10 b5 1d de 10 49 12 b8 b b8 b 1 ff 48
GPGPU_93_1=5 5 2 10 c2 67 28 10 34 3 b8 b b8 b 1 ff 50
```

At this stage, after turning the system on (without rebooting the iDRAC), the iDRAC recognizes the new GPU:

```
grep GetGPGPUPwr /tmp/idraclogs
...
Nov 16 14:10:18 idrac-FFDCWL2 L4, S55 [1084]: GetGPGPUPwr: Looking for VID=0x10de DID=0x1db5 SVID=0x10de SDID=0x1249
Nov 16 14:10:18 idrac-FFDCWL2 L4, S55 [1084]: GetGPGPUPwr: Found Table Entry (88)
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: GPGPU Adapter Power Values
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: Width        = 5
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: VID          = 10de
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: DID          = 1db5
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: SVID         = 10de
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: SDID         = 1249
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: PeakPwr      = bb8
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: ThrottledPwr = bb8
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: gpuHotSup    = 1
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: gpuDCT       = 255
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
```

Bingo! The HW Power Brake slowdown is no longer there.

Since the thermal tables were left unchanged (power and thermal tables are two different entities), server's fans will run on full speed. By executing `AppThermalSHM -U` on iDRAC, this behaviour could be suppressed (to control the fans speed manually via `racadm`).

The power tables will get reinitialized to the default values (`/flash/pd0/ipmi/Trailbreaker/platcfgfld.txt`) on the next iDRAC reboot. To avoid throttling `writecfg` should be executed prior to system powerup. The permanent solution would be to unsqueeze the part of iDRAC image that is mounted to `/dev/mmcblk0p9` on `/flash/pd0`, edit `platcfgfld.txt` and `thermalconfig.txt` for Trailbreaker platform, squeeze it back and flash to `/dev/mmcblk0p9` partition on iDRAC.

(To allow OEM customizations for power tables, there's a `/etc/sysapps_script/pm_power_update.sh` script that reads a configuration file `/flash/data0/persmod/poweroem.conf` that is located on a writable flash filesystem and alters power tables via a series of `IPMICmd` commands. However populating this file with relevant data didn't worked for me; `IPMICmd` returned an error status. I should research this more I suppose.)

*Here, l4rz's gets within touching distance of a permanent solution; while we can alter the squashfs present on `/dev/mmcblk0p9`, we need to be careful as failing to compute and store a CRC for our modded partition will result in the iDRAC rolling itself back to its previous available firmware version, and additionally, this partition is part of the iDRAC firmware image and gets overwritten on iDRAC updates.*

*Since we'd like to be able to update our iDRAC controller to the latest available version after applying the mod, in order to not remain on a version vulnerable to known RCEs indefinitely, we keep digging, and observe that early in the boot process, the init script `/etc/init.d/setup-flash.sh` is called, which contains a few interesting blocks for us:*

```
setup_thermal_config()                                                                                 
{                                                  
    persmodpath=/flash/data0/persmod/ThermalConfig.txt
    dracpath=/etc/default/ipmi/default/ThermalConfig.txt
    [ ! -e /flash/pd0/ipmi/${systemname}/ThermalConfig.txt ] || dracpath=/flash/pd0/ipmi/${systemname}/ThermalConfig.txt
    if [ -e $persmodpath ] ; then                                           
        PersmodVer=$(grep TEMPLATE_REVISION_NUM $persmodpath | sed 's/.*\([X,x]\)\([0-9][0-9]\).*/\2/') 
        DRACThermalFileVer=`grep TEMPLATE_REVISION_NUM $dracpath | sed 's/.*\([X,x]\)\([0-9][0-9]\).*/\2/' `
        if [ $PersmodVer -le $DRACThermalFileVer ] ; then                     
            echo "Thermal Config from Identity Module Installed"                                       
            conditional_link $persmodpath /flash/data0/BMC_Data/ThermalConfig.txt               
        else                                                                                           
            echo "Thermal Config from Identity Module with version" $PersmodVer "is greater than the iDRAC supported version" $DRACThermalFileVer
            echo "Thermal Config from Identity Module could not be installed"
            conditional_link $dracpath /flash/data0/BMC_Data/ThermalConfig.txt                         
        fi                                     
    else                                                         
        conditional_link $dracpath /flash/data0/BMC_Data/ThermalConfig.txt
    fi                                                        
} 
```

*and*

```
cfgdir=/flash/data0/config                                                                                                  
for file in lmcfg.txt platcfggrp.txt platcfgfld.txt cfgfld.txt  \             
    cfggrp.txt gencfggrp.txt \                                                                                              
    gencfgfld.txt \                                                           
    nonpmaltdefaults.txt    \                                                                                               
    altdefaults.txt                                                                                                         
do                                                                            
    if [ -e  /flash/data0/persmod/$file ]; then                                                                             
        conditional_link /flash/data0/persmod/$file $cfgdir/$file                                                           
    elif [ -e /flash/pd0/config/$file ]; then                                 
        conditional_link /flash/pd0/config/$file $cfgdir/$file              
    elif [ -e /flash/pd0/ipmi/$systemname/$file ]; then                       
        conditional_link /flash/pd0/ipmi/$systemname/$file $cfgdir/$file
    elif [ -e /etc/default/config/$file ]; then                               
        conditional_link /etc/default/config/$file  $cfgdir/$file             
    elif [ -e /etc/default/ipmi/default/$file ]; then                                   
        conditional_link /etc/default/ipmi/default/$file $cfgdir/$file        
    else                                                                      
        echo "PANIC: Could not find a copy of $file to use."          
    fi                                                                  
done 
```

*These scripts, certainly intending on providing OEMs with the flexibility to add their own devices to the thermal and platform configurations for the system, give us the tools we need to get rid of GPU throttling for 32GB V100 GPUs.*

*Since it's 2025, and we can be an OEM if we want, we can design a [ThermalConfig.txt](/persmod/ThermalConfig.txt) and [platcfgfld.txt](/persmod/platcfgfld.txt) file to add our GPU, without overwriting any existing configurations or supported cards:*

```
[...]
[3_GPU_TIER3]
    VENDOR_ID=4318,4318,4318,4318,4318,4318,4098;
    SUB_VENDOR_ID=4318,4318,4318,4318,4318,4318,4136;
    DEVICE_ID=7601,7610,7603,7600,7604,7605,26562;
    SUB_DEVICE_ID=4626,4634,4629,4627,4628,4681,820;
    TARGET=72,72,72,72,72,72,80;
[...]
```

```
[...]
20033:CFG_BIN:89:1:GPGPU_91:'05 05 DE 10 B3 1D DE 10 15 12 B8 0B B8 0B 01 FF 48':17:CFG_READONLY::
20033:CFG_BIN:89:1:GPGPU_92:'05 05 DE 10 B5 1D DE 10 49 12 B8 0B B8 0B 01 FF 48':17:CFG_READONLY::
20033:CFG_BIN:90:1:GPGPU_93:'05 05 DE 10 BA 1D DE 10 1A 12 B8 0B B8 0B 01 FF 48':17:CFG_READONLY::
20033:CFG_BIN:91:1:GPGPU_94:'05 05 02 10 C2 67 28 10 34 03 B8 0B B8 0B 01 FF 50':17:CFG_READONLY::
20033:CFG_BIN:92:1:GPGPU_END:'FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF':17:CFG_READONLY::
[...]
```

*By simply saving these two text files to `/flash/data0/persmod/`, and rebooting the iDRAC, our GPU throttling fix is now live and persistent.*


## Steps

1) Make sure all cables are installed and the system configuration is as close as possible to "supported by Dell", i.e. there is no error `UEFI0147: The system hardware or cabling configuration is invalid` error during system boot. For C4130 Configuration K it involves installing all GPU power cables and the downlink PCIe cable from SXM2 board to PCIe riser. Boot the system up, observe the throttled state and note the PCI device IDs of the GPUs:

```
nvidia-smi -q
...
GPU 00000000:1E:00.0
    Product Name                    : Tesla V100-SXM2-32GB
...
    PCI
        Bus                         : 0x1E
        Device                      : 0x00
        Domain                      : 0x0000
        Device Id                   : 0x1DB510DE
        Bus Id                      : 00000000:1E:00.0
        Sub System Id               : 0x124910DE
```

2) Install BIOS 2.5.4 and iDRAC 2.50.50. If there's an `UEFI0315: Unable to process an iDRAC request to configure Secure Boot keys because of a communication error between BIOS` error after downgrade, [you need to reset the keys via redfish](https://www.dell.com/support/kbdoc/en-us/000177187/idrac8-uefi0315-error-at-post-after-downgrading-idrac8-firmware).

```
curl -k -v -u root --request POST https://192.168.0.120/redfish/v1/Systems/System.Embedded.1/SecureBoot/Actions/SecureBoot.ResetKeys -d '{"ResetKeysType":"ResetAllKeysToDefault"}'  --header "Content-Type: application/json"
```

3) *Use [the exploit](exploits/CVE-2018-1207.py) to get a proper shell on the iDRAC running version 2.50. Prior to running the script, make sure that the SH4 cross compiler is installed and working (`apt install gcc-sh4-linux-gnu`) and start e.g., a netcat listener. We have updated the original exploit to support Python 3 and recent GCC package names.*

4) The embedded payload's shell has been improved a bit from the original exploit, but if we want reliable access the next step is to alter `/etc/passwd` and `/etc/shadow` to access the root shell directly via ssh:

```
cd /tmp
# change idracuser shell to /bin/sh
sed 's/\/usr\/bin\/clpd/\/bin\/sh/g' < /etc/passwd > 111
cat 111 > /etc/passwd
# set the su password to user1234
sed 's/\$1\$fY6DG6Hu\$OpwCBE01ILIS1H\/Lxq\/7d0/\$1\$nVOr80rB\$HDAd6FRlG24k\/WN4ZuYPC0/g' < /etc/shadow > 112
cat 112 > /etc/shadow
```

Test it by sshing to `root@192.168.0.120`, using default password `calvin`, executing `su`, entering `user1234`.

5) *Copy the provided [ThermalConfig.txt](/persmod/ThermalConfig.txt) and [platcfgfld.txt](/persmod/platcfgfld.txt) files to the `/flash/data0/persmod/` directory, then reboot the iDRAC by issuing e.g., `racadm racreset`. If the `persmod` directory does not exist, simply create it with `mkdir /flash/data0/persmod/`.*

*Once the iDRAC has rebooted, you can verify that the fix has been applied by looking at the early logs from the iDRAC, or simply that the correct symlinks have been automatically created on startup:*

```
ls -al /flash/data0/config/platcfgfld.txt /flash/data0/BMC_Data/ThermalConfig.txt 
lrwxrwxrwx    1 root     root            38 Dec 31  1999 /flash/data0/BMC_Data/ThermalConfig.txt -> /flash/data0/persmod/ThermalConfig.txt
lrwxrwxrwx    1 root     root            35 Dec 31  1999 /flash/data0/config/platcfgfld.txt -> /flash/data0/persmod/platcfgfld.txt
```

```
cat /tmp/setup-flash.log | grep -i "identity module"
+ echo Thermal Config from Identity Module Installed
Thermal Config from Identity Module Installed
```

6) Now boot the system up. Prior to boot turn iDRAC debugs on:

```
debugcontrol -l 10
debugcontrol -s 1024
debugcontrol -i start
debugcontrol -g start
```

Monitor the /tmp/idraclogs` log file for `GetGPGPUPwr` related messages. This is good:
```
    Nov 16 14:10:18 idrac-FFDCWL2 L4, S55 [1084]: GetGPGPUPwr: Looking for VID=0x10de DID=0x1db5 SVID=0x10de SDID=0x1249
    Nov 16 14:10:18 idrac-FFDCWL2 L4, S55 [1084]: GetGPGPUPwr: Found Table Entry (88)
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: GPGPU Adapter Power Values
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: Width        = 5
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: VID          = 10de
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: DID          = 1db5
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: SVID         = 10de
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: SDID         = 1249
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: PeakPwr      = bb8
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: ThrottledPwr = bb8
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: gpuHotSup    = 1
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: gpuDCT       = 255
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
    Nov 16 14:10:18 idrac-FFDCWL2 L5, S55 [1084]: GetGPGPUPwr: **************************
```

This is bad:

```
    Nov 16 14:26:18 idrac-FFDCWL2 L4, S55 [1075]: GetGPGPUPwr: Looking for VID=0x10de DID=0x1db5 SVID=0x10de SDID=0x1249
    Nov 16 14:26:18 idrac-FFDCWL2 L4, S55 [1075]: GetGPGPUPwr: End of table reached (Entry 92). Didn't find a power table match for device
```

7) Install Ubuntu 20.04 (`ubuntu-20.04.3-live-server-amd64.iso`), install `build-essential`, manually blacklist nouveau driver:

```
vi /etc/modprobe.d/blacklist-nouveau.conf

blacklist nouveau
options nouveau modeset=0

sudo update-initramfs -u
reboot
```

8) Download and install the Nvidia data center driver 470.82.01 (download and install `nvidia-driver-local-repo-ubuntu2004-470.82.01_1.0-1_amd64.deb`; add the key, then do `sudo apt-get install cuda-drivers`)

9) Reboot the system and enjoy the lack of HW Power Brake Slowdown in `nvidia-smi -q` output.

10) *Success.*


[^1]: I'm not aware of the exact mechanism how iDRAC signals throttling to a GPU. The 12v rail readings are normal in that state. Most likely, iDRAC sets or resets some specific bit in the CPLD memory. [The CPLD (implemented on Altera FPGA) seems to function as a large GPIO device](https://www.sstic.org/media/SSTIC2019/SSTIC-actes/iDRACKAR/SSTIC2019-Article-iDRACKAR-iooss.pdf). It may in turn assert a signal on interface between main board and SXM2 FRU. Alternativey, it's possible that iDRAC signals something to the PLX PCIe switch, or other logic on the FRU board and it results in GPU power brake state. It is unlikely that iDRAC communicates directly with GPUs via interface such as SMBPBI (SMBus Post Box Interface). It is also not clear how exactly the power brake state gets asserted. It seems that specific PCIe pin (PWR_BRAKE_N) is responsible for this action. Likely the end point for this signal is some PIN on a MEG-Array SXM2 mezzanine connector. The SXM2 pinout wasn't disclosed by NVIDIA and I was unable to find it. The only relevant document I was able to find is [Advanced Accelerator Adapter Electro-Mechanical Specification by Open POWER foundation](http://cdn.openpowerfoundation.org/wp-content/uploads/resources/25Gbps-spec-1.0/25Gbps-spec-20171108.pdf). I'm not sure whether NVLINK 2.0 and OpenCAPI 3.0 are somehow pin compatible, at least for power and PCIe lines. If that so, the PWR_BRAKE_N is the pin E18 on the right SXM2 Meg-Array. Maybe plastering some Kapton paper over this pin could help to avoid throttling. Maybe the Nvidia BIOS checks the state of the pin and would throttle the GPU anyway if the pin is in <i>mu</i> state. Would be nice if someone could find out.

## Written by

l4rz & *re-l*
