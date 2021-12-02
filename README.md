# Reverse engineering Dell iDRAC to get rid of GPU throttling

## TL;DR
Unsupported GPUs in Dell C4130 get throttled, here's how to prevent this from happening.

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
of BMC, Blackhat 2018](https://i.blackhat.com/us-18/Wed-August-8/us-18-Waisman-Soler-The-Unbearable-Lightness-of-BMC.pdf)). Some Russian guy [put together a Python script](https://github.com/KraudSecurity/Exploits/blob/master/CVE-2018-1207/CVE-2018-1207.py) to exploit CVE-2018-1207; this exploit requires gcc cross compiler for SH4 architecture (iDRAC8 is based on  Renesas SH7758), [here's payload.so built for remote IP 192.168.0.100](http://l4rz.net/payload.so). It works only with iDRAC verions lower than < 2.52.52.52, but it's not really an issue since iDRAC8 can be easily downgraded.

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

2) Use the exploit https://github.com/KraudSecurity/Exploits/tree/master/CVE-2018-1207 to get the root iDRAC shell. Prior to running the script, make sure that the SH4 cross compiler is installed and working, or use [my payload.so built for remote IP 192.168.0.100](http://l4rz.net/payload.so). Launch the netcat and then the script.

3) The netcat shell is garbage, some commands like writecfg do not work at all for some reason, so the next step is to alter `/etc/passwd` and `/etc/shadow` to access root sheel via ssh:

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

4) With the system energized but turned off, do:

```
ssh root@192.168.0.120
su
readcfg -g20033
# we can observe the following lines in power config
GPGPU_91_1=5 5 de 10 b3 1d de 10 15 12 b8 b b8 b 1 ff 48
GPGPU_92_1=5 5 de 10 ba 1d de 10 1a 12 b8 b b8 b 1 ff 48
GPGPU_93_1=5 5 2 10 c2 67 28 10 34 3 b8 b b8 b 1 ff 50
# we want to change one of approved gid/vid to the one of v100-sxm2-32gb VID=0x10de DID=0x1db5 SVID=0x10de SDID=0x1249
writecfg -r'@@20033:90:1' -v'05 05 DE 10 B5 1D DE 10 49 12 B8 0B B8 0B 01 FF 48' # this changes line #92 aka 90
# to verify
readcfg -g20033
GPGPU_91_1=5 5 de 10 b3 1d de 10 15 12 b8 b b8 b 1 ff 48
GPGPU_92_1=5 5 de 10 b5 1d de 10 49 12 b8 b b8 b 1 ff 48 # b5!!!!!
GPGPU_93_1=5 5 2 10 c2 67 28 10 34 3 b8 b b8 b 1 ff 50
```

5) Now boot the system up. Prior to boot turn iDRAC debugs on:

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

6) Install Ubuntu 20.04 (`ubuntu-20.04.3-live-server-amd64.iso`), install `build-essential`, manually blacklist nouveau driver:

```
vi /etc/modprobe.d/blacklist-nouveau.conf

blacklist nouveau
options nouveau modeset=0

sudo update-initramfs -u
reboot
```

7) Download and install the Nvidia data center driver 470.82.01 (download and install `nvidia-driver-local-repo-ubuntu2004-470.82.01_1.0-1_amd64.deb`; add the key, then do `sudo apt-get install cuda-drivers`)

8) Reboot the system and enjoy the lack of HW Power Brake Slowdown in `nvidia-smi -q` output.

9) After iDRAC reload: you need to ssh as root and do writecfg to patch the thermal table, then reboot again.

<!--
echo "PCI_Index_1=92" >> poweroem.conf
echo "PCI_VendorID_1=0x10 0xDE" >> poweroem.conf
echo "PCI_DeviceID_1=0x1D 0xB5" >> poweroem.conf
echo "PCI_SubVendorID_1=0x10 0xDE" >> poweroem.conf
echo "PCI_SubDeviceID_1=0x12 0x49" >> poweroem.conf
echo "PCI_PeakPower_1=0x01 0x2C" >> poweroem.conf
echo "PCI_Throttled_Power_1=0x01 0x2C" >> poweroem.conf
echo "PCI_Type_1=0x00" >> poweroem.conf
-->

#### Notes:

[^1]: I'm not aware of the exact mechanism how iDRAC signals throttling to a GPU. The 12v rail readings are normal in that state. Most likely, iDRAC sets or resets some specific bit in the CPLD memory. [The CPLD (implemented on Altera FPGA) seems to function as a large GPIO device](https://www.sstic.org/media/SSTIC2019/SSTIC-actes/iDRACKAR/SSTIC2019-Article-iDRACKAR-iooss.pdf). It may in turn assert a signal on interface between main board and SXM2 FRU. Alternativey, it's possible that iDRAC signals something to the PLX PCIe switch, or other logic on the FRU board and it results in GPU power brake state. It is unlikely that iDRAC communicates directly with GPUs via interface such as SMBPBI (SMBus Post Box Interface).

It is also not clear how exactly the power brake state gets asserted. It seems that specific PCIe pin (PWR_BRAKE_N) is responsible for this action. Likely the end point for this signal is some PIN on a MEG-Array SXM2 mezzanine connector. The SXM2 pinout wasn't disclosed by NVIDIA and I was unable to find it. The only relevant document I was able to find is [Advanced Accelerator Adapter Electro-Mechanical Specification by Open POWER foundation](http://cdn.openpowerfoundation.org/wp-content/uploads/resources/25Gbps-spec-1.0/25Gbps-spec-20171108.pdf). I'm not sure whether NVLINK 2.0 and OpenCAPI 3.0 are somehow pin compatible, at least for power and PCIe lines. If that so, the PWR_BRAKE_N is the pin E18 on the right SXM2 Meg-Array. Maybe plastering some Kapton paper over this pin could help to avoid throttling. Maybe the Nvidia BIOS checks the state of the pin and would throttle the GPU anyway if the pin is in <i>mu</i> state. Would be nice if someone could find out.

## Written by

l4rz
