编译openocd源代码

### 0 Download openocd src

# git clone --recurse-submodules  git://git.code.sf.net/p/openocd/code openocd

git://git.code.sf.net/p/openocd/code 据说这个是官方最新版本的地址，

cd chroot_armbain
10752* ls
10753* cd cahill_build_armbian
10754* ls
10755* cd ..
10756* ls
10757* cd chroot_armbain
10758* ls
10759* ls root_armbian
10760* sudo chroot ./root_armbian

登录root_armbian环境，在这个环境下，有可以用的开发环境比如libtools之类的库

再在这个环境下，挂载/home/cahill/nfsroot 

mount -t nfs 192.168.0.169:/home/cahill/nfsroot /mnt

cd /mnt/openocd_src20240402/openocd_012lts/



#### 1 编译

root@cahill-DELL-precision:/mnt/openocd_src20240402/openocd_012lts# ./bootstrap

之后生成configure

###### 1.1 加入axiFFJtag驱动配置选项

根据/home/cahill/nfsroot/openocd012-code-withaxi-axiJtag-xvc-2024_compress/openocd012-code-withaxi-axiJtag-xvc里面的configure.ac修改openocd_012lts里面的configure.ac文件，加热管相关的配置，

此时生成的configure，运行configure --help之后，就会看到（axiFFJtag）选项，如下：

  --enable-internal-libjaylink
                          Enable building internal libjaylink
  --enable-axiFFJtag      Enable building support for axiFFJtag by cahill.
  --enable-remote-bitbang Enable building support for the Remote Bitbang
                          driver

#### 在生成Makefile时，需要运行configure  --enable-axiFFJtag

MPSSE mode of FTDI based devices        yes (auto)
ST-Link Programmer                      yes (auto)
TI ICDI JTAG Programmer                 yes (auto)
Keil ULINK JTAG Programmer              yes (auto)
ANGIE Adapter                           yes (auto)
Altera USB-Blaster II Compatible        yes (auto)
Bitbang mode of FT232R based devices    yes (auto)
Versaloon-Link JTAG Programmer          yes (auto)
TI XDS110 Debug Probe                   yes (auto)
CMSIS-DAP v2 Compliant Debugger         yes (auto)
OSBDM (JTAG only) Programmer            yes (auto)
eStick/opendous JTAG Programmer         yes (auto)
Olimex ARM-JTAG-EW Programmer           yes (auto)
Raisonance RLink JTAG Programmer        yes (auto)
USBProg JTAG Programmer                 yes (auto)
Espressif JTAG Programmer               yes (auto)
CMSIS-DAP Compliant Debugger            no
Nu-Link Programmer                      no
Cypress KitProg Programmer              no
Altera USB-Blaster Compatible           yes (auto)
ASIX Presto Adapter                     yes (auto)
OpenJTAG Adapter                        yes (auto)
Linux GPIO bitbang through libgpiod     no

#### Xilinx axiFFJtag                        yes

SEGGER J-Link Programmer                no
Bus Pirate                              yes (auto)
Use Capstone disassembly framework      no

###### 1.2 修改src/jtag/drivers/Makefile.am

在这个文件中加入条件编译选项

if AXIFFJTAG
DRIVERFILES += %D%/axiFFJtag.c
endif

###### 1.3 修改src/jtag/interfaces.h

加入

extern struct adapter_driver xlnx_axi_FFJtag_adapter_driver;

这个与以前的文件不一样，

###### 1.4 在src/jtag/interfaces.c加入

\\#if BUILD_AXIFFJTAG == 1

​    &xlnx_axi_FFJtag_adapter_driver,

\#endif

此时编译出现如下错误：

src/jtag/interfaces.lo -MD -MP -MF src/jtag/.deps/interfaces.Tpo -c src/jtag/interfaces.c -o src/jtag/interfaces.o
src/jtag/interfaces.c:130:6: error: 'adapter_driver' undeclared here (not in a function)
     &adapter_driver xlnx_axi_FFJtag_adapter_driver;
      ^
src/jtag/interfaces.c:130:21: error: expected '}' before 'xlnx_axi_FFJtag_adapter_driver'
     &adapter_driver xlnx_axi_FFJtag_adapter_driver;

###### 1.5 在src/jtag/drivers/目录加入axiFFJtage.c文件

这个文件需要少许修改，如下

static int axi_ffjtag_execute_queue(struct jtag_command *cmd_queue) {

  struct jtag_command *cmd = cmd_queue;

  int ret;

  while (cmd) {

​    ret = axi_ffjtag_execute_command(cmd);

​    if (ret != ERROR_OK) return ret;

​    cmd = cmd->next;

  }

  return ERROR_OK;

}

###### 1.6 最终去掉其他的adapter

./configure --disable-ftdi   --disable-stlink  --disable-ti-icdi  --disable-ulink --disable-angie  --disable-usb-blaster-2 --disable-ft232r  --disable-vsllink --disable-xds110 --disable-cmsis-dap-v2  --disable-osbdm --disable-opendous --disable-armjtagew  --disable-rlink  --disable-usbprog  --disable-esp-usb-jtag --disable-cmsis-dap --disable-nulink --disable-kitprog   --disable-usb-blaster   --disable-presto --disable-openjtag  --disable-buspirate --disable-jlink --disable-parport --disable-parport-ppdev --disable-parport-giveio --disable-jtag_vpi  --disable-vdebug  --disable-jtag_dpi  --disable-amtjtagaccel --disable-bcm2835gpio --disable-imx_gpio  --disable-am335xgpio  --disable-ep93xx  --disable-at91rm9200  --disable-gw16012   --disable-sysfsgpio  --disable-xlnx-pcie-xvc  --enable-axiFFJtag

再次编译 make .........

完事  。。。。