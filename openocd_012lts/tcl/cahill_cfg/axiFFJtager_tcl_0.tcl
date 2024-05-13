#cahill create axiFFJtager ip Jtag0 = 0x43c40000
bindto 0.0.0.0
tcl_port 6660
telnet_port 4440
gdb_port 3330
adapter driver axi_FFJtager
axi_ffjtag_devaddr 0x43c40000
#transport select jtag
transport select swd
adapter speed 100
