KERNELDIR=/lib/modules/`uname -r`/build
#ARCH=i386
#KERNELDIR=/usr/src/kernels/`uname -r`-i686

MODULES = firewallExtension.ko 
 
obj-m += firewallExtension.o 
firewallExtension-y := klist.o firewall.o

firewallExtension.ko: firewall.c klist.h
	make -C  $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:	
	make -C $(KERNELDIR) M=$(PWD) modules_install

quickInstall:
	cp $(MODULES) /lib/modules/`uname -r`/extra

