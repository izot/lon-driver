include ../../../Apollo.cfg

KMODS = u61 u50
KDIR = ../../../$(SYSROOT)/usr/src/linux-headers-$(KVERSION)
ifeq ($(KARCH),armhf)
	USE_ARCH=arm
else
	USE_ARCH=$(KARCH)
endif

all: $(ARCH)

$(ARCH): $(KMODS:%=%.ko)

$(KMODS:%=%.ko):
	sudo ARCH=$(USE_ARCH) CROSS_COMPILE=$(CROSS_COMPILE) make -C $(KDIR) M=`pwd`/$(@:%.ko=%) modules

install:

clean:
	for i in $(KMODS) ; do (cd $$i && make $@) ; done
