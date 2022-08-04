EXTRA_CFLAGS += -I$(src)/include -DU50_KERNEL -g
obj-m += u50.o
u50-y += U50Link.o U50Osal.o U50Log.o U50Driver.o packet_util.o ipv6_ls_to_udp.o ip_util.o

clean:
	sudo rm -rf .??*.cmd .tmp_versions *.ko *.o Module.symvers modules.order
  
