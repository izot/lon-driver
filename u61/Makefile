EXTRA_CFLAGS += -I$(src)/include -DU61_KERNEL -DU50_KERNEL -g
obj-m += u61.o
u61-objs :=  U61Module.o U61Link.o packet_util.o U61Osal.o ipv6_ls_to_udp.o ip_util.o U61Log.o

clean:
	sudo rm -rf .??*.cmd .tmp_versions *.ko *.o Module.symvers modules.order
