# lon-driver
The EnOcean LON driver enables developers to add support to Linux for the EnOcean U10, U20, U60, and U70 USB LON network interfaces. The LON protocol is an open standard defined by the ISO/IEC 14908 series of standards.

This repository includes the following directories:

o lonifd -- LON Interface Daemon: creates a Linux LON network interface when a compatible LON USB network interface is discovered.

o U50 -- Serial USB LON Driver: implements a LON driver for a LON USB network interface that incorporate a serial USB interface.  Compatible with the EnOcean U60 FT USB Network Interface.

o U60 -- Parallel USB LON Driver:  implements a LON driver for a LON USB network interface that incorporate a parallel USB interface.  Compatible with the EnOcean U10 FT, U20 PL, U60 TP-1250, and U70 PL USB Network Interfaces.
