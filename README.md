# lwip_contrib_unix_pcapif_livecapture

lwip contrib 中提供了对 UNIX/Linux 的支持，可以方便地将 lwip 移植到 UNIX/Linux，并做为一个进程运行。

其中，`contrib/ports/unix/netif` 中提供了对多种接口类型的支持，包括 tap/tun 等接口。但对于 macOS Big Sur，无法方便地创建 tap/tun 接口，所以需要使用基于 libpcap 的 pcapif 接口。

目前，`contrib/ports/unix/netif/pcapif.c` 仅支持打开已保存的抓包文件。本 repo 将其修改为使用实时捕获（live capture）模式。从而可以做到实时接收物理网卡上的报文，并将报文发送到物理网卡。


目前仅实现了基本的报文收发功能；报文统计、SNMP 等功能暂未实现完整。如有需要，可参考 `contrib/ports/win32/pcapif.c` 中的代码进行完善。


在 macOS Big Sur (11.2.3)，lwip 1.4.1, contrib 1.4.1 下测试通过。