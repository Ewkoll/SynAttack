# SynAttack

通过Go发送SYN包，只能在Linux环境发送。

# 通过C语言实现模拟大量客户端连接工具

混杂模式下接受数据包，手动构造完成TCP三次握手，服务端占用资源，并且连接只能等待服务器检测后再剔除连接，尤其对于某些服务器可以容忍客户端长期不发送数据，没有认证机制。服务器主动关闭大量无效连接也是会占用大量的资源。

需要添加防火墙规则，阻止系统自动发送RST包。