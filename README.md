# wifidump

a demo tool for dump wifi device , and record the mac to sqlite db. 




**应用场景及主要用处：**

用作监听模式，监听周围wifi信号，并将mac记录到数据库。可以用作“探针”使用

**要求：**

1. 基于openwrt SDK 编译环境编译，本工具作为一个package可在SDK中独立编译
2. 要求wifi驱动支持monitor模式，并兼容iw命令将wifi模式配置为monitor；或者通过驱动自己私有接口命令更改wifi接口到monitor模式


**使用：**

1. 使用iw命令添加一个monitor模式的网络接口

`iw phy phy0 interface add moni0 type monitor`

2. 执行该demo程序

`wifidump moni0 /tmp/sqlfile`
