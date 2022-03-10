# Tzdriver模块介绍<a name="ZH-CN_TOPIC_0000001078530726"></a>

-   [简介](#section469617221261)
-   [tzdriver工程框架](#section15884114210197)
-   [二级目录结构](#section1464106163817)

## 简介<a name="section469617221261"></a>

tzdriver（Trustzone driver）是REE的一部分，REE组件提供了一套用于和TEEOS交互的富运行环境（REE）接口组件，包括驱动（tzdriver）、libteec（应用接口库）、teecd（agent服务）。本组件tzdriver一般情况下为内核的一部分，也可以编译为ko模块。

## Tzdriver工程框架<a name="section15884114210197"></a>

tee_tzdriver：工程目录
-   README.md&README_zh.md：指导文件
-   LICENSE：许可证（GPL v2）
-   linux：为linux kernel提供的tzdriver
-   liteos：为liteos_a kernel提供的tzdriver

## 二级目录结构<a name="section1464106163817"></a>

**表 1**  tzdriver二级源代码主要目录结构

<a name="table2977131081412"></a>
<table><thead align="left"><tr id="row7977610131417"><th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.1"><p id="p18792459121314"><a name="p18792459121314"></a><a name="p18792459121314"></a>主要二级目录</p>
</th>
<th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.2"><p id="p77921459191317"><a name="p77921459191317"></a><a name="p77921459191317"></a>描述</p>
</th>
</tr>
</thead>
<tbody><tr id="row17977171010144"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1836912441194"><a name="p1836912441194"></a><a name="p1836912441194"></a>core</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p2549609105"><a name="p2549609105"></a><a name="p2549609105"></a>核心功能代码，smc，agent等都在这里面</p>
</td>
</tr>
<tr id="row6978161091412"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p64006181102"><a name="p64006181102"></a><a name="p64006181102"></a>tlogger</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p7456843192018"><a name="p7456843192018"></a><a name="p7456843192018"></a>日志组件相关代码</p>
</td>
</tr>
<tr id="row6978201031415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1978910485104"><a name="p1978910485104"></a><a name="p1978910485104"></a>auth</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p1059035912204"><a name="p1059035912204"></a><a name="p1059035912204"></a>鉴权相关代码</p>
</td>
</tr>
<tr id="row1897841071415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p182586363119"><a name="p182586363119"></a><a name="p182586363119"></a>include</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p19278126102113"><a name="p19278126102113"></a><a name="p19278126102113"></a>头文件导出</p>
</td>
</tr>
</tbody>
</table>

