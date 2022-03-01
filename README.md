# Tzdriver Module Introduction<a name="ZH-CN_TOPIC_0000001078530726"></a>

-   [Introduction](#section469617221261)
-   [tzdriver project Structure](#section15884114210197)
-   [secondary Directories structure](#section1464106163817)

## Introduction<a name="section469617221261"></a>

tzdriver is a part of REE. The REE module provides a set of rich execution environment \(REE\) API components for interacting with TEEOS, including tzdriver \(driver\), libteec \(API library\), and teecd \(agent service\). This module tzdriver normally is a part of kernel, sometimes could be ko(kernel module).

## Tzdriver project Structure<a name="section15884114210197"></a>

tee_tzdriver：project directory
-   README.md&README_zh.md：Introduction file
-   LICENSE：GPL v2 LICENSE
-   linux：tzdriver for linux kernel
-   liteos：tzdriver for liteos_a kernel

## Secondary Directories structure<a name="section1464106163817"></a>

**Table 1**  tzdriver main secondary source code structure

<a name="table2977131081412"></a>
<table><thead align="left"><tr id="row7977610131417"><th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.1"><p id="p18792459121314"><a name="p18792459121314"></a><a name="p18792459121314"></a>main secondary directory</p>
</th>
<th class="cellrowborder" valign="top" width="50%" id="mcps1.2.3.1.2"><p id="p77921459191317"><a name="p77921459191317"></a><a name="p77921459191317"></a>description</p>
</th>
</tr>
</thead>
<tbody><tr id="row17977171010144"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1836912441194"><a name="p1836912441194"></a><a name="p1836912441194"></a>core</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p2549609105"><a name="p2549609105"></a><a name="p2549609105"></a>core function code, include:smc, agent...</p>
</td>
</tr>
<tr id="row6978161091412"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p64006181102"><a name="p64006181102"></a><a name="p64006181102"></a>tlogger</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p7456843192018"><a name="p7456843192018"></a><a name="p7456843192018"></a>for tee log</p>
</td>
</tr>
<tr id="row6978201031415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p1978910485104"><a name="p1978910485104"></a><a name="p1978910485104"></a>auth</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p1059035912204"><a name="p1059035912204"></a><a name="p1059035912204"></a>for authentication</p>
</td>
</tr>
<tr id="row1897841071415"><td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.1 "><p id="p182586363119"><a name="p182586363119"></a><a name="p182586363119"></a>include</p>
</td>
<td class="cellrowborder" valign="top" width="50%" headers="mcps1.2.3.1.2 "><p id="p19278126102113"><a name="p19278126102113"></a><a name="p19278126102113"></a>export header files</p>
</td>
</tr>
</tbody>
</table>

