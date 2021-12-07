# parseDexByPython
 使用python对dex文件进行解析  
### 10-18  
 了解整体知识  
 完成loadfile文件加载，确定文件读取方式  
 dex_header结构体解析一半  
### 10-19  
 dex_header结构体解析完成并输出  
 确定内存数据读取转换成hex数据的形式  
### 11-04
 索引区string解析完成。
 string数据的mutf-8的格式转化为utf-8格式，进行中。
### 11-17
 使用struct解析从内存中获取的字节数据，感觉之前写的格式转换都可以采用这种方式进行。
### 11-29
 已经完成：strings解析，types解析
 正在进行：protos解析
 尚未开始：field解析，method解析，class_def解析，map_list解析
 其中fiedl解析，method解析应该较快完成
 class_def解析，map_list解析 初步判断难度稍大。
### 11-30
 已经完成：strings解析，types解析,protos解析,field解析
 正在进行：
 尚未开始：method解析，class_def解析，map_list解析
### 12-07
 已经完成：strings解析，types解析,protos解析,field解析,method解析，
 正在进行：class_def解析,基本解析完成，正在debug。
 尚未开始：map_list解析
 当前问题，python的 for循环似乎有问题，多个结构嵌套循环时 跑飞了。暂时不知道怎么解决，少量循环正常。
