#!/usr/bin/env python3.8

'''
项目内容：解析dex文件格式
项目作者：zxz
开始日期：2021-10-18

'''

import mmap
import struct
import sys


#定义dex_magic的类
class struct_dex_magic:
    dex =[3]
    newline =[1]
    ver =[3]
    zero =[1]

class struct_dex_header:
    magic =struct_dex_magic()    #dex魔数
    checksum =[4]     #校验值
    signature =[20]  #签名信息
    file_size =[4]
    header_size =[4]
    endian_tag =[4]
    link_size =[4]
    link_off =[4]
    map_off =[4]
    string_ids_size =[4]
    string_ids_off =[4]
    type_ids_siez =[4]
    type_ids_off =[4]
    proto_ids_size =[4]
    proto_ids_off =[4]
    field_ids_size =[4]
    field_ids_off =[4]
    method_ids_size =[4]
    method_ids_off =[4]
    class_defs_size =[4]
    class_defs_off =[4]
    date_size =[4]
    date_off =[4]



#加载dex文件
def loadFile():
    try:
        dexFilePath =sys.argv[1]  #通过ssy来获取命令行参数，获取加载目标文件
    except IndexError:
        print("错误：请输入需要解析的dex文件路径")
        exit()
    with open(dexFilePath,'rb') as f:    
        global dexFileMmap  #全局变脸，用于映射dex文件
        dexFileMmap =mmap.mmap(f.fileno(),0,access=mmap.ACCESS_READ) #利用mmap模块将dex文件映射到内存中
    
    dexFileMmap.seek(0)
    dexMagic =dexFileMmap.read(8)
    if(dexMagic.hex() !="6465780a30333500"):   #判断文件格式是否为dex,"64 65 78 0A 30 33 35 00"
        print("请输入正确的dex文件")
        exit()

#读取dexheader数据
def parseDexHeader():
    dexFileMmap.seek(0)
    dexheader =dexFileMmap.read(0x70)  #dexheader长度固定，0x70,112个字节

    dex_header =struct_dex_header()
    dex_magic =struct_dex_magic()

    dex_magic.dex =dexheader[0:3]
    dex_magic.newline =dexheader[3:4]
    dex_magic.ver =dexheader[4:7]
    dex_magic.zero =dexheader[7:8]

    dex_header.magic =dex_magic
    dex_header.checksum =dexheader[8:0xc]
    dex_header.signature =dexheader[0xc:0x20]
    dex_header.file_size =dexheader[0x20:0x24]
    








        








if __name__ == "__main__":
    loadFile()
    parseDexHeader()