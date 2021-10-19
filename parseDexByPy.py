#!/usr/bin/env python3.8

'''
项目内容：解析dex文件格式
项目作者：zxz
开始日期：2021-10-18

'''

from io import RawIOBase
import mmap
from os import pipe
import struct
import sys
import binascii
import socket

'''

文件头--------dex_haader     文件头

     --------string_ids     字符串的索引
     --------type_ids       类型的索引
索引区--------prote_ids      方法原型的索引
     --------field_ids      域的索引
     --------method_ds      方法的索引

     --------class_defs     类的定义区
数据区--------data           数据区
     --------link_data      链接数据区






'''


#定义dex_magic的类。用于表示dex魔数
class struct_dex_magic:
    dex =[3]                    #dex标志位
    newline =[1]
    ver =[3]                    #dex版本信息
    zero =[1]
    def printInfo(self):
        print("magic            -->",str(self.dex +self.newline +self.ver +self.zero))


#定义dex_hander的类。用于表示dex头部信息，
class struct_dex_header:
    magic =struct_dex_magic()    #dex魔数，起始：0x00，长度 8
    checksum =[4]                #校验值，起始：0x8,长度 4。采用alder-32算法，将0xc到文件结尾所有的byte数据计算
    signature =[20]              #签名信息，起始：0xc,长度 0x14。采用sha1算计，将0x20到文件结尾所有的byte数据计算
    file_size =[4]               #dex文件大小，起始:0x20,长度 4
    header_size =[4]             #文件头大小，起始：0x24，长度 4
    endian_tag =[4]              #文件字节序，起始：0x28，长度 4。默认小尾字节序，默认数据是: 0x78 0x56 0x34 0x12
    link_size =[4]               #文件链接段大小，起始：0x2c,长度 4，如果数值为0表示静态链接
    link_off =[4]                #文件链接段偏移，起始：0x30，长度 4，
    map_off =[4]                 #map数据偏移，起始：0x34，长度4
    string_ids_size =[4]         #字符串的数量，起始：0x38，长度4，即string_id_item的数量
    string_ids_off =[4]          #字符串偏移，起始：0x3c,长度4，即string_id_item的起始位置
    type_ids_size =[4]           #类的数量，起始：0x40，长度4，即type_id_item的数量
    type_ids_off =[4]            #类的偏移，起始：0x44，长度4，即typy_id_item的起始位置
    proto_ids_size =[4]          #方法原型的数量，起始：0x48，长度4，即proto_id_item的数量
    proto_ids_off =[4]           #方法原型的偏移，起始：0x4c,长度4，即proto_id_item的起始位置
    field_ids_size =[4]          #字段的数量，起始：0x50，长度4，即field_id_item的数量
    field_ids_off =[4]           #字段的偏移，起始：0x54，长度4，即field_id_item的起始位置
    method_ids_size =[4]         #方法的数量，起始：0x58,长度4，即method_id_item的数量
    method_ids_off =[4]          #方法的偏移，起始：0x5c,长度4，即method_id_item的起始位置
    class_defs_size =[4]         #类定义的数量，起始：0x60,长度4，即class_def_item的数量
    class_defs_off =[4]          #类定义的偏移，起始：0x64,长度4，即class_def_item的起始位置
    data_size =[4]               #数据段 的大小，起始：0x68,长度4
    data_off =[4]                #数据段 的偏移，起始：0x6c,长度4

    #打印dex文件头
    def printInfo(self):
        print("---***---dex_header---***---")
        self.magic.printInfo()
        print("checksum         -->",self.checksum)
        print("signature        -->",self.signature)
        print("file_size        -->",self.file_size)
        print("header_size      -->",self.header_size)
        print("endian_tag       -->",self.endian_tag)
        print("link_size        -->",self.link_size)
        print("link_off         -->",self.link_off)
        print("map_off          -->",self.map_off)
        print("string_ids_size  -->",self.string_ids_size)
        print("string_ids_off   -->",self.string_ids_off)
        print("type_ids_size    -->",self.type_ids_size)
        print("type_ids_off     -->",self.type_ids_off)
        print("proto_ids_size   -->",self.proto_ids_size)
        print("proto_ids_off    -->",self.proto_ids_off)
        print("field_ids_size   -->",self.field_ids_size)
        print("field_ids_off    -->",self.field_ids_off)
        print("method_ids_size  -->",self.method_ids_size)
        print("method_ids_off   -->",self.method_ids_off)
        print("class_defs_sieze -->",self.class_defs_size)
        print("class_defs_off   -->",self.class_defs_off)
        print("data_size        -->",self.data_size)
        print("data_off         -->",self.data_off)





#全局变量
dex_header =struct_dex_header()     #dex结构体

#加载dex文件
def loadFile():
    try:
        dexFilePath =sys.argv[1]  #通过ssy来获取命令行参数，获取加载目标文件
    except IndexError:
        print("错误：请输入需要解析的dex文件路径")
        exit()
    
    global dexFileMmap
    dexFileMmap =open(dexFilePath,'rb')

    
    dexFileMmap.seek(0)
    dexMagic =dexFileMmap.read(8)
    if(dexMagic.hex() !="6465780a30333500"):   #判断文件格式是否为dex,"64 65 78 0A 30 33 35 00"
        print("请输入正确的dex文件")
        exit()

#读取dexheader数据
def parseDexHeader():
    dexFileMmap.seek(0)
    dexheader =dexFileMmap.read(0x70)  #dexheader长度固定，0x70,112个字节

    
    
    dex_magic =struct_dex_magic()

    #dex_header数据获取，同时将数据整型 大小端转换 转为可用格式
    dex_magic.dex =dexheader[0:3]
    dex_magic.newline =dexheader[3:4]
    dex_magic.ver =dexheader[4:7]
    dex_magic.zero =dexheader[7:8]

    dex_header.magic =dex_magic
    

    dex_header.checksum =dexheader[8:0xc]
    tmpValue= list(reversed(dex_header.checksum))
    dex_header.checksum =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.signature =dexheader[0xc:0x20]
    dex_header.signature =dex_header.signature.hex()

    dex_header.file_size =dexheader[0x20:0x24]
    tmpValue= list(reversed(dex_header.file_size))
    dex_header.file_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.header_size =dexheader[0x24:0x28]
    tmpValue= list(reversed(dex_header.header_size))
    dex_header.header_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.endian_tag =dexheader[0x28:0x2c]
    tmpValue= list(reversed(dex_header.endian_tag))
    dex_header.endian_tag =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.link_size =dexheader[0x2c:0x30]
    tmpValue= list(reversed(dex_header.link_size))
    dex_header.link_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.link_off =dexheader[0x30:0x34]
    tmpValue= list(reversed(dex_header.link_off))
    dex_header.link_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.map_off =dexheader[0x34:0x38]
    tmpValue= list(reversed(dex_header.map_off))
    dex_header.map_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.string_ids_size =dexheader[0x38:0x3c]
    tmpValue= list(reversed(dex_header.string_ids_size))
    dex_header.string_ids_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.string_ids_off =dexheader[0x3c:0x40]
    tmpValue= list(reversed(dex_header.string_ids_off))
    dex_header.string_ids_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.type_ids_size =dexheader[0x40:0x44]
    tmpValue= list(reversed(dex_header.type_ids_size))
    dex_header.type_ids_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.type_ids_off =dexheader[0x44:0x48]
    tmpValue= list(reversed(dex_header.type_ids_off))
    dex_header.type_ids_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.proto_ids_size =dexheader[0x48:0x4c]
    tmpValue= list(reversed(dex_header.proto_ids_size))
    dex_header.proto_ids_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.proto_ids_off =dexheader[0x4c:0x50]
    tmpValue= list(reversed(dex_header.proto_ids_off))
    dex_header.proto_ids_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.field_ids_size =dexheader[0x50:0x54]
    tmpValue= list(reversed(dex_header.field_ids_size))
    dex_header.field_ids_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.field_ids_off =dexheader[0x54:0x58]
    tmpValue= list(reversed(dex_header.field_ids_off))
    dex_header.field_ids_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.method_ids_size =dexheader[0x58:0x5c]
    tmpValue= list(reversed(dex_header.method_ids_size))
    dex_header.method_ids_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.method_ids_off =dexheader[0x5c:0x60]
    tmpValue= list(reversed(dex_header.method_ids_off))
    dex_header.method_ids_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.class_defs_size =dexheader[0x60:0x64]
    tmpValue= list(reversed(dex_header.class_defs_size))
    dex_header.class_defs_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.class_defs_off =dexheader[0x64:0x68]
    tmpValue= list(reversed(dex_header.class_defs_off))
    dex_header.class_defs_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.data_size =dexheader[0x68:0x6c]
    tmpValue= list(reversed(dex_header.data_size))
    dex_header.data_size =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    dex_header.data_off =dexheader[0x6c:0x70]
    tmpValue= list(reversed(dex_header.data_off))
    dex_header.data_off =append_hex(tmpValue[0],tmpValue[1],tmpValue[2],tmpValue[3])

    #调用打印函数，打印dex文件头数据
    dex_header.printInfo()

   

    




#将hex数据移位拼接，例如 0x11 +0x22 +0x33 +0x44 = 0x11223344
def append_hex(arg0, arg1, arg2, arg3):
    arg0 =arg0<<24
    arg1 =arg1<<16
    arg2 =arg2<<8
    result = arg0 +arg1 +arg2 +arg3
    return hex(result)
        








if __name__ == "__main__":
    loadFile()
    parseDexHeader()