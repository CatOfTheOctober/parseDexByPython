#!/usr/bin/env python3.8
#-*- coding : utf-8-*-
# coding:unicode_escape

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
strings_list =[]                     #string全部字符串信息
types_list =[]                       #type全部字符串信息
protos_list =[]                      #proto全部字符串信息

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


#计算dex_header->checksum
def calcChecksum():
    '''
        checksum采用Adler-32算法，计算数据范围是 0xc到文件结尾。
        adler-32计算分为两个步骤：
        1、定义两个变量，varA、varB，其中varA初始化为1，varB初始化为0
        2、读取字节数组的一个字节（byteA），计算varA =(varA +varB) mod 65521
            然后计算出 varB =(varA +varB) mod 65521
        3、重复步骤2，直至字节数组全部读取完毕，得到最终 varA、varB两个变量的结果
        4、得到的varA、varB两个变量， checksum =(varB <<16) + varA

    '''    
    dexFileMmap.seek(0xc)
    srcBtye =dexFileMmap.read() #获取 0xc之后的全部数据
    varA =1
    varB =0
    icount =0
    listAB =[]

    while icount <len(srcBtye):
        varA =(varA +srcBtye[icount]) % 65521
        varB =(varB +varA) %65521
        icount +=1

    outPut =(varB <<16) +varA

    return outPut
   
'''
函数功能：解析文件字符串
函数参数：stringIdOffset
函数返回：打印string内容
'''
def parseStringIdList():
    '''
    解析字符串索引表
    1、字符串数量在dexHeader->string_ids_size 中定义，
    2、字符串偏移在dexHeader->string_ids_off 中定义，一般值为 0x70
    '''
    string_ids_size =dex_header.string_ids_size #string 数量
    string_ids_size =eval(string_ids_size)
    string_ids_off =dex_header.string_ids_off   #string 索引表初始偏移
    string_ids_off =eval(string_ids_off)

    print("---***---string_ids---***---")
    print("字符串数量：",string_ids_size)    

    for i in range(string_ids_size):  #遍历索引表
        string_index_off =string_ids_off +0x4 *i  #字符串索引表地址
        dexFileMmap.seek(string_index_off  ,0)
        string_item_off =dexFileMmap.read(4)    #字符串数据区地址
        string_item_off =eval(append_hex(string_item_off[3],string_item_off[2],string_item_off[1],string_item_off[0]))
        str_data =parseStringItemData(string_item_off)

        try:
            print("字符串序列:",i,str_data.decode())
            strings_list.append(str_data.decode())
        except UnicodeDecodeError:
            print("字符串序列:",i,str(str_data))    #如果不能使用utf-8编码，则直接打印bytes数据。
            strings_list.append(str_data)


'''
函数功能：解析数据区中的string数据，将mutf-8数据转化为utf-8数据
函数参数：字符串mutf-8数据的偏移值
函数返回：转化之后的 utf-8数据
'''
def parseStringItemData(stringItemOff):
    dexFileMmap.seek(stringItemOff)
    result =readUled128(stringItemOff)
    str_len =result[0]
    str_off =result[1]
    dexFileMmap.seek(str_off)
    str_data =dexFileMmap.read(str_len)
    return str_data


'''
函数功能：解析类型字符串 type_str
函数参数：typeIdOffset
函数返回：打印type内容
'''
def parseTypeIdList():
    '''
    解析类型索引表
    1、类型数量在 dex_header->type_ids_size 中定义
    2、类型偏移在 dex_header->type_ids_off 中定义
    3、type中的value信息是在string中的偏移；例：type_ids_off 中存放的数值为 0x7E，对应的数据则是 string[0x7E]中的字符串
    '''
    type_ids_size =dex_header.type_ids_size
    type_ids_size =eval(type_ids_size)
    type_ids_off =dex_header.type_ids_off
    type_ids_off =eval(type_ids_off)

    print("---***---type_ids---***---")
    print("类型数量：",type_ids_size)    

    for i in range(type_ids_size):
        dexFileMmap.seek(type_ids_off +0x4 *i, 0)
        type_ids =dexFileMmap.read(4)
        type_ids =eval(append_hex(type_ids[3], type_ids[2], type_ids[1], type_ids[0]))
        if(type_ids<= len(strings_list)):
            type_str =strings_list[type_ids]
            type_str =jniTypeFormat(type_str)
            types_list.append(type_str)
            print("类型序列：",i,type_str)
  

'''
函数功能：类型字符串转换。将JNI函数签名类型的字符转换成基本数据类型的字符；将“C” 转换成“char”
函数参数：JNI函数签名类型的字符
函数返回：基本数据类型的字符
'''
def jniTypeFormat(jniType):
    jniTypeDict ={
        "Z":"boolean",
        "B":"byte",
        "C":"char",
        "S":"short",
        "I":"int",
        "J":"long",
        "F":"float",
        "D":"double",
        "V":"void"
    }
    if(jniType.startswith("L") ==True):
        return jniType[1:len(jniType) -1]
    elif(jniType.startswith("[") ==True):
        tmp =jniType[1:len(jniType)]
        if(tmp.startswith("L") ==True):
            return tmp[1:len(tmp) -1] +"[]"
        else:
            if(jniTypeDict.get(tmp) !=None):
                return jniTypeDict[tmp] +"[]"
            else:
                return jniType
    else:
        if(jniTypeDict.get(jniType) !=None):
            return jniTypeDict[jniType]
        else:
            return jniType


'''
函数功能：解析方法原型 proto_str；即含有方法的参数和返回值，不含方法的名称
函数参数：protoIdOffet
函数返回：打印proto的内容
'''
def parseProtoIdList():
    '''
    解析proto数据
    1、方法原型数量在 dex_header.proto_ids_size 中定义
    2、方法原型索引偏移在 dex_header.proto_ids_size 中定义

    方法原型索引结构：每个方法原型占用12个字节
    method_id_item{
        uint shorty_idx             value:strings_list索引；返回值与参数的类型缩写；比如返回值类型为"L"，参数类型为"I"，则此数据为"LI"
        uint return_type_idx        value:types_list索引；方法返回值类型
        uint paramnters_type_off    value:文件偏移partameters_ptr；方法参数的地址
    }
    partameters_ptr{
        uint size                   value:方法参数的数量
        ushort type_item            value:types_list索引；方法参数类型
    }
    '''
    proto_ids_size =dex_header.proto_ids_size
    proto_ids_size =eval(proto_ids_size)
    proto_ids_off =dex_header.proto_ids_off
    proto_ids_off =eval(proto_ids_off)




#函数功能：解析uleb128的数据，获取string的长度。
#函数参数：uleb128数据起始位置
#函数返回：result[0],数据长度;result[1]，数据内容
#相关连接：https://www.52pojie.cn/thread-1220562-1-1.html
def readUled128(offset):
    result = [-1,-1]
    n = 0
    dexFileMmap.seek(offset)

    tmp =dexFileMmap.read(1)
    data =struct.unpack('!B' ,tmp) #利用struct将获取到的 byte数据转为 int类型。
    data =data[0]
    #data = int(dexFileMmap.read(1))
    if data > 0x7f:
        dexFileMmap.seek(offset +1)
        n = 1
        tmp = struct.unpack('!B' ,dexFileMmap.read(1))
        
        data = (data & 0x7f) | ((tmp[0] & 0x7f) << 7)
        if tmp[0] > 0x7f:
            dexFileMmap.seek(offset + 2)
            n = 2
            tmp = struct.unpack('!B' ,dexFileMmap.read(1))
            data |= (tmp[0] & 0x7f) << 14
            if tmp[0] > 0x7f:
                dexFileMmap.seek(offset + 3)
                n = 3
                tmp = struct.unpack('!B' ,dexFileMmap.read(1))
                data |= (tmp[0] & 0x7f) << 21
                if tmp[0] > 0x7f:
                    dexFileMmap.seek(offset + 4)
                    n = 4
                    tmp = struct.unpack('!B' ,dexFileMmap.read(1))
                    data |= tmp[0] << 28
    result[0] = data
    result[1] = offset + n + 1
    return result


#将hex数据移位拼接，例如 0x11 +0x22 +0x33 +0x44 = 0x11223344
def append_hex(arg0, arg1, arg2, arg3):
    arg0 =arg0<<24
    arg1 =arg1<<16
    arg2 =arg2<<8
    result = arg0 +arg1 +arg2 +arg3
    return hex(result)
        

if __name__ == "__main__":
    loadFile()         #加载dex文件
    parseDexHeader()   #解析dexHeader
    calcChecksum()     #计算 checksum
    parseStringIdList()#解析stringID格式
    parseTypeIdList()  #解析typeID格式
    parseProtoIdList() #解析
