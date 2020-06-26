/*
 *
 * file_tools.cpp 负责 文件加密和文件读写
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include<string>
#include <sys/sysmacros.h>
#include<math.h>
#include<string.h>
 #include <unistd.h>
#include<iostream>
using namespace std;
namespace file_utiles{

void cp_and_reset(void* dst, void* src, const size_t bytes){
	memcpy(dst,src,bytes);
	memset(src,0,bytes);
}
size_t get_file_name( const char* src, char* dest=NULL,  char sep ='/'){
	/* 从路径中取出文件	
	 * src 原路径
	 * dst 存放文件名的地方，如果dst为NULL则返回
	 * sep 文件路径分割符
	 * return 文件字符串第一个字符在原字符串的下标
	 */
	const char* offset = strrchr(src,sep);
	if( NULL== offset){
		// 没找到表明src整个都是文件名		
		offset = src;	
	}else{
		offset+=1;
	}
	if(dest!=NULL){
		strcpy(dest,offset);  // 复制包括 '\0'
	}
	return offset -src;

}

//对linux一些文件操作进行封装
int OpenRFile(const string& pathname, size_t* size,const size_t block_size = 4096 ,int flags = O_RDONLY){
	/*
	 * 对 open函数进行封装,只用于打开普通文件
	 * pathname : 路径名
	 * block_size : 缓冲区的大小
	 * size  值结果参数,返回文件的大小
	 * flags 打开模式 默认只读
	 * 返回值 : 返回文件描述符，如果出错返回-1,如果是非普通文件返回-2
	 */
	int file_fd = open(pathname.c_str(),flags);
	if(file_fd==-1) return -1;
	// 开始计算文件大小
	if(size == NULL) return file_fd;  // 不用计算大小了
	struct stat stat_buf;
	if(fstat(file_fd,&stat_buf)!=0){
		close(file_fd);
		return -1;
	}

	// 判断是否为普通文件
	if(!S_ISREG(stat_buf.st_mode)){
		close(file_fd);
		return -1;
	}
	// 计算大小
	(*size) = stat_buf.st_size;  // 以字节为单位
	return file_fd;
}

int CreateRFile(const string& pathname, int mode = S_IRUSR|S_IWUSR, const string& append = "(1)"){
	/*
	 *在制定目录创建新文件，如果文件名重复的话，会自动加上附加符
	 *pathname: 文件名
	 *mode : 创建的权限 默认所有者有 读写执行权限
	 *return : 文件描述符,如果失败返回-1
	 */
	int file_fd = -1;
	int circle =0; // 循环次数，最多允许循环 10 次
	string new_pathname = pathname;
	while(circle<10&&(file_fd=open(new_pathname.c_str(),O_CREAT|O_EXCL|O_RDWR,mode))<0){
		// 尝试重命名操作
		new_pathname += append ;		
		circle++;
	}
	return file_fd;
}

ssize_t ReadBlock(int file_fd,void* buffer, const size_t bsize){
	// 将一整个 block的文件读到缓冲区
	size_t readed = 0;
	size_t left = bsize;
	while(readed != bsize){
		ssize_t temps = read(file_fd,buffer,left);
		if(temps ==-1) return -1;
		else if(temps ==0) break;
		readed += temps;
		left -= temps; 
	}
	return readed;
}

ssize_t WriteBlock(int file_fd, void* buffer, const size_t bsize){
	size_t writed = 0; //已经发送的
	size_t left = bsize;
	while(writed!= bsize){
		ssize_t temps =  write(file_fd,buffer,left);
		if( temps ==-1) return -1;   // 发送过程出错了
		writed+= temps;           
		left -= temps;
	}
	return writed;

}


}
