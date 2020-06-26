#include "mcast_app.cpp"
#include<stdlib.h>
#include<string.h>
#include<iostream>
using namespace std;
using namespace mcast_class;
int main(int argc, char** argv){

	// 测试代码，先构造一个简单的多播程序是看看
	if(argc!=5){
		printf("usuage: app local-ip  multicast-ip-address port TTL\n");
		exit(1);
	}
	
	control(argv[1],argv[2],atoi(argv[3]),atoi(argv[3]),atoi(argv[4]));
}
