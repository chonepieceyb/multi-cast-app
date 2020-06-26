/*
 *负责文件加密的 cpp
 *
 */

#include<math.h>
#include <iostream>
#include <cassert>
#include <string>
#include <vector>
#include<string.h>
#include<time.h>
#include<stdlib.h>
#include "/usr/local/include/openssl/des.h"
#include "/usr/local/include/openssl/rsa.h"
#include "/usr/local/include/openssl/pem.h"
using namespace std;
namespace security_utils{

string generate_des_key(int min =8,int max =8){
	
	// 产生 [min-max]位的由字母数字组成的随机字符串
	srand(time(NULL));  
	int bits = min + rand()%(max-min+1);  
	string result="";
	for(int i =0;i<bits;i++){
		// 随机决定字符还是数字
		switch( rand()%3){
			case 0:
				//数字
				result += '0' + rand()%10;
				break;
			case 1:
				// 字母
				result +=('a'+rand()%26);
				break;
			case 2:
				// 大写字母
				result +=('A'+rand()%26);
				break;
			default:
				break;
		}

	}
	return std::move(result);
}

// des 对称加密  采用 ecb模式加密

void   des(const char* src,const size_t length,char* dest, const std::string &key, int mode,size_t& result_length)
{

	/*
	 *加密函数
	 *src: 原数据
	 *length: src长度
	 *dest: 加密后数据，注意buffer大小要自己设置
	 *key 密钥
	 *result_length : 值结果参数，返回秘文的长度
	 *return : 秘文指针。
	 *mode: 模式 0 加密 1 解密
	 */
	// 按照我的理解，des得到的应该都是8的倍数,所以需要根据length进行适当的填充
	//
	int flag;
	if(mode==0){
		flag = DES_ENCRYPT;
	}else{
		flag = DES_DECRYPT;
	}
	result_length = ceil(float(length)/8)*8;   //向上取整为 8 的倍数
	char* offset = dest;
	DES_cblock keyEncrypt;
	memset(keyEncrypt, 0, 8);

	// 构造补齐后的密钥
	if (key.length() <= 8)
		memcpy(keyEncrypt, key.c_str(), key.length());
	else
		memcpy(keyEncrypt, key.c_str(), 8);

	// 密钥置换
	DES_key_schedule keySchedule;
	DES_set_key_unchecked(&keyEncrypt, &keySchedule);

	// 循环加密，每8字节一次
	const_DES_cblock inputText;
	DES_cblock outputText;
	unsigned char tmp[8];

	for (int i = 0; i < length / 8; i++)
	{
		memcpy(inputText, src + i * 8, 8);
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, flag);
		memcpy(offset, outputText, 8);
		offset+=8;
	}

	if (length % 8 != 0)
	{

		int tmp1 = length / 8 * 8;   // 取出 "余数"
		int tmp2 = length - tmp1;
		memset(inputText, 0, 8);
		memcpy(inputText, src+ tmp1, tmp2);  // 不够的位数，用 0 填充
		DES_ecb_encrypt(&inputText, &outputText, &keySchedule, flag);// 加密函数
		memcpy(offset, outputText, 8);

	}

}




// ---- rsa非对称加解密 ---- //
#define KEY_LENGTH  2048               // 密钥长度
#define PUB_KEY_FILE "pubkey.pem"    // 公钥路径
#define PRI_KEY_FILE "prikey.pem"    // 私钥路径

// 函数方法生成密钥对
void generateRSAKey(string& public_key,string& private_key, size_t key_length = 2048)
{
	// 公私密钥对
	size_t pri_len;
	size_t pub_len;
	char *pri_key = NULL;
	char *pub_key = NULL;

	// 生成密钥对
	RSA *keypair = RSA_generate_key(key_length, RSA_3, NULL, NULL);

	BIO *pri = BIO_new(BIO_s_mem());
	BIO *pub = BIO_new(BIO_s_mem());

	PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(pub, keypair);

	// 获取长度
	pri_len = BIO_pending(pri);
	pub_len = BIO_pending(pub);

	// 密钥对读取到字符串
	pri_key = (char *)malloc(pri_len + 1);
	pub_key = (char *)malloc(pub_len + 1);

	BIO_read(pri, pri_key, pri_len);
	BIO_read(pub, pub_key, pub_len);

	pri_key[pri_len] = '\0';
	pub_key[pub_len] = '\0';

	// 存储密钥对
	public_key = pub_key;
	private_key = pri_key;

	/*
	// 存储到磁盘（这种方式存储的是begin rsa public key/ begin rsa private key开头的）
	FILE *pubFile = fopen(PUB_KEY_FILE, "w");
	if (pubFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pub_key, pubFile);
	fclose(pubFile);

	FILE *priFile = fopen(PRI_KEY_FILE, "w");
	if (priFile == NULL)
	{
		assert(false);
		return;
	}
	fputs(pri_key, priFile);
	fclose(priFile);
	*/
	// 内存释放
	RSA_free(keypair);
	BIO_free_all(pub);
	BIO_free_all(pri);

	free(pri_key);
	free(pub_key);
}

// 命令行方法生成公私钥对（begin public key/ begin private key）
// 找到openssl命令行工具，运行以下
// openssl genrsa -out prikey.pem 1024
// openssl rsa - in privkey.pem - pubout - out pubkey.pem

// 公钥加密
std::string rsa_pub_encrypt(const std::string &clearText, const std::string &pubKey)
{
	std::string strRet;
	RSA *rsa = NULL;
	BIO *keybio = BIO_new_mem_buf((unsigned char *)pubKey.c_str(), -1);
	// 此处有三种方法
	// 1, 读取内存里生成的密钥对，再从内存生成rsa
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa
	// 3，直接从读取文件指针生成rsa
	RSA* pRSAPublicKey = RSA_new();
	rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *encryptedText = (char *)malloc(len + 1);
	memset(encryptedText, 0, len + 1);

	// 加密函数
	int ret = RSA_public_encrypt(clearText.length(), (const unsigned char*)clearText.c_str(), (unsigned char*)encryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(encryptedText, ret);

	// 释放内存
	free(encryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}

// 私钥解密
std::string rsa_pri_decrypt(const std::string &cipherText, const std::string &priKey)
{
	std::string strRet;
	RSA *rsa = RSA_new();
	BIO *keybio;
	keybio = BIO_new_mem_buf((unsigned char *)priKey.c_str(), -1);

	// 此处有三种方法
	// 1, 读取内存里生成的密钥对，再从内存生成rsa
	// 2, 读取磁盘里生成的密钥对文本文件，在从内存生成rsa
	// 3，直接从读取文件指针生成rsa
	rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa, NULL, NULL);

	int len = RSA_size(rsa);
	char *decryptedText = (char *)malloc(len + 1);
	memset(decryptedText, 0, len + 1);

	// 解密函数
	int ret = RSA_private_decrypt(cipherText.length(), (const unsigned char*)cipherText.c_str(), (unsigned char*)decryptedText, rsa, RSA_PKCS1_PADDING);
	if (ret >= 0)
		strRet = std::string(decryptedText, ret);

	// 释放内存
	free(decryptedText);
	BIO_free_all(keybio);
	RSA_free(rsa);

	return strRet;
}
}

/*

using namespace security_utils;
int main(int argc, char **argv)
{
	// 原始明文
	char* srcText = "abcdf";
	
	char* destText = new char[30];
	char* destText2 = new char[30];


	string eText;
	string dText;
	string k ="1234567";
	eText=des_encrypt(srcText,k);
	cout<<"秘文"<<eText<<endl;
	dText= des_decrypt(eText,k);
	cout<<"解密"<<dText<<endl;



	std::string encryptText;
	std::string encryptHexText;
	std::string decryptText;

	std::cout << "=== 原始明文 ===" << std::endl;
	std::cout << srcText << std::endl;
	// des
	std::cout << "=== des加解密 ===" << std::endl;
	std::string desKey = "1234567";
	size_t result_length;
	des(srcText,5,destText,desKey,0,result_length);  // 这里加密可能不能加最后一个字符
	destText[result_length]='\0';   //手动加终结
	std::cout << "加密字符： " << std::endl;
	std::cout << destText << std::endl;
	std::cout<<"加密结果长度: "<<result_length<<std::endl;
	des(destText,8,destText2, desKey,1,result_length);
	destText2[5] = '\0';
	std::cout << "解密字符： " << std::endl;
	std::cout << destText2 << std::endl;
	std::cout<<"解密结果长度: "<<result_length<<std::endl;
	// rsa
	std::cout << "=== rsa加解密 ===" << std::endl;
	std::string key[2];
	generateRSAKey(key);
	std::cout << "公钥: " << std::endl;
	std::cout << key[0] << std::endl;
	std::cout << "私钥： " << std::endl;
	std::cout << key[1] << std::endl;
	encryptText = rsa_pub_encrypt(srcText, key[0]);
	std::cout << "加密字符： " << std::endl;
	std::cout << encryptText << std::endl;
	decryptText = rsa_pri_decrypt(encryptText, key[1]);
	std::cout << "解密字符： " << std::endl;
	std::cout << decryptText << std::endl;

	system("pause");
	return 0;
}

*/
