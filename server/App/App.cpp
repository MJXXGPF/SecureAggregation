#include "App.h"

#include "cn_edu_xd_jni_JNICall.h"
#include<iostream>
using namespace std;
#define MAX 1000000
#include <iostream>
#include <fstream>
#include <time.h>
extern "C" __declspec(dllexport) void aggregate(const uint8_t * encode_data,int encode_data_size, float * update_params, int totalParams, int clinet_size,int algo);
void init() {
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret == SGX_SUCCESS) {
		//printf("init success\n");
	}
	else {
		printf("init fail\n");
	}
}
void destroy() {

	ret = sgx_destroy_enclave(global_eid);
	if (ret == SGX_SUCCESS) {
		//printf("destroy success\n");
	}
	else {
		printf("destroy fail\n");
	}
}
extern "C" __declspec(dllexport) void encrypt_app(const uint8_t *raw_data, int src_len, const char *key, uint8_t *encode_data, int p_dst_len);
void encrypt_app(const uint8_t *raw_data, int src_len,const char *key, uint8_t *encode_data,int p_dst_len) {
	//printf("encoding...\n");
	init();
	//const uint32_t src_len = strlen(raw_data);
	////printf("src_len=%d\n", src_len);
	//int t = src_len / 64;
	//int r = src_len % 64;
	////uint8_t *encode_data = (uint8_t *)malloc(MAX * sizeof(uint8_t));
	//uint8_t *buf = (uint8_t *)malloc(64 * sizeof(uint8_t));
	//for (int i = 0; i < t; i++) {
	//	ecall_encrypt(global_eid, raw_data+64*i, key, buf);
	//	for (int j = 0; j < 64; j++) {
	//		encode_data[j + i * 64] = buf[j];
	//	}
	//}
	//printf("raw_data + t * 64=%s\n", raw_data + t * 64);
	ecall_encrypt(global_eid, raw_data,src_len,key, encode_data, p_dst_len);
	/*for (int i = 0; i < r; i++) {
		encode_data[i + t * 64] = buf[i];
	}*/
	destroy();
}
extern "C" __declspec(dllexport) void decrypt_app(const uint8_t *encode_data, const char *key, uint8_t *decode_data, int src_len);
void decrypt_app(const uint8_t *encode_data,const char *key, uint8_t *decode_data,int src_len) {
	//printf("decoding...\n");
	init();
	//printf("src_len=%d\n", src_len);
	//uint8_t *buf = (uint8_t *)malloc(src_len * sizeof(uint8_t));
	ecall_decrypt(global_eid, encode_data, key, decode_data, src_len);
	/*int t = src_len / 64;
	int r = src_len % 64;
	uint8_t *buf = (uint8_t *)malloc(64 * sizeof(uint8_t));
	for (int i = 0; i < t; i++) {
		ecall_decrypt(global_eid,encode_data + i * 64, key, buf,64);
		for (int j = 0; j < 64; j++) {
			decode_data[j + i * 64] = buf[j];
		}
	}
	ecall_decrypt(global_eid, encode_data + t * 64, key, buf, r);
	for (int i = 0; i < r; i++) {
		decode_data[i + t * 64] = buf[i];
	}*/
	destroy();
}
void aggregate(const uint8_t * encode_data, int encode_data_size, float * update_params, int update_params_size,int clinet_size,int algo) {
	init();
	printf("aggregate\n");
	// 计时开始
	clock_t start = clock();
	ecall_aggregate(global_eid, encode_data, encode_data_size, update_params, update_params_size, clinet_size,algo);
	// 计时结束
	clock_t end = clock();
	double duration = (double)(end - start);
	printf("Execution time: %f seconds\n", duration);
	
	destroy();
	
}

JNIEXPORT void JNICALL Java_cn_edu_xd_jni_JNICall_init
(JNIEnv * env, jclass cls) {
	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &global_eid, NULL);
	if (ret == SGX_SUCCESS) {
		printf("init success\n");
	}
	else {
		printf("init fail\n");
	}
}
JNIEXPORT void JNICALL Java_cn_edu_xd_jni_JNICall_destroy
(JNIEnv * env, jclass cls) {
	ret = sgx_destroy_enclave(global_eid);
	if (ret == SGX_SUCCESS) {
		printf("destroy success\n");
	}
	else {
		printf("destroy fail\n");
	}
}
JNIEXPORT void JNICALL Java_cn_edu_xd_jni_JNICall_hello(JNIEnv * env, jclass cls) {
	ecall_hello(global_eid);
}

void ocall_print_string(const char *str)
{
	printf("%s", str);
}

jstring char2Jstring(JNIEnv* env, const char* pat)
{
	//定义java String类 strClass
	jclass strClass = (env)->FindClass("java/lang/String");
	//获取java String类方法String(byte[],String)的构造器,用于将本地byte[]数组转换为一个新String
	jmethodID ctorID = (env)->GetMethodID(strClass, "<init>", "([BLjava/lang/String;)V");
	//建立byte数组
	jbyteArray bytes = (env)->NewByteArray((jsize)strlen(pat));
	//将char* 转换为byte数组
	(env)->SetByteArrayRegion(bytes, 0, (jsize)strlen(pat), (jbyte*)pat);
	//设置String, 保存语言类型,用于byte数组转换至String时的参数
	jstring encoding = (env)->NewStringUTF("GB2312");
	//将byte数组转换为java String,并输出
	return (jstring)(env)->NewObject(strClass, ctorID, bytes, encoding);

}
JNIEXPORT jstring JNICALL Java_cn_edu_xd_jni_JNICall_aggregation
(JNIEnv * env, jclass cls, jstring _s) {
	const char *in = env->GetStringUTFChars(_s, 0);
	char ret[10] = {'\0'};
	int num = 0;
	printf("app address ret: %p\n", ret);
	printf("app address num: %p\n", &num);
	
	ecall_aggregation(global_eid,in,ret,&num);
	printf("app value num: %d\n", num);
	printf("after aggregation: %s\n", ret);
	return char2Jstring(env, ret);
	
}


