#include "Enclave_t.h"
#include "Enclave.h"
#include "sgx_trts.h"
#include <vector>
#include <string>
#include <sgx_tcrypto.h>
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include <cstring>
#include<vector>
#include <time.h>
#include <cmath>
using namespace std;
#define SGXSSL_CTR_BITS 128
#define SHIFT_BYTE 8
#define sz 100
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef uint8_t sgx_aes_ctr_128bit_key_t[16];
int SGX_AES_BLOCK_SIZE = 16;

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

/*
打印16进制的函数
*/
void print_hex(const uint8_t *buf, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

/*
C实现的类似于python中的struct.unpack函数
*/
template<typename T>
T unpack(const uint8_t* buffer, size_t offset) {
	T value;
	memcpy(&value, buffer + offset, sizeof(T));
	return value;
}


/*
C实现的类似于python中的struct.pack函数
*/
template<typename T>
vector<uint8_t> pack(const T* array, size_t length) {
	vector<uint8_t> bytes(length * sizeof(T));
	size_t offset = 0;
	for (size_t i = 0; i < length; i++) {
		memcpy(bytes.data() + offset, &array[i], sizeof(T));
		offset += sizeof(T);
	}
	return bytes;
}
/*
二元组结构定义
index: 维度下标
value: 维度值
*/
typedef struct {
	int index;
	float value;
}_tuple;

/*
三元组结构定义
no: 排名
value_fake: 因为后面的使用的不经意原语是以8字节为单位 这个字段是用来补齐no
index: 维度下标
value: 维度值
*/
typedef struct {
	int no;
	float value_fake;
	int index;
	float value;
}_tuple2;

typedef struct{
	int value;
	int index;
}mypair;





void normal_aggregate(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, _tuple *all_client_data);
void baseline(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data);
void baseline_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data);
void baseline_primitive_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d);
void advance_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data, int size);
void advance_primitive_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size);
void advance_primitive2(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple2 *all_client_data, int size);
void advance_primitive2_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size);
void normal_aggregate_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters);

void o_oblivious_sort_idx(_tuple *all_client_data, int size);
void o_oblivious_sort_idx_new(int size);
void o_oblivious_sort_idx2(_tuple2 *all_client_data, int size);
void o_oblivious_sort_idx2_new(int size);
void o_oblivious_sort_idx3(_tuple2 *all_client_data, int size);
void o_oblivious_sort_idx3_new(int size);


void oblivious_sort_idx(_tuple *all_client_data, int size, _tuple ** arr_ptr);
void oblivious_sort_idx_new(int size);
void oblivious_sort_idx2(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr);
void oblivious_sort_idx2_new(int size);
void oblivious_sort_idx3(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr);
void oblivious_sort_idx3_new(int size);
void quick_sort_by_no(int start, int end);
void quick_sort_by_id(int start, int end);


int pad_max_idx_weight_to_power_of_two(_tuple *all_client_data, int size, _tuple ** arr_ptr);
int pad_max_idx_weight_to_power_of_two_new(int size);
int pad_max_idx_weight_to_power_of_two2(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr);
int pad_max_idx_weight_to_power_of_two2_new(int size);




void bubbleSort(_tuple *all_client_data, int size);
void bubbleSort1_new(int size);
void bubbleSort2_new(int size);

void quick_sort_int(int lo,int hi);
int partition_int(int lo,int hi);
void swap_int(int i,int j);
void quick_sort_float(int lo,int hi);
int partition_float(int lo,int hi);
void swap_float(int i,int j);
void quick_sort_pair(int lo,int hi);
int partition_pair(int lo,int hi);
void swap_pair(int i,int j);
void merge_sort_pair(int lo,int hi);
void merge(int lo,int mid,int hi);
int partition_pair(int lo,int hi);
void swap_pair(int i,int j);
void getSortPermJ(int size);
void getSortPermB(int size);
void getB(int size);
void apply1(int size);
void apply2(int size);


/*
for test ignore
*/

void ecall_sum(int * data, int * sum, int size) {
	_tuple *all_client_data2 = (_tuple*)malloc(sizeof(_tuple)*sz);
	_tuple *all_client_data21 = (_tuple*)malloc(sizeof(_tuple)*sz);
	_tuple *all_client_data22 = (_tuple*)malloc(sizeof(_tuple)*sz);
	for (int i = 0; i < sz; i++) {
		all_client_data22[i].index = 1;
	}
	int s = 0;
	for (int i = 0; i < sz; i++) {
		s += all_client_data22[i].index;
	}
	printf("ecall sum sum=%d\n",s);
}
/*
加密数据
*/
void ecall_encrypt(const uint8_t *raw_data,int src_len,const char *key, uint8_t *p_dst, int p_dst_len) {
	
	int blockSize = 16;
	sgx_status_t rc;
	const uint8_t *p_src = raw_data;
	uint8_t p_ctr[16] = { '0' };
	const uint32_t ctr_inc_bits = 128;
	uint8_t *p_dst2 = (uint8_t *)malloc(blockSize * sizeof(uint8_t));
	int t = src_len;
	int m = src_len / blockSize;
	int r = src_len % blockSize;
	for (int i = 0; i < m; i++) {
		rc = sgx_aes_ctr_encrypt((sgx_aes_ctr_128bit_key_t *)key, p_src+ blockSize *i, blockSize, p_ctr, ctr_inc_bits, p_dst2);
		for (int j = 0; j < blockSize; j++) {
			p_dst[i *  blockSize + j] = p_dst2[j];
		}
	}
	rc = sgx_aes_ctr_encrypt((sgx_aes_ctr_128bit_key_t *)key, p_src + blockSize * m, r, p_ctr, ctr_inc_bits, p_dst2);
	for (int j = 0; j < r; j++) {
		p_dst[m *  blockSize + j] = p_dst2[j];
	}
	free(p_dst2);
	
	
	//*((char*)p_dst + src_len) = '\0';

}
/*
for test ignore 
*/
int add(int a, int b) {
	printf("hello python call dll\n");
	return a + b+1000;
}

/*
解密
*/
void  ecall_decrypt(const uint8_t *encode_data,
	const char *key, uint8_t *p_dst, int len)
{
	int blockSize = 16;
	uint32_t src_len = len;
	uint8_t p_ctr[16] = { '0' };
	const uint32_t ctr_inc_bits = 128;
	uint8_t *sgx_ctr_keys = (uint8_t *)malloc(16 * sizeof(char));
	memcpy(sgx_ctr_keys,key, 16);
	uint8_t *p_dsts2 = (uint8_t *)malloc(blockSize * sizeof(char));
	memset(p_dsts2, '\0', blockSize);
	sgx_status_t rc;
	int t = src_len;
	int i = 0;
	int m = src_len / 16;
	int r = src_len % 16;
	for (int i = 0; i < m; i++) {
		rc = sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t *)sgx_ctr_keys, encode_data + blockSize *i, blockSize, p_ctr, ctr_inc_bits, p_dsts2);
		for (int j = 0; j < blockSize; j++) {
			p_dst[i* blockSize +j]= p_dsts2[j];
		}
	}
	rc = sgx_aes_ctr_decrypt((sgx_aes_gcm_128bit_key_t *)sgx_ctr_keys, encode_data + blockSize *m,r, p_ctr, ctr_inc_bits, p_dsts2);
	for (int j = 0; j <r; j++) {
		p_dst[m *  blockSize + j] = p_dsts2[j];
	}
	
	free(sgx_ctr_keys);
	free(p_dsts2);
	
}

/*
for test ignore
*/
extern "C" int hello() {
	printf("hello\n");
	return 1;
}
//100M/8=
//vector<_tuple2> all_client_data(100000);

_tuple2 all_client_data[90000000];
double arr[sz];
/*
for test ignore
*/
void ecall_hello() {
    // int sum=0;
	
    // for(int i=0;i<sz;i++){
    //     arr[i]=1;
    // }
    //  for(int i=0;i<sz;i++){
    //     sum+=arr[i];
    // }
    printf("hello in enclave\n");
	 
}
/*
for test ignore
*/
void ecall_aggregation(const char * input, char ret[10],int* num){
	
	printf("server receive %s\n", input);
	printf("enclave address ret: %p\n", ret);
	printf("enclave address num: %p\n", &num);
	*num = 999;
	for (int i = 0; i < 9; i++) {
		ret[i] = 'b';
	}
	ret[9] = '\0';
	printf("val of ret in enclave: %s\n", ret);
	
}

/*
聚合函数
encode_data: 客户端传递的加密数据
encode_data_size：加密数据大小
update_params：最后更新的数据
update_params_size：最后更新的数据的大小，即d
client_size: 客户端数量
algo: 采用的聚合算法
*/
void ecall_aggregate(const uint8_t * encode_data, int encode_data_size,float * update_params, int update_params_size, int client_size,int algo) {

	printf("ecall_aggregate....\n");
	ocall_start_time();
	int byte_size_per_client = encode_data_size / client_size;
	int given_num_of_sparse_parameters = byte_size_per_client / 8;
	printf("encode_data_size=%d\n", encode_data_size);
	printf("client_size=%d\n", client_size);
	printf("byte_size_per_client=%d\n", byte_size_per_client);
	printf("given_num_of_sparse_parameters=%d\n", given_num_of_sparse_parameters);
	printf("update_params_size=%d\n", update_params_size);
	int n = client_size, k = given_num_of_sparse_parameters, d = update_params_size;
	uint8_t * decode_data_per_client = (uint8_t *)malloc(byte_size_per_client);
	int offset = 0;
	int len = -1;
	if (algo == 3)
		len = n * k + d;
	else
		len = n * k;
	printf("len=%d\n", len);

	if (algo != 4) {
		//algo=4是自己设计的算法  需要使用三元组
		printf("algo=%d\n", algo);
		int idx = 0;
		for (int i = 0; i < client_size; i++) {
			ecall_decrypt(encode_data + offset, "1234567812345678", decode_data_per_client, byte_size_per_client);

			int offset2 = 0;
			for (int j = 0; j < given_num_of_sparse_parameters; j++) {
				all_client_data[idx].index = unpack<int>(decode_data_per_client, offset2);
				offset2 += 4;
				all_client_data[idx].value = unpack<float>(decode_data_per_client, offset2);
				offset2 += 4;
				idx++;
			}
			offset += byte_size_per_client;
		}
	}
	else {//其他的算法只需要使用二元组
		printf("algo=%d\n", algo);
		int idx = 0;
		for (int i = 0; i < client_size; i++) {
			
			ecall_decrypt(encode_data + offset, "1234567812345678", decode_data_per_client, byte_size_per_client);

			int offset2 = 0;
			for (int j = 0; j < given_num_of_sparse_parameters; j++) {
				all_client_data[idx].no = 0;
				all_client_data[idx].value_fake = 0.0;
				all_client_data[idx].index = unpack<int>(decode_data_per_client, offset2);
				offset2 += 4;
				all_client_data[idx].value = unpack<float>(decode_data_per_client, offset2);
				offset2 += 4;
				idx++;
			}
			offset += byte_size_per_client;
		}
	}
	
	switch (algo) {
	/*case 1:  normal_aggregate(update_params, update_params_size, client_size, given_num_of_sparse_parameters, all_client_data); break;
	case 2:   baseline_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, all_client_data); break;
	case 3:   advance_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, all_client_data,len); break;
	case 4:   advance_primitive2(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, all_client_data2,len); break;*/
	case 1:  normal_aggregate_new(update_params, update_params_size, client_size, given_num_of_sparse_parameters); break;
	case 2:   baseline_primitive_new(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size); break;
	case 3:   advance_primitive_new(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len); break;
	case 4:   advance_primitive2_new(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len); break;
	}
	ocall_end_time();
}

/*
普通聚合 可以应用于稀疏梯度  也可以应用于非稀疏梯度
*/
void normal_aggregate(float * update_params, int update_params_size, int client_size,int given_num_of_sparse_parameters, _tuple *all_client_data) {
	
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			update_params[all_client_data[idx].index] += all_client_data[idx].value;
			idx++;
		}
	}
	
	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}

/*
_new表示保存客户端数据的数组是是一个全局变量  因为直接在函数中进行malloc会有一些错误
*/
void normal_aggregate_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters) {

	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			update_params[all_client_data[idx].index] += all_client_data[idx].value;
			idx++;
		}
	}

	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}

/*
olive论文中的baseline算法  二重循环  逐个比较
*/
void baseline(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters,int d, _tuple *all_client_data) {
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			int index = all_client_data[idx].index;
			for (int k = 0; k < d; k++) {
				int flag = index == k;
				if (flag) {
					update_params[k] += all_client_data[idx].value;
				}
				else {
					update_params[k] += 0;
				}
			}
			idx++;
			
		}
	}
	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}


// extern "C" {
// 	/*
// 	不经意移动原语  flag为true时  ret=y  否则ret=x
// 	*/
// 	int64_t o_mov(int64_t flag,int  *x, int *y, int *ret);
// 	/*
// 	不经意移动原语  flag为true时  ret=y  否则ret=x
// 	*/
// 	int64_t o_mov_float(int64_t flag, float  *x, float *y, float *ret);
// 	/*
// 	不经意移动原语 flag为true x和y进行交换
// 	*/
// 	int64_t o_swap(int64_t flag, int *x, int *y);
// }


/*
olive论文中的baseline算法  添加了不经意原语
*/
void baseline_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data) {
	printf("baseline_primitive...\n");
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		//printf("client#%d\n", i);
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			int index = all_client_data[idx].index;
			for (int k = 0; k < d; k++) {
				int flag = index == k;
				float x = update_params[k], y = update_params[k]+all_client_data[idx].value,z=-1;
				//o_mov_float(flag, &x, &y, &z);
                if(flag){
                    z=y;
                }else{
                    z=x;
                }
				update_params[k] = z;
				float *tmp = &z;//0611 不加这一行好像数据有问题？？？
			}
			idx++;
		}
	}
	
	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}

/*
olive论文中的baseline算法  添加了不经意原语
*/
void baseline_primitive_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d) {
	printf("baseline_primitive...\n");
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			int index = all_client_data[idx].index;
			for (int k = 0; k < d; k++) {
				int flag = index == k;
				float x = update_params[k], y = update_params[k] + all_client_data[idx].value, z = -1;
				//o_mov_float(flag, &x, &y, &z);
                  if(flag){
                    z=y;
                }else{
                    z=x;
                }
				update_params[k] = z;
				float *tmp = &z;//0611 不加这一行好像数据有问题？？？
			}
			idx++;
		}
	}

	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}

#define MAX 10000000
/*
olive论文中的advance算法
*/
void advance_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data,int size) {
	printf("advance_primitive...\n");
	int n = client_size, k = given_num_of_sparse_parameters;
	//1. 添加d个dummy元组
	for (int i = n * k,idx=0; i < size; i++) {
		all_client_data[i].index = idx;
		all_client_data[i].value = 0.0;
		idx++;
	}
	printf("size=%d\n", size);
	oblivious_sort_idx(all_client_data, size,&all_client_data);//第一次不经意排序
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length = n * k + d;
	for (int i = 1; i < initialized_parameter_length; i++) {
		
		
		//以下代码不使用不经意原语实现相关操作
		int flag = pre_idx == all_client_data[i].index;
		if (flag) {
			all_client_data[i - 1].index = MAX;
			all_client_data[i - 1].value =0.0;
			pre_idx = pre_idx;
			pre_val = pre_val + all_client_data[i].value;
		}
		else
		{
			all_client_data[i - 1].index = pre_idx;
			all_client_data[i - 1].value = pre_val;
			pre_idx = all_client_data[i].index;
			pre_val = all_client_data[i].value;
		}

		//以下代码使用不经意原语实现相关操作
		// _tuple t1 = { pre_idx, pre_val };
		// _tuple t2 = {MAX, 0.0 };
		// _tuple update = { 0,0.0 };
		// //一次操作的数据时8个字节 因此移动index的同时也移动了value
		// o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index, &update.index);
		
		// all_client_data[i - 1].index = update.index;
		// all_client_data[i - 1].value = update.value;
		// _tuple pre_update = { 0,0.0 };
		// t1 = { all_client_data[i].index, all_client_data[i].value};
		// t2 = { pre_idx, pre_val + all_client_data[i].value };
		// o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index,&pre_update.index);
		// pre_idx = pre_update.index;
		// pre_val = pre_update.value;
	
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	oblivious_sort_idx(all_client_data, size, &all_client_data);//第二次不经意排序
	for (int i = 0; i < d; i++) {
		update_params[i] = all_client_data[i].value;
		update_params[i] /= client_size;
	}
}
/*
olive论文中的advance算法
*/
void advance_primitive_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size) {
	int n = client_size, k = given_num_of_sparse_parameters;
	for (int i = n * k, idx = 0; i < size; i++) {
		all_client_data[i].index = idx;
		all_client_data[i].value = 0.0;
		idx++;
	}
	//oblivious_sort_idx_new(size);
	//bubbleSort1_new(size);
	quick_sort_by_id(0,size-1);
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length = n * k + d;
	for (int i = 1; i < initialized_parameter_length; i++) {

		int flag = pre_idx == all_client_data[i].index;
		if (flag) {
			all_client_data[i - 1].index = MAX;
			all_client_data[i - 1].value =0.0;
			pre_idx = pre_idx;
			pre_val = pre_val + all_client_data[i].value;
		}
		else
		{
			all_client_data[i - 1].index = pre_idx;
			all_client_data[i - 1].value = pre_val;
			pre_idx = all_client_data[i].index;
			pre_val = all_client_data[i].value;
		}

		
		// _tuple t1 = { pre_idx, pre_val };
		// _tuple t2 = { MAX, 0.0 };
		// _tuple update = { 0,0.0 };
		// o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index, &update.index);
		// all_client_data[i - 1].index = update.index;
		// all_client_data[i - 1].value = update.value;
		// _tuple pre_update = { 0,0.0 };
		// t1 = { all_client_data[i].index, all_client_data[i].value };
		// t2 = { pre_idx, pre_val + all_client_data[i].value };
		// o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index, &pre_update.index);
		// pre_idx = pre_update.index;
		// pre_val = pre_update.value;
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	//bubbleSort1_new(size);
	//oblivious_sort_idx_new(size);
	quick_sort_by_id(0,size-1);
	for (int i = 0; i < d; i++) {
		update_params[i] = all_client_data[i].value;
		update_params[i] /= client_size;
	}
}

/*
自己设计的算法 使用malloc申请all_client_data
*/
void advance_primitive2(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple2 *all_client_data,int size) {
	oblivious_sort_idx2(all_client_data, size, &all_client_data);
	int n = client_size, k = given_num_of_sparse_parameters;
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length = n * k;
	int X = 0, Y = n * k-1;
	for (int i = 1; i < initialized_parameter_length; i++) {
		int flag = pre_idx == all_client_data[i].index;
		//不使用原语进行操作
		if (flag) {
			all_client_data[i - 1].no = Y;
			Y--;
			all_client_data[i - 1].index = MAX;
			all_client_data[i - 1].value =0.0;
			pre_idx = pre_idx;
			pre_val = pre_val + all_client_data[i].value;
		}
		else
		{
			all_client_data[i - 1].no = X;
			X++;
			all_client_data[i - 1].index = pre_idx;
			all_client_data[i - 1].value = pre_val;
			pre_idx = all_client_data[i].index;
			pre_val = all_client_data[i].value;
		}

		//使用原语进行操作
		// _tuple2 t1 = { 0,0.0,pre_idx, pre_val };
		// _tuple2 t2 = {0,0.0, MAX, 0.0 };
		// _tuple2 update = { 0,0.0,0,0.0 };

		// o_mov(flag, &t1.index, &t2.index, &update.index);
		// o_mov(flag, &X, &Y, &update.no);
		// all_client_data[i - 1].no = update.no;
		// all_client_data[i - 1].index = update.index;
		// all_client_data[i - 1].value = update.value;
		// _tuple2 pre_update = { 0,0.0,0,0.0 };
		// t1 = { 0,0.0,all_client_data[i].index, all_client_data[i].value };
		// t2 = { 0,0.0, pre_idx, pre_val + all_client_data[i].value };
		// o_mov(flag, &t1.index, &t2.index, &pre_update.index);
		// o_mov(flag, &X, &Y, &pre_update.no);
		// if (flag) {
		// 	Y--;
		// }
		// else {
		// 	X++;
		// }
		// pre_idx = pre_update.index;
		// pre_val = pre_update.value;
	}
	all_client_data[initialized_parameter_length - 1].no = X;
	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	oblivious_sort_idx3(all_client_data, size, &all_client_data);
	for (int i = 0; i <=X; i++) {
		int index = all_client_data[i].index;
		update_params[index] = all_client_data[i].value;
		update_params[index] /= client_size;
	}
}
int p_arr[2*60000];
int b_arr[2*60000];
int j_arr[2*60000];
float v_arr[2*60000];
mypair pairs[2*60000];
float v1_arr[2*60000];
float v2_arr[2*60000];
mypair tmp_p[2*60000];


/*
自己设计的算法 使用全局变量 all_client_data
*/
void advance_primitive2_new(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size) {
	int n = client_size, k = given_num_of_sparse_parameters;
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length = n * k;
	int X = 0, Y = n * k - 1;
	ocall_start_time2();
	oblivious_sort_idx2_new(size);
	//bubbleSort1_new(size);
	//quick_sort_by_id(0,size-1);
	ocall_end_time2();
	ocall_print_time2();

	printf("X=%d,Y=%d\n", X, Y);
	ocall_start_time3();
	for (int i = 1; i < initialized_parameter_length; i++) {
		int flag = pre_idx == all_client_data[i].index;
		
		//不使用原语
		if (flag) {
			all_client_data[i - 1].no = Y;
			Y--;
			all_client_data[i - 1].index = MAX;
			all_client_data[i - 1].value =0.0;
			pre_idx = pre_idx;
			pre_val = pre_val + all_client_data[i].value;
		}
		else
		{
			all_client_data[i - 1].no = X;
			X++;
			all_client_data[i - 1].index = pre_idx;
			all_client_data[i - 1].value = pre_val;
			pre_idx = all_client_data[i].index;
			pre_val = all_client_data[i].value;
		}

		//使用原语
		// _tuple2 t1 = { 0,0.0,pre_idx, pre_val };
		// _tuple2 t2 = { 0,0.0, MAX, 0.0 };
		// _tuple2 update = { 0,0.0,0,0.0 };
		// o_mov(flag, &t1.index, &t2.index, &update.index);
		// o_mov(flag, &X, &Y, &update.no);
		// all_client_data[i - 1].no = update.no;
		// all_client_data[i - 1].index = update.index;
		// all_client_data[i - 1].value = update.value;
		// _tuple2 pre_update = { 0,0.0,0,0.0 };
		// t1 = { 0,0.0,all_client_data[i].index, all_client_data[i].value };
		// t2 = { 0,0.0, pre_idx, pre_val + all_client_data[i].value };
		// o_mov(flag, &t1.index, &t2.index, &pre_update.index);
		// o_mov(flag, &X, &Y, &pre_update.no);
		// pre_idx = pre_update.index;
		// pre_val = pre_update.value;

		// if (flag) {
		// 	Y--;
		// }
		// else {
		// 	X++;
		// }
	}
	all_client_data[initialized_parameter_length - 1].no = X;
	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	ocall_end_time3();
	ocall_print_time3();
    ocall_start_time2();
	oblivious_sort_idx3_new(size);
	//bubbleSort2_new(size);
    //quick_sort_by_no(0,size-1);  
	//next step: oblivious write algorithm
	// for(int i=0;i<d;i++){
	// 	j_arr[i]=all_client_data[i].index;
	// 	v_arr[i]=all_client_data[i].value;
	// }

	// for(int i=d;i<2*d;i++){
	// 	j_arr[i]=i-d;
	// 	v_arr[i]=0.0;
	// }
	// getSortPermJ(2*d);
	// getB(2*d);
	// apply1(2*d);
	// getSortPermB(2*d);
	// apply2(2*d);
	// for (int i = 0; i < d; i++){
	// 	update_params[i] =v2_arr[i]/client_size;
	// }
	ocall_end_time2();
	ocall_print_time2();
	printf("X=%d,Y=%d  0924\n", X,Y);
	for (int i = 0; i <= X; i++) {
		int index = all_client_data[i].index;
		update_params[index] = all_client_data[i].value/client_size;
	}
	

}

/*
拓展数组大小为2次幂 针对与二元组&&malloc申请all_client_data
*/
int pad_max_idx_weight_to_power_of_two(_tuple *all_client_data, int size, _tuple ** arr_ptr) {
	//printf("pad_max_idx_weight_to_power_of_two start...\n");
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	printf("newLen=%d\n", new_size);
	_tuple *new_arr = (_tuple*)realloc(all_client_data,sizeof(_tuple)*new_size);
	for (int i = size; i < new_size; i++) {
		new_arr[i].index = 0;
		new_arr[i].value = 0.0;
	}
	*arr_ptr = new_arr;
	//printf("pad_max_idx_weight_to_power_of_two end...\n");
	return new_size - size;
}
/*
拓展数组大小为2次幂 针对与二元组&&全局all_client_data
*/
int pad_max_idx_weight_to_power_of_two_new(int size) {
	//printf("pad_max_idx_weight_to_power_of_two start...\n");
	unsigned int power = ceil(log2(size));//????????????????????>=len???????????????? ????????????????????????????
	int new_size = pow(2, power);
	printf("newSize=%d\n", new_size);
	for (int i = size; i < new_size; i++) {
		all_client_data[i].index = 0;
		all_client_data[i].value = 0.0;
	}
	return new_size - size;
}

/*
拓展数组大小为2次幂 针对与三元组&&malloc申请all_client_data
*/
int pad_max_idx_weight_to_power_of_two2(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr) {
	//printf("pad_max_idx_weight_to_power_of_two2 start...\n");
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	printf("newLen=%d\n", new_size);
	_tuple2 *new_arr = (_tuple2*)realloc(all_client_data, sizeof(_tuple2)*new_size);
	for (int i = size; i < new_size; i++) {
		new_arr[i].no = 0;
		new_arr[i].value_fake = 0.0;
		new_arr[i].index = 0;
		new_arr[i].value = 0.0;
	}
	*arr_ptr = new_arr;
	//printf("pad_max_idx_weight_to_power_of_two2 end...\n");
	return new_size - size;
}

/*
拓展数组大小为2次幂 针对与三元组&&全局all_client_data
*/
int pad_max_idx_weight_to_power_of_two2_new(int size) {
	//printf("pad_max_idx_weight_to_power_of_two2 start...\n");
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	printf("newSize=%d\n", new_size);
	for (int i = size; i < new_size; i++) {
		all_client_data[i].no = 0;
		all_client_data[i].value_fake = 0.0;
		all_client_data[i].index = 0;
		all_client_data[i].value = 0.0;
	}
	//printf("newLen=%d\n", new_size);
	return new_size - size;
}
/*
针对二元组&&malloc申请的all_client_data
*/
void oblivious_sort_idx(_tuple *all_client_data, int size, _tuple ** arr_ptr) {
	//printf("oblivious_sort_idx start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two(all_client_data, size, &all_client_data);
	//bubbleSort(all_client_data, size); ????????????????
	o_oblivious_sort_idx(all_client_data, size+ number_of_pads);
	_tuple *tmp = (_tuple*)malloc(size * sizeof(_tuple));
	for (int i = 0; i < size; i++) {
		tmp[i].index = all_client_data[i + number_of_pads].index;
		tmp[i].value = all_client_data[i + number_of_pads].value;
	}
	free(all_client_data);
	*arr_ptr = tmp;
	//printf("oblivious_sort_idx end...\n");

}
/*
针对二元组&&全局定义的all_client_data
*/
void oblivious_sort_idx_new(int size) {
	//printf("oblivious_sort_idx start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two_new(size);
	o_oblivious_sort_idx_new(size + number_of_pads);
	for (int i = 0; i < size; i++) {
		all_client_data[i].no = all_client_data[i + number_of_pads].no;
		all_client_data[i].value_fake = all_client_data[i + number_of_pads].value_fake;
		all_client_data[i].index = all_client_data[i + number_of_pads].index;
		all_client_data[i].value = all_client_data[i + number_of_pads].value;
	}
	//printf("oblivious_sort_idx end...\n");

}
/*
针对三元组&&malloc申请的all_client_data 针对index排序
*/
void oblivious_sort_idx2(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr) {
	//printf("oblivious_sort_idx2 start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two2(all_client_data, size, &all_client_data);
	o_oblivious_sort_idx2(all_client_data, size + number_of_pads);
	_tuple2 *tmp = (_tuple2*)malloc(size * sizeof(_tuple2));
	for (int i = 0; i < size; i++) {
		tmp[i].no= all_client_data[i + number_of_pads].no;
		tmp[i].value_fake = all_client_data[i + number_of_pads].value_fake;
		tmp[i].index = all_client_data[i + number_of_pads].index;
		tmp[i].value = all_client_data[i + number_of_pads].value;
	}
	free(all_client_data);
	*arr_ptr = tmp;
	//printf("oblivious_sort_idx2 end...\n");
}
/*
针对三元组&&全局定义的all_client_data  针对index排序
*/
void oblivious_sort_idx2_new(int size) {
	//printf("oblivious_sort_idx2_new start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two2_new(size);
	o_oblivious_sort_idx2_new(size + number_of_pads);
	for (int i = 0; i < size; i++) {
		all_client_data[i].no = all_client_data[i + number_of_pads].no;
		all_client_data[i].value_fake = all_client_data[i + number_of_pads].value_fake;
		all_client_data[i].index = all_client_data[i + number_of_pads].index;
		all_client_data[i].value = all_client_data[i + number_of_pads].value;
	}
	//printf("oblivious_sort_idx2 end...\n");
}

/*
针对三元组&&malloc申请的all_client_data 针对no排序
*/
void oblivious_sort_idx3(_tuple2 *all_client_data, int size, _tuple2 ** arr_ptr) {
	//printf("oblivious_sort_idx2 start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two2(all_client_data, size, &all_client_data);
	o_oblivious_sort_idx3(all_client_data, size + number_of_pads);
	_tuple2 *tmp = (_tuple2*)malloc(size * sizeof(_tuple2));
	for (int i = 0; i < size; i++) {
		tmp[i].no = all_client_data[i + number_of_pads].no;
		tmp[i].value_fake = all_client_data[i + number_of_pads].value_fake;
		tmp[i].index = all_client_data[i + number_of_pads].index;
		tmp[i].value = all_client_data[i + number_of_pads].value;
	}
	free(all_client_data);
	*arr_ptr = tmp;
	//printf("oblivious_sort_idx2 end...\n");
}
/*
针对三元组&&全局定义的all_client_data  针对no排序
*/
void oblivious_sort_idx3_new(int size) {
	//printf("oblivious_sort_idx3 start...\n");
	int number_of_pads = pad_max_idx_weight_to_power_of_two2_new(size);
	o_oblivious_sort_idx3_new(size + number_of_pads);
	for (int i = 0; i < size; i++) {
		all_client_data[i].no = all_client_data[i + number_of_pads].no;
		all_client_data[i].value_fake = all_client_data[i + number_of_pads].value_fake;
		all_client_data[i].index = all_client_data[i + number_of_pads].index;
		all_client_data[i].value = all_client_data[i + number_of_pads].value;
	}
	
	//printf("oblivious_sort_idx3 end...\n");
}
/*
不经意排序  针对二元组&&malloc申请的all_client_data
*/
void o_oblivious_sort_idx(_tuple *all_client_data,int size) {
	//printf("o_oblivious_sort_idx start...\n");
	
	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].index < all_client_data[m].index;
				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
				
				//不使用原语
			    if (cond1 ^ cond2) {
					int t1=all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value= all_client_data[m].value;
					all_client_data[m].value = t2;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}
	//printf("o_oblivious_sort_idx end...\n");
}

/*
不经意排序  针对二元组&&malloc申请的all_client_data
*/
void o_oblivious_sort_idx_new(int size) {
	//printf("o_oblivious_sort_idx start...\n");

	/*double start = 0, end = 0;
	ocall_get_time_ms(&start);*/

	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].index < all_client_data[m].index;
				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);

				
			    if (cond1 ^ cond2) {
					int t1=all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value= all_client_data[m].value;
					all_client_data[m].value = t2;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}
	/*ocall_get_time_ms(&end);*/
	//printf("o_oblivious_sort_idx end...\n");
}

/*
不经意排序  针对三元组&&malloc申请的all_client_data  根据index排序
*/
void o_oblivious_sort_idx2(_tuple2 *all_client_data, int size) {
	//printf("o_oblivious_sort_idx2 start...size=%d\n",size);
	//double start = 0, end = 0;
	//ocall_get_time_ms(&start);
	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].index < all_client_data[m].index;

				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
				
				if (cond1 ^ cond2) {
					int t1=all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value= all_client_data[m].value;
					all_client_data[m].value = t2;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}
	/*ocall_get_time_ms(&end);
	printf("o_oblivious_sort_idx2 Execution time: %f ms\n", end - start);*/
	//printf("o_oblivious_sort_idx2 end...\n");
}
/*
不经意排序  针对二元组&&全局定义的all_client_data   根据index排序
*/
void o_oblivious_sort_idx2_new(int size) {
	//printf("o_oblivious_sort_idx2_new start...size=%d\n",size);
	/*double start = 0, end = 0;
	ocall_get_time_ms(&start);*/

	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].index < all_client_data[m].index;

				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);

				if (cond1 ^ cond2) {
					int t1=all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value= all_client_data[m].value;
					all_client_data[m].value = t2;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}

	/*ocall_get_time_ms(&end);*/
	
	//printf("o_oblivious_sort_idx2 end...\n");
}
/*
不经意排序  针对三元组&&malloc申请的all_client_data  根据no排序
*/
void o_oblivious_sort_idx3(_tuple2 *all_client_data, int size) {
	//printf("o_oblivious_sort_idx3 start...\n");

	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].no < all_client_data[m].no;

				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
				//o_swap((cond1 ^ cond2), &all_client_data[l].no, &all_client_data[m].no);

				if (cond1 ^ cond2) {
					int t1 = all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value = all_client_data[m].value;
					all_client_data[m].value = t2;

					t1 = all_client_data[l].no;
					all_client_data[l].no = all_client_data[m].no;
					all_client_data[m].no = t1;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}
	//printf("o_oblivious_sort_idx3 end...\n");
}

/*
不经意排序  针对三元组&&全局定义的all_client_data 根据no排序
*/
void o_oblivious_sort_idx3_new(int size) {
	/*double start = 0, end = 0;
	ocall_get_time_ms(&start);*/
	//printf("o_oblivious_sort_idx3 start...\n");
	int half_size = size >> 1;
	int i = 2;
	while (i <= size) {
		int j = i >> 1;
		while (j > 0) {
			int ml = j - 1;
			int mh = ~ml;
			for (int k = 0; k < half_size; k++) {
				int l = ((k & mh) << 1) | (k & ml);
				int m = l + j;
				int cond1 = cond1 = (l & i) == 0;
				int cond2 = all_client_data[l].no < all_client_data[m].no;

				//o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
				//o_swap((cond1 ^ cond2), &all_client_data[l].no, &all_client_data[m].no);

				if (cond1 ^ cond2) {
					int t1 = all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value = all_client_data[m].value;
					all_client_data[m].value = t2;

					t1 = all_client_data[l].no;
					all_client_data[l].no = all_client_data[m].no;
					all_client_data[m].no = t1;
				}
			}
			j >>= 1;
		}
		i <<= 1;
	}
	/*ocall_get_time_ms(&end);*/
	
	//printf("o_oblivious_sort_idx3 end...\n");
}

/*
针对二元组的冒泡排序
*/
void bubbleSort(_tuple *all_client_data, int size) {
	for (int i = 0; i < size - 1; i++) {
		for (int j = 0; j < size - i - 1; j++) {
			if (all_client_data[j].index > all_client_data[j + 1].index) {

				int t1 = all_client_data[j].index;
				all_client_data[j].index = all_client_data[j + 1].index;
				all_client_data[j + 1].index = t1;

				float t2 = all_client_data[j].value;
				all_client_data[j].value = all_client_data[j + 1].value;
				all_client_data[j + 1].value = t2;
			}
		}
	}
}

/*
针对三元组或者二元组的冒泡排序  根据index排序
*/
void bubbleSort1_new(int size) {
	for (int i = 0; i < size - 1; i++) {
		for (int j = 0; j < size - i - 1; j++) {
			if (all_client_data[j].index > all_client_data[j + 1].index) {

				int t1 = all_client_data[j].index;
				all_client_data[j].index = all_client_data[j+1].index;
				all_client_data[j+1].index = t1;

				float t2 = all_client_data[j].value;
				all_client_data[j].value = all_client_data[j+1].value;
				all_client_data[j+1].value = t2;

				
			}
		}
	}
}

/*
针对三元组的冒泡排序  根据no排序
*/
void bubbleSort2_new(int size) {
	for (int i = 0; i < size - 1; i++) {
		for (int j = 0; j < size - i - 1; j++) {
			if (all_client_data[j].no > all_client_data[j + 1].no) {

				int t1 = all_client_data[j].index;
				all_client_data[j].index = all_client_data[j + 1].index;
				all_client_data[j + 1].index = t1;

				float t2 = all_client_data[j].value;
				all_client_data[j].value = all_client_data[j + 1].value;
				all_client_data[j + 1].value = t2;

				t1 = all_client_data[j].no;
				all_client_data[j].no = all_client_data[j + 1].no;
				all_client_data[j + 1].no = t1;
			}
		}
	}
}
/*

*/
void quick_sort_by_id(int start, int end) {

    if (start >= end) {
        return;  // 如果数组只有一个元素或为空，直接返回
    }
    
    _tuple2 pivot = all_client_data[start];  // 以第一个元素为基准
    int i = start, j = end;
    while (i < j) {
        while (i < j && all_client_data[j].index >= pivot.index) {
            j--;  // 从右往左找到第一个小于基准的元素
        }
        all_client_data[i].index = all_client_data[j].index;
		all_client_data[i].value = all_client_data[j].value;
        
        while (i < j && all_client_data[i].index <= pivot.index) {
            i++;  // 从左往右找到第一个大于基准的元素
        }
        all_client_data[j].index = all_client_data[i].index;
		all_client_data[j].value = all_client_data[i].value;
    }
    // arr[i] = pivot;  // 将基准放到最终位置
	all_client_data[i].index = pivot.index;
	all_client_data[i].value = pivot.value;
    
    quick_sort_by_id(start, i - 1);  // 对左侧子数组递归排序
    quick_sort_by_id(i + 1, end);  // 对右侧子数组递归排序

}
void quick_sort_by_no(int start, int end) {
    if (start >= end) {
        return;  // 如果数组只有一个元素或为空，直接返回
    }
    
    _tuple2 pivot = all_client_data[start];  // 以第一个元素为基准
    int i = start, j = end;
    while (i < j) {
        while (i < j && all_client_data[j].no >= pivot.no) {
            j--;  // 从右往左找到第一个小于基准的元素
        }
        all_client_data[i].index = all_client_data[j].index;
		all_client_data[i].value = all_client_data[j].value;
		all_client_data[i].no = all_client_data[j].no;
        
        while (i < j && all_client_data[i].no <= pivot.no) {
            i++;  // 从左往右找到第一个大于基准的元素
        }
        all_client_data[j].index = all_client_data[i].index;
		all_client_data[j].value = all_client_data[i].value;
		all_client_data[j].no = all_client_data[i].no;
    }
    // arr[i] = pivot;  // 将基准放到最终位置
	all_client_data[i].index = pivot.index;
	all_client_data[i].value = pivot.value;
	all_client_data[i].no = pivot.no;
    
    quick_sort_by_no(start, i - 1);  // 对左侧子数组递归排序
    quick_sort_by_no(i + 1, end);  // 对右侧子数组递归排序
	
}

void quick_sort_int(int lo,int hi){
	if(lo>=hi){
		return;
	}
	int p=partition_int(lo,hi);
	quick_sort_int(lo,p-1);
	quick_sort_int(p+1,hi);
}
int partition_int(int lo,int hi){
	int i=lo,j=hi+1;
	int v=j_arr[lo];
	while(true){
		while(i<hi&&j_arr[++i]<v);
		while(j>lo&&j_arr[--j]>v);
		if(i>=j){
			break;
		}
		swap_int(i,j);
	}
	swap_int(lo,j);
	return j;
}
void swap_int(int i,int j){
	int t=j_arr[i];
	j_arr[i]=j_arr[j];
	j_arr[j]=t;
}
void quick_sort_float(int lo,int hi){
	if(lo>=hi){
		return;
	}
	int p=partition_float(lo,hi);
	quick_sort_float(lo,p-1);
	quick_sort_float(p+1,hi);
}
int partition_float(int lo,int hi){
	int i=lo,j=hi+1;
	float v=v_arr[lo];
	while(true){
		while(i<hi&&v_arr[++i]<v);
		while(j>lo&&v_arr[--j]>v);
		if(i>=j){
			break;
		}
		swap_float(i,j);
	}
	swap_float(lo,j);
	return j;
}
void swap_float(int i,int j){
	float t=v_arr[i];
	v_arr[i]=v_arr[j];
	v_arr[j]=t;
}
void merge_sort_pair(int lo,int hi){
	if(lo>=hi){
		return;
	}
	int mid=(lo+hi)/2;
	merge_sort_pair(lo,mid);
	merge_sort_pair(mid+1,hi);
	merge(lo,mid,hi);

}
void merge(int lo,int mid,int hi){
	int i=lo,j=mid+1,t=0;
	while(i<=mid&&j<=hi){
		if(pairs[i].value<=pairs[j].value){
			tmp_p[t++]=pairs[i++];
		}else{
			tmp_p[t++]=pairs[j++];
		}
	}
	while(i<=mid){
		tmp_p[t++]=pairs[i++];
	}
	while(j<=hi){
		tmp_p[t++]=pairs[j++];
	}
	for(int i=lo;i<=hi;i++){
		pairs[i]=tmp_p[i-lo];
	}
}
void swap_pair(int i,int j){
	mypair t=pairs[i];
	pairs[i]=pairs[j];
	pairs[j]=t;
}
void getSortPermJ(int size){
	for(int i=0;i<size;i++){
		pairs[i].value=j_arr[i];
		pairs[i].index=i;
	}
	quick_sort_int(0,size-1);
	merge_sort_pair(0,size-1);
	for(int i=0;i<size;i++){
		p_arr[i]=pairs[i].index;
	}
}
void getSortPermB(int size){
	for(int i=0;i<size;i++){
		pairs[i].value=b_arr[i];
		pairs[i].index=i;
	}
	quick_sort_int(0,size-1);
	merge_sort_pair(0,size-1);
	for(int i=0;i<size;i++){
		p_arr[i]=pairs[i].index;
	}
}
void getB(int size){
	b_arr[0]=0;
	for(int i=1;i<size;i++){
		b_arr[i]=j_arr[i]==j_arr[i-1]?1:0;
	}
}
void apply1(int size){
	for(int i=0;i<size;i++){
		v1_arr[i]=v_arr[p_arr[i]];
	}

}
void apply2(int size){
	for(int i=0;i<size;i++){
		v2_arr[i]=v1_arr[p_arr[i]];
	}

}
