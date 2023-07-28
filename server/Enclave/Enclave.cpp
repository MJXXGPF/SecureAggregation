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

using namespace std;
#define SGXSSL_CTR_BITS 128
#define SHIFT_BYTE 8

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef uint8_t sgx_aes_ctr_128bit_key_t[16];
int SGX_AES_BLOCK_SIZE = 16;
void print_hex(const uint8_t *buf, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

template<typename T>
T unpack(const uint8_t* buffer, size_t offset) {
	T value;
	memcpy(&value, buffer + offset, sizeof(T));
	return value;
}

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
typedef struct {
	int index;
	float value;
}_tuple;

extern "C" __declspec(dllexport) int add(int, int);
extern "C" __declspec(dllexport) int ecall_ctr_encrypt_py(const char *raw_data, const char *sgx_ctr_key, uint8_t *p_dst);
void normal_aggregate(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, _tuple *all_client_data);
void baseline(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data);
void baseline_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data);
void advance_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data, int size);
void o_oblivious_sort_idx(_tuple *all_client_data, int size);
void oblivious_sort_idx(_tuple *all_client_data, int size, _tuple ** arr_ptr);
void bubbleSort(_tuple *all_client_data, int size);
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
int add(int a, int b) {
	printf("hello python call dll\n");
	return a + b+1000;
}


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
extern "C" int hello() {
	printf("hello\n");
	return 1;
}

void ecall_hello() {
	
	 
}
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


//_tuple all_client_data[10][100000]; //100 client 10000 params 7.6mb

/**
encode_data：加密的数据
encode_data_size：加密数据的字节数
update_params：待更新的数据数组 大小为d
update_params_size： 大小为d 
client_size: 客户端数量
algo: 聚合算法
*/
void ecall_aggregate(const uint8_t * encode_data, int encode_data_size,float * update_params, int update_params_size, int client_size,int algo) {
	
	

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
	
	int len = n * k + d;
	_tuple *all_client_data = all_client_data = (_tuple*)malloc(sizeof(_tuple)*(len));
	
	
	/*接收数据 解密数据 处理数据作为数组*/
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		ecall_decrypt(encode_data+offset, "1234567812345678", decode_data_per_client, byte_size_per_client);
		
		int offset2 = 0;
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			all_client_data[idx].index= unpack<int>(decode_data_per_client, offset2);
			offset2 += 4;
			all_client_data[idx].value = unpack<float>(decode_data_per_client, offset2);
			offset2 += 4;
			idx++;
		}
		offset += byte_size_per_client;
	}

	/*for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			printf("%d ", all_client_data[i][j].index);
		}
		printf("\n");
	}*/
	

	switch (algo) {
	case 1:  normal_aggregate(update_params, update_params_size, client_size, given_num_of_sparse_parameters, all_client_data); break;
	//case 2:   baseline(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size); break;
	case 2:   baseline_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, all_client_data); break;
	case 3:   advance_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, all_client_data,len); break;
	}
	
	printf("\n");
}

/*聚合算法*/


/*聚合算法1： 非稀疏矩阵或稀疏矩阵 普通聚合*/
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

/*聚合算法2：安全聚合baseline 未使用不经意原语*/
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


extern "C" {
	//flag为true返回y  flag为true返回x
	int64_t o_mov(int64_t flag,int  *x, int *y, int *ret);
	int64_t o_mov_int(int64_t flag, float  *x, float *y, float *ret);
	int64_t o_swap(int64_t flag, int *x, int *y);
}
/*聚合算法3：安全聚合baseline 使用不经意原语*/
void baseline_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data) {
	
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		//printf("client#%d\n", i);
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			int index = all_client_data[idx].index;
			for (int k = 0; k < d; k++) {
				int flag = index == k;
				float x = update_params[k], y = update_params[k]+all_client_data[idx].value,z=-1;
				o_mov_int(flag, &x, &y, &z);
				update_params[k] = z;
				float *tmp = &z;//0611 注释这一行会导致update_params全为0 ？？？	
			}
			idx++;
		}
	}
	
	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}


#define MAX 10000000
/*聚合算法4：安全聚合advance 使用不经意原语*/
void advance_primitive(float * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, _tuple *all_client_data,int size) {
	printf("advance_primitive\n");
	int n = client_size, k = given_num_of_sparse_parameters;
	//1. 插入dummy数据 d个0 （0.0）(1.0) (2.0)....(d-1,0)
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
		
		/*
		不使用原语 直接进行赋值操作
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
		}*/

		//以下代码使用原语进行变量赋值
		_tuple t1 = { pre_idx, pre_val };
		_tuple t2 = {MAX, 0.0 };
		_tuple update = { 0,0.0 };
		//o_mov虽然只进行的index的赋值 但是一次会处理8字节 因此value同时也被处理了
		o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index, &update.index);
	
		all_client_data[i - 1].index = update.index;
		all_client_data[i - 1].value = update.value;
		_tuple pre_update = { 0,0.0 };
		t1 = { all_client_data[i].index, all_client_data[i].value};
		t2 = { pre_idx, pre_val + all_client_data[i].value };
		o_mov(pre_idx == all_client_data[i].index, &t1.index, &t2.index,&pre_update.index);
		pre_idx = pre_update.index;
		pre_val = pre_update.value;
	
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;//处理最后一个位置 最后一个位置在循环中处理不到
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	oblivious_sort_idx(all_client_data, size, &all_client_data);//第二次不经意排序
	
	//从区间[0,nk+d-1]中选择前d个元素
	for (int i = 0; i < d; i++) {
		update_params[i] = all_client_data[i].value;
		update_params[i] /= client_size;
	}


}
/**
稀疏率0.001  size=21*3=63   d=21840  nk+d=21903
newLen=32768

稀疏率0.0001  size=2*3=6   d=21840  nk+d=21846
newLen=32768

稀疏率0.3  size=6552*3=19656   d=21840  nk+d=41496
newLen=32768
*/
int pad_max_idx_weight_to_power_of_two(_tuple *all_client_data, int size, _tuple ** arr_ptr) {
	unsigned int power = ceil(log2(size));//寻找第一个>=len的二次幂 后面排序的要求
	int new_size = pow(2, power);
	printf("newLen=%d\n", new_size);
	_tuple *new_arr = (_tuple*)realloc(all_client_data,sizeof(_tuple)*new_size);
	for (int i = size; i < new_size; i++) {
		new_arr[i].index = 0;
		new_arr[i].value = 0.0;
	}
	*arr_ptr = new_arr;
	return new_size - size;
}
void oblivious_sort_idx(_tuple *all_client_data, int size, _tuple ** arr_ptr) {
	int number_of_pads = pad_max_idx_weight_to_power_of_two(all_client_data, size, &all_client_data);
	//bubbleSort(all_client_data, size); 冒泡排序
	o_oblivious_sort_idx(all_client_data, size+ number_of_pads);
	_tuple *tmp = (_tuple*)malloc(size * sizeof(_tuple));
	//删除数组前面为了形成二次幂添加的0
	for (int i = 0; i < size; i++) {
		tmp[i].index = all_client_data[i + number_of_pads].index;
		tmp[i].value = all_client_data[i + number_of_pads].value;
	}
	free(all_client_data);
	*arr_ptr = tmp;//删除0后的新数组赋值给all_client_data

}
void o_oblivious_sort_idx(_tuple *all_client_data,int size) {
	printf("o_oblivious_sort_idx begin...size=%d\n",size);
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
				o_swap((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
				/*
				不使用原语进行变量交换操作
				if (cond1 ^ cond2) {
					int t1=all_client_data[l].index;
					all_client_data[l].index = all_client_data[m].index;
					all_client_data[m].index = t1;

					float t2 = all_client_data[l].value;
					all_client_data[l].value= all_client_data[m].value;
					all_client_data[m].value = t2;
				}*/
			}
			j >>= 1;
		}
		i <<= 1;
	}
}

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