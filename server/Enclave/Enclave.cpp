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
int N=-1;
#define MAX 10000000


//打印函数 ocall调用
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


//打印16进制的函数
void print_hex(const uint8_t *buf, size_t len) {
	for (size_t i = 0; i < len; ++i) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}


//C实现的类似于python中的struct.unpack函数
template<typename T>
T unpack(const uint8_t* buffer, size_t offset) {
	T value;
	memcpy(&value, buffer + offset, sizeof(T));
	return value;
}



//C实现的类似于python中的struct.pack函数
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
三元组结构定义
no: 排名
index: 维度下标
value: 维度值
*/
typedef struct {
	int no;
	int index;
	double value;
}_tuple;


typedef struct{
	int index;
	float value;
	long long value_ll;
}mypair;


//基础算法  二重循环遍历 累加  不使用不经意原语
void baseline(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters,int d);
//基础算法  二重循环遍历 累加  使用不经意原语
void baseline_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d);
//olive论文中的算法
void advance_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size);
//提出的算法
void advance_primitive_proposed(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size);
//普通聚合 不考虑内存访问模式泄露  稀疏梯度or非稀疏梯度都可聚合
void normal_aggregate(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters);

//对tuple数组(聚合数据)按照index不经意排序
void o_oblivious_sort_tuple_by_index(int size);
//对tuple数组(聚合数据)按照no不经意排序
void o_oblivious_sort_tuple_by_no(int size);
//对tuple数组(聚合数据)按照index不经意排序===>具体实现的方法
void oblivious_sort_tuple_by_index(int size);
//对tuple数组(聚合数据)按照no不经意排序===>具体实现的方法
void oblivious_sort_tuple_by_no(int size);


//将tuple数组(聚合数据)大小拓展为2的次幂
int pad_max_idx_weight_to_power_of_two(int size);
//将mypair数组大小拓展为2的次幂
int pad_max_idx_weight_to_power_of_two_for_mypair(int size);


//获取j_arr排序后的一个排列
void getSortPermJ(int size);
//获取b_arr排序后的一个排列
void getSortPermB(int size);
//获取p_arr排序后的一个排列
void getSortPermP(int size);
//计算b_arr
void getB(int size);
//将某个排列应用于某个数组
void apply(int size);

//mypair数组按照value_ll属性排序===归并排序
void merge_sort_pair_by_value_long(int lo,int hi);
void merge_pair_by_value_long(int lo,int mid,int hi);

//mypair数组按照index属性排序===归并排序
void merge_sort_pair_by_index(int lo,int hi);
void merge_pair_by_index(int lo,int mid,int hi);

//mypair数组按照value_ll属性排序===bitonic排序
void oblivious_sort_mypair_by_value_long(int size);
void o_oblivious_sort_mypair_by_value_long(int size);

//mypair数组按照index属性排序===bitonic排序
void oblivious_sort_mypair_by_index(int size);
void o_oblivious_sort_mypair_by_index(int size);


void o_swap(double* x, double* y, int flag);
void o_swap(long long * x, long long* y, int flag);
void o_swap(mypair * x, mypair * y, int flag);
float o_mov(int flag, float src, float val);



//不经意比较原语
int o_equals(double x,double y){
	int ret=0;
	asm volatile (
        "mov %[n1], %%rax\n"      // 将 num1 加载到 eax 寄存器
        "mov %[n2], %%rbx\n"      // 将 num2 加载到 ebx 寄存器
        "cmp %%rax, %%rbx\n"      // 比较 eax 和 ebx 的值
        "sete %%al\n"             // 如果相等，将 al 寄存器设置为 1
        "movzx %%al, %[res]\n"    // 将 al 寄存器的值扩展到 result 变量
        : [res] "=r" (ret)      // 输出操作数，将结果存储在 result 变量中
        : [n1] "r" (x), [n2] "r" (y)  // 输入操作数，指定 num1 和 num2
        : "rax", "rbx"             // 指定被修改的寄存器
    );
	return ret;
}

//不经意交换原语 需要8字节对齐
void o_swap_double(int flag,double* x, double* y) {
    asm volatile (
        "test %[flag], %[flag] \n\t"   // 测试 flag 变量的值是否为零
        "movq (%[y]), %%r10 \n\t"      // 将 y 指针指向的内存内容加载到 r10 寄存器
        "movq (%[x]), %%r9 \n\t"       // 将 x 指针指向的内存内容加载到 r9 寄存器
        "mov %%r9, %%r11 \n\t"         // 将 r9 寄存器的值复制到 r11 寄存器
        "cmovnz %%r10, %%r9 \n\t"      // 如果 flag 非零，将 r10 寄存器的值移动到 r9 寄存器
        "cmovnz %%r11, %%r10 \n\t"     // 如果 flag 非零，将 r11 寄存器的值移动到 r10 寄存器
        "movq %%r9, (%[x]) \n\t"       // 将 r9 寄存器的值存储到 x 指针指向的内存位置
        "movq %%r10, (%[y]) \n\t"      // 将 r10 寄存器的值存储到 y 指针指向的内存位置
        :
        : [x] "r" (x), [y] "r" (y), [flag] "r" (flag)
        : "r9", "r10", "r11"
    );
}

//不经意交换原语 需要8字节对齐
void o_swap_long( int flag,long long  * x, long long* y) {
    asm volatile (
        "test %[flag], %[flag] \n\t"   // 测试 flag 变量的值是否为零
        "movq (%[y]), %%r10 \n\t"      // 将 y 指针指向的内存内容加载到 r10 寄存器
        "movq (%[x]), %%r9 \n\t"       // 将 x 指针指向的内存内容加载到 r9 寄存器
        "mov %%r9, %%r11 \n\t"         // 将 r9 寄存器的值复制到 r11 寄存器
        "cmovnz %%r10, %%r9 \n\t"      // 如果 flag 非零，将 r10 寄存器的值移动到 r9 寄存器
        "cmovnz %%r11, %%r10 \n\t"     // 如果 flag 非零，将 r11 寄存器的值移动到 r10 寄存器
        "movq %%r9, (%[x]) \n\t"       // 将 r9 寄存器的值存储到 x 指针指向的内存位置
        "movq %%r10, (%[y]) \n\t"      // 将 r10 寄存器的值存储到 y 指针指向的内存位置
        :
        : [x] "r" (x), [y] "r" (y), [flag] "r" (flag)
        : "r9", "r10", "r11"
    );
}

//不经意交换原语 需要8字节对齐
void o_swap_int( int flag, int * x, int * y) {
    asm volatile (
        "test %[flag], %[flag] \n\t"   // 测试 flag 变量的值是否为零
        "movq (%[y]), %%r10 \n\t"      // 将 y 指针指向的内存内容加载到 r10 寄存器
        "movq (%[x]), %%r9 \n\t"       // 将 x 指针指向的内存内容加载到 r9 寄存器
        "mov %%r9, %%r11 \n\t"         // 将 r9 寄存器的值复制到 r11 寄存器
        "cmovnz %%r10, %%r9 \n\t"      // 如果 flag 非零，将 r10 寄存器的值移动到 r9 寄存器
        "cmovnz %%r11, %%r10 \n\t"     // 如果 flag 非零，将 r11 寄存器的值移动到 r10 寄存器
        "movq %%r9, (%[x]) \n\t"       // 将 r9 寄存器的值存储到 x 指针指向的内存位置
        "movq %%r10, (%[y]) \n\t"      // 将 r10 寄存器的值存储到 y 指针指向的内存位置
        :
        : [x] "r" (x), [y] "r" (y), [flag] "r" (flag)
        : "r9", "r10", "r11"
    );
}

//不经意移动原语  flag为1返回val  flag为0返回src
float o_mov_float(int flag, float src, float val) {
    float ret;
    asm volatile (
        "xor %%ecx, %%ecx\n\t"
        "mov %[flag], %%ecx\n\t"
        "test %%ecx, %%ecx\n\t"
        "mov %[src],%[ret]\n\t"
        "cmovnz %[val], %[ret]\n\t"
        : [ret] "=a" (ret)
        : [flag] "r" (flag), [src] "r" (src),[val] "r" (val)
        : "%ecx"
    );

    return ret;
}
//不经意移动原语  flag为1返回val  flag为0返回src
int o_mov_int(int flag, int src,int val) {
    int ret;
    asm volatile (
        "xor %%ecx, %%ecx\n\t"
        "mov %[flag], %%ecx\n\t"
        "test %%ecx, %%ecx\n\t"
        "mov %[src],%[ret]\n\t"
        "cmovnz %[val], %[ret]\n\t"
        : [ret] "=a" (ret)
        : [flag] "r" (flag), [src] "r" (src),[val] "r" (val)
        : "%ecx"
    );

    return ret;
}

//测试ecall调用的函数 可忽略
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

//加密数据
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

//测试ecall调用的函数 可忽略
int add(int a, int b) {
	printf("hello python call dll\n");
	return a + b+1000;
}

//解密
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

//测试ecall调用的函数 可忽略
extern "C" int hello() {
	printf("hello\n");
	return 1;
}


_tuple all_client_data[90000000];
double arr[sz];

//测试ecall调用的函数 可忽略
void ecall_hello() {
    printf("hello in enclave\n");
	 
}

//测试ecall调用的函数 可忽略
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
void ecall_aggregate(const uint8_t * encode_data, int encode_data_size,float * _update_params, int update_params_size, int client_size,int algo) {

	printf("ecall_aggregate....\n");
    N=2*update_params_size+1;
	double *update_params=(double*)malloc(sizeof(double)*update_params_size);
	for(int i=0;i<update_params_size;i++){
		update_params[i]=_update_params[i];
	}
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
	case 1:  normal_aggregate(update_params, update_params_size, client_size, given_num_of_sparse_parameters); break;
	case 2:   baseline_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size); break;
	case 3:   advance_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len); break;
	case 4:   advance_primitive_proposed(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len); break;
	}
	for(int i=0;i<update_params_size;i++){
		_update_params[i]=update_params[i];
	}
	ocall_end_time();
}



//普通聚合 可以应用于稀疏梯度  也可以应用于非稀疏梯度
void normal_aggregate(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters) {

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


//olive论文中的baseline算法(没有使用不经意原语)  二重循环  逐个比较
void baseline(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters,int d) {
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



//olive论文中的baseline算法  添加了不经意原语
void baseline_primitive(double* update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d) {
	printf("baseline_primitive...\n");
	int idx = 0;
	for (int i = 0; i < client_size; i++) {
		for (int j = 0; j < given_num_of_sparse_parameters; j++) {
			int index = all_client_data[idx].index;
			for (int k = 0; k < d; k++) {
				int flag = index == k;
				float x = update_params[k], y = update_params[k] + all_client_data[idx].value, z = -1;
				z=o_mov_float(flag, x, y);

				//普通交换
                // if(flag){
                //     z=y;
                // }else{
                //     z=x;
                // }
				update_params[k] = z;
				// float *tmp = &z;//0611 不加这一行好像数据有问题？？？ ans: 因为之前的mov需要8字节导致
			}
			idx++;
		}
	}

	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}


//olive论文中的advance算法
void advance_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size) {
	int n = client_size, k = given_num_of_sparse_parameters;
	for (int i = n * k, idx = 0; i < size; i++) {
		all_client_data[i].index = idx;
		all_client_data[i].value = 0.0;
		idx++;
	}
	oblivious_sort_tuple_by_index(size);
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length = n * k + d;
	for (int i = 1; i < initialized_parameter_length; i++) {

		int flag = pre_idx == all_client_data[i].index;
		//不使用不经意语言的代码
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


		//使用不经意语言的代码
		// all_client_data[i - 1].index=o_mov_int(flag,pre_idx,MAX);
		// all_client_data[i - 1].value=o_mov_float(flag,pre_val,0.0);
		// pre_idx=o_mov_int(flag,all_client_data[i].index,pre_idx);
		// pre_val=o_mov_float(flag,all_client_data[i].value,pre_val + all_client_data[i].value);
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	oblivious_sort_tuple_by_no(size);
	for (int i = 0; i < d; i++) {
		update_params[i] = all_client_data[i].value;
		update_params[i] /= client_size;
	}
}


long long p_arr[2*600000];
long long b_arr[2*600000];
long long j_arr[2*600000];
long long t_arr[2*600000];
float v_arr[2*600000];
mypair pairs[2*600000];
mypair tmp_p[2*600000];





//拓展数组大小为2次幂 针对tuple
int pad_max_idx_weight_to_power_of_two(int size) {
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	//printf("newSize=%d\n", new_size);
	for (int i = size; i < new_size; i++) {
		all_client_data[i].no = 0;
		all_client_data[i].index = 0;
		all_client_data[i].value = 0.0;
	}
	return new_size - size;
}

//拓展数组大小为2次幂 针对mypair
int pad_max_idx_weight_to_power_of_two_for_mypair(int size) {
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	//printf("newSize=%d\n", new_size);
	for (int i = size; i < new_size; i++) {
		pairs[i].index = -1;
		pairs[i].value=-1;
		pairs[i].value_ll=-1;
	}
	return new_size - size;
}


//根据index排序排序tuple类型的all_client_data
void oblivious_sort_tuple_by_index(int size) {
	int number_of_pads = pad_max_idx_weight_to_power_of_two(size);
	o_oblivious_sort_tuple_by_index(size + number_of_pads);
	//[1:number_of_pads]数据为0   [number_of_pads+1,size+number_of_pads]为真实数据
	for (int i = 0; i < size; i++) {
		//将真实数据移动到all_client_data数组前面
		all_client_data[i]=all_client_data[i+number_of_pads];
	}
}



//根据no排序排序tuple类型的all_client_data
void oblivious_sort_tuple_by_no(int size) {
	int number_of_pads = pad_max_idx_weight_to_power_of_two(size);
	o_oblivious_sort_tuple_by_no(size + number_of_pads);
	for (int i = 0; i < size; i++) {
		all_client_data[i]=all_client_data[i+number_of_pads];
	}
}


//根据index排序排序tuple类型的all_client_data
void o_oblivious_sort_tuple_by_index(int size) {
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
				//no(4 byte) index(4 byte)  value(8 byte)
				o_swap_int((cond1 ^ cond2), &all_client_data[l].no, &all_client_data[m].no);
				o_swap_double((cond1 ^ cond2), &all_client_data[l].value, &all_client_data[m].value);


				//普通交换代码
				// if (cond1 ^ cond2) {
				// 	_tuple tmp=all_client_data[l];
				// 	all_client_data[l]=all_client_data[m];
				// 	all_client_data[m]=tmp;
				// }
			}
			j >>= 1;
		}
		i <<= 1;
	}
}

//根据no排序排序tuple类型的all_client_data
void o_oblivious_sort_tuple_by_no(int size) {
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

				//no(4 byte) index(4 byte)  value(8 byte)
				o_swap_int((cond1 ^ cond2), &all_client_data[l].no, &all_client_data[m].no);
				o_swap_double((cond1 ^ cond2), &all_client_data[l].value, &all_client_data[m].value);

				//普通交换代码
				// if (cond1 ^ cond2) {
				// 	_tuple tmp=all_client_data[l];
				// 	all_client_data[l]=all_client_data[m];
				// 	all_client_data[m]=tmp;
				// }
			}
			j >>= 1;
		}
		i <<= 1;
	}
}



//mypair数组归并排序===按照value排序
void merge_sort_pair_by_value_long(int lo,int hi){
	if(lo>=hi){
		return;
	}
	int mid=(lo+hi)/2;
	merge_sort_pair_by_value_long(lo,mid);
	merge_sort_pair_by_value_long(mid+1,hi);
	merge_pair_by_value_long(lo,mid,hi);

}
void merge_pair_by_value_long(int lo,int mid,int hi){
	int i=lo,j=mid+1,t=0;
	while(i<=mid&&j<=hi){
		if(pairs[i].index<=pairs[j].index){
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

//mypair数组归并排序===按照index排序
void merge_sort_pair_by_index(int lo,int hi){
	if(lo>=hi){
		return;
	}
	int mid=(lo+hi)/2;
	merge_sort_pair_by_index(lo,mid);
	merge_sort_pair_by_index(mid+1,hi);
	merge_pair_by_index(lo,mid,hi);

}
void merge_pair_by_index(int lo,int mid,int hi){
	int i=lo,j=mid+1,t=0;
	while(i<=mid&&j<=hi){
		if(pairs[i].index<=pairs[j].index){
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



//mypair数组不经意排序===根据value
void oblivious_sort_mypair_by_value_long(int size) {
	int number_of_pads = pad_max_idx_weight_to_power_of_two_for_mypair(size);
	o_oblivious_sort_mypair_by_value_long(size + number_of_pads);
	//[1:number_of_pads]数据为0   [number_of_pads+1,size+number_of_pads]为真实数据
	for (int i = 0; i < size; i++) {
		//将真实数据移动到mypair数组前面
		pairs[i]=pairs[i+number_of_pads];
		
	}
}

//不经意排序  针对数组pairs===根据value
void o_oblivious_sort_mypair_by_value_long(int size) {
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
				int cond2 = pairs[l].value_ll <pairs[m].value_ll;

				//【index(4 byte)  value(4 byte)】  value_ll(8 byte) 
				o_swap_int((cond1 ^ cond2), &pairs[l].index, &pairs[m].index);
				o_swap_long((cond1 ^ cond2), &pairs[l].value_ll,&pairs[m].value_ll);

				//不使用原语进行交换
				// if (cond1 ^ cond2) {
				// 	 mypair tmp=pairs[l];
				// 	 pairs[l]=pairs[m];
				// 	 pairs[m]=tmp;
				// }
			}
			j >>= 1;
		}
		i <<= 1;
	}
}

//mypair数组不经意排序===根据index
void oblivious_sort_mypair_by_index(int size) {
	int number_of_pads = pad_max_idx_weight_to_power_of_two_for_mypair(size);
	o_oblivious_sort_mypair_by_index(size + number_of_pads);
	//[1:number_of_pads]数据为0   [number_of_pads+1,size+number_of_pads]为真实数据
	for (int i = 0; i < size; i++) {
		//将真实数据移动到mypair数组前面
		pairs[i]=pairs[i+number_of_pads];
		
	}
}

//不经意排序  针对数组pairs===根据index
void o_oblivious_sort_mypair_by_index(int size) {
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
				int cond2 = pairs[l].index <pairs[m].index;

				//【index(4 byte)  value(4 byte)】   value_ll(8 byte) 
				o_swap_int((cond1 ^ cond2), &pairs[l].index, &pairs[m].index);
				o_swap_long((cond1 ^ cond2), &pairs[l].value_ll,&pairs[m].value_ll);

				//不使用原语进行交换
				// if (cond1 ^ cond2) {
				// 	 mypair tmp=pairs[l];
				// 	 pairs[l]=pairs[m];
				// 	 pairs[m]=tmp;
				// }
			}
			j >>= 1;
		}
		i <<= 1;
	}
}
void getSortPermJ(int size){
	for(int i=0;i<size;i++){
		pairs[i].value_ll=j_arr[i]*N+i;
		pairs[i].index=i;
	}
	//merge_sort_pair(0,size-1);
	oblivious_sort_mypair_by_value_long(size);
	for(int i=0;i<size;i++){
		p_arr[i]=pairs[i].index;
		j_arr[i]=(pairs[i].value_ll-pairs[i].index)/N;//恢复j[i]的原始值
	}
}
void getSortPermB(int size){
	for(int i=0;i<size;i++){
		pairs[i].value_ll=b_arr[i]*N+i;
		pairs[i].index=i;
	}
	//merge_sort_pair(0,size-1);
	oblivious_sort_mypair_by_value_long(size);
	for(int i=0;i<size;i++){
		p_arr[i]=pairs[i].index;
	}
}

void getSortPermP(int size){
	for(int i=0;i<size;i++){
		pairs[i].index=i;
		pairs[i].value_ll=p_arr[i];
	}
	//merge_sort_pair(0,size-1);
	oblivious_sort_mypair_by_value_long(size);
	for(int i=0;i<size;i++){
		t_arr[i]=pairs[i].index;
	}
}
void getB(int size){
	b_arr[0]=0;
	for(int i=1;i<size;i++){
		b_arr[i]=j_arr[i]==j_arr[i-1]?1:0;
	}
}

void  apply(int size){
	getSortPermP(size);
	for(int i=0;i<size;i++){//attach操作 attach t and v
		//将t v数组组成一个pair数组
		pairs[i].index=t_arr[i];
		pairs[i].value=v_arr[i];
	}
	oblivious_sort_mypair_by_index(size);
	for(int i=0;i<size;i++){
		v_arr[i]=pairs[i].value;
	}
	
}
