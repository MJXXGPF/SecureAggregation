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
#define ASCENDING true

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
	int index;
	double value;
}_tuple;




//基础算法  二重循环遍历 累加  不使用不经意原语
void baseline(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters,int d);
//基础算法  二重循环遍历 累加  使用不经意原语
void baseline_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d);
//olive
void advance_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size,int nk);
//STI
void advance_primitive_proposed(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size,int nk);
//普通聚合 不考虑内存访问模式泄露  稀疏梯度or非稀疏梯度都可聚合
void normal_aggregate(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters);

//对tuple数组(聚合数据)按照index不经意排序
void o_oblivious_sort_tuple_by_index(int size);
//对tuple数组(聚合数据)按照index不经意排序===>具体实现的方法
void oblivious_sort_tuple_by_index(int size);

//tuple数组按照id属性排序===归并排序
void merge_sort_tuple_by_id(int lo,int hi);
void merge_tuple_by_id(int lo,int mid,int hi);


//将tuple数组(聚合数据)大小拓展为2的次幂
int pad_max_idx_weight_to_power_of_two(int size);



//不经意原语函数定义
void o_swap(double* x, double* y, int flag);
float o_mov(int flag, float src, float val);



//bitonic even 算法中的相关函数
void exchange_tuple(int i, int j);
void compare_tuple_index(int i, int j, bool dir);
void bitonicMerge_tuple_by_index(int lo, int n, bool dir);
void bitonicSort_tuple_by_index(int lo, int n, bool dir) ;


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


_tuple *all_client_data;

void exchange(int i, int j);
int greatestPowerOfTwoLessThan(int n);
void compare(int i, int j, bool dir) ;
void bitonicMerge(int lo, int n, bool dir);
void bitonicSort(int lo, int n, bool dir) ;

//====test相关
void test_fix_r_var_d();
void test_fix_d_var_r();
void advance_primitive_test(int nk,int d);
void advance_primitive_proposed_test(int nk,int d);
void test1(int nk,int d);
void test2(int nk,int d);
void test_two_times_bitonic_sort();
void test_4_times_sort_var_d();
void test_two_times_sort_with_d();


//测试ecall调用的函数 可忽略
void ecall_test() {
	//test_fix_r_var_d();
	//test_two_times_bitonic_sort();
	//test_fix_d_var_r();
	//test_fix_r_var_d();
	//test_4_times_sort();
	//test_two_times_sort_with_d();
	test_fix_d_var_r();

	
	 
}

void test_olive_d_var(){
	double r=15;
	int d=10000;

	for(int i=0;i<50;i++){
		int nk=r*d;
		ocall_start_time();
		//advance_primitive_test(nk,d);
		//printf("=========================================\n");
		advance_primitive_proposed_test(nk,d);
		// printf("------------------------------------------------------------\n");
		ocall_end_time();
		ocall_print_time();
		d+=10000;
	}
	
}
void test_4_times_sort_var_d(){
	 double r=15;
	int d=10000;
	for(int i=0;i<50;i++){
		int nk=r*d;
		ocall_start_time();
		bitonicSort_tuple_by_index(0,nk,ASCENDING);
        bitonicSort_tuple_by_index(0,nk,ASCENDING);
        bitonicSort_tuple_by_index(0,nk,ASCENDING);
		bitonicSort_tuple_by_index(0,nk,ASCENDING);
		ocall_end_time();
		ocall_print_time();
		d+=10000;
	}
}
void test_two_times_sort_with_d(){
    double r=15;
	int d=10000;
    for(int i=0;i<50;i++){
		int nk=r*d;
		ocall_start_time();
		//  bitonicSort_tuple_by_index(0,nk+d,ASCENDING);
        //  bitonicSort_tuple_by_no(0,nk+d,ASCENDING);
		oblivious_sort_tuple_by_index(nk+d);
		oblivious_sort_tuple_by_index(nk+d);
		ocall_end_time();
		ocall_print_time();
		d+=10000;
	}

}
void test_fix_r_var_d(){
	double r=0.02;
	int d=10000;
	for(int i=0;i<100;i++){
		int nk=r*d;
		int size=nk;
		ocall_start_time();
		//advance_primitive_test(nk,d);
		advance_primitive_proposed_test(nk,d);
		ocall_end_time();
		ocall_print_time();
		d+=10000;
	}
}
void test_fix_d_var_r(){
	int d=50890;
	double r=0.01;
	for(int i=0;i<200;i++){
		int nk=r*d;
		ocall_start_time();
		//advance_primitive_test(nk,d);
		advance_primitive_proposed_test(nk,d);
		ocall_end_time();
		ocall_print_time();
		if(r==0.01){
			r=0.05;
		}else if(r>=0.05&&r<1){
			r+=0.05;
		}else if(r>=1){
			r+=1;
		}
	}
}
void test_two_times_bitonic_sort(){
	double r=0.02;
	int d=10000;
	for(int i=0;i<100;i++){
		int nk=r*d;
		ocall_start_time();
		printf("nk+d=%d  ",nk+d);
    	oblivious_sort_tuple_by_index(nk+d);
    	oblivious_sort_tuple_by_index(nk+d);
    	ocall_end_time();
    	ocall_print_time();
		d+=10000;
	}
   
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

	//printf("ecall_aggregate....\n");
	ocall_start_time();
    N=2*update_params_size+1;
	double *update_params=(double*)malloc(sizeof(double)*update_params_size);
	for(int i=0;i<update_params_size;i++){
		update_params[i]=_update_params[i];
	}
	int byte_size_per_client = encode_data_size / client_size;
	int given_num_of_sparse_parameters = byte_size_per_client / 8;
	// printf("encode_data_size=%d\n", encode_data_size);
	// printf("client_size=%d\n", client_size);
	// printf("byte_size_per_client=%d\n", byte_size_per_client);
	// printf("given_num_of_sparse_parameters=%d\n", given_num_of_sparse_parameters);
	// printf("update_params_size=%d\n", update_params_size);
	int n = client_size, k = given_num_of_sparse_parameters, d = update_params_size;
	uint8_t * decode_data_per_client = (uint8_t *)malloc(byte_size_per_client);
	int offset = 0;
	int len = -1;
	if (algo == 3)
		len = n * k + d;
	else
		len = n * k;
	//printf("len=%d\n", len);

	if (algo != 4) {
		//algo=4是自己设计的算法  需要使用三元组
		//printf("algo=%d\n", algo);
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
		//printf("algo=%d\n", algo);
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

	switch (algo) {
	case 1:  normal_aggregate(update_params, update_params_size, client_size, given_num_of_sparse_parameters); break;
	case 2:   baseline_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size); break;
	case 3:   advance_primitive(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len,1); break;
	case 4:   advance_primitive_proposed(update_params, update_params_size, client_size, given_num_of_sparse_parameters, update_params_size, len,1); break;
	}
	for(int i=0;i<update_params_size;i++){
		_update_params[i]=update_params[i];
	}
	ocall_end_time();
}


double update_params[50890];



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
				// float *tmp = &z;//0611 不加这一行好像数据有问题？？？ ans: 因为之前的o_mov需要8字节导致
			}
			idx++;
		}
	}

	for (int i = 0; i < update_params_size; i++) {
		update_params[i] /= client_size;
	}
}


//olive论文中的advance算法
void advance_primitive(double  * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size,int nk) {
	int n = client_size, k = given_num_of_sparse_parameters;
	for (int i = nk, idx = 0; i < size; i++) {
		all_client_data[i].index = idx;
		all_client_data[i].value = 0.0;
		idx++;
	}
	oblivious_sort_tuple_by_index(size);
	//quick_sort_tuple_by_id(0,size-1);
	//printf("n=%d size=%d\n",n,size);
	//merge_sort_tuple_by_id(0,size-1);
	//printf("size=%d ",size);
	
	//bitonicSort_tuple_by_index(0,size,ASCENDING);
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length =  size;
	for (int i = 1; i < initialized_parameter_length; i++) {

		int flag = pre_idx == all_client_data[i].index;
		//不使用不经意语言的代码
		// if (flag) {
		// 	all_client_data[i - 1].index = MAX;
		// 	all_client_data[i - 1].value =0.0;
		// 	pre_idx = pre_idx;
		// 	pre_val = pre_val + all_client_data[i].value;
		// }
		// else
		// {
		// 	all_client_data[i - 1].index = pre_idx;
		// 	all_client_data[i - 1].value = pre_val;
		// 	pre_idx = all_client_data[i].index;
		// 	pre_val = all_client_data[i].value;
		// }


		//使用不经意语言的代码
		all_client_data[i - 1].index=o_mov_int(flag,pre_idx,MAX);
		all_client_data[i - 1].value=o_mov_float(flag,pre_val,0.0);
		pre_idx=o_mov_int(flag,all_client_data[i].index,pre_idx);
		pre_val=o_mov_float(flag,all_client_data[i].value,pre_val + all_client_data[i].value);
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	oblivious_sort_tuple_by_index(size);
	//quick_sort_tuple_by_id(0,size-1);
	//merge_sort_tuple_by_id(0,size-1);
	//bitonicSort_tuple_by_index(0,size,ASCENDING);
	for (int i = 0; i < d; i++) {
		update_params[i] = all_client_data[i].value;
		update_params[i] /= client_size;
	}
}


void advance_primitive_test(int nk,int d){
	int size=nk+d;
	for (int i = nk, idx = 0; i < size; i++) {
		all_client_data[i].index = idx;
		all_client_data[i].value = 0.0;
		idx++;
	}
	//printf("nk=%d  d=%d  ",nk,d);
	//oblivious_sort_tuple_by_index(size);
	bitonicSort_tuple_by_index(0,size,ASCENDING);
	int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
	int dummy_idx = MAX;
	int initialized_parameter_length =  size;
	for (int i = 1; i < initialized_parameter_length; i++) {

		int flag = pre_idx == all_client_data[i].index;
		//不使用不经意语言的代码
		// if (flag) {
		// 	all_client_data[i - 1].index = MAX;
		// 	all_client_data[i - 1].value =0.0;
		// 	pre_idx = pre_idx;
		// 	pre_val = pre_val + all_client_data[i].value;
		// }
		// else
		// {
		// 	all_client_data[i - 1].index = pre_idx;
		// 	all_client_data[i - 1].value = pre_val;
		// 	pre_idx = all_client_data[i].index;
		// 	pre_val = all_client_data[i].value;
		// }

		//使用不经意语言的代码
		all_client_data[i - 1].index=o_mov_int(flag,pre_idx,MAX);
		all_client_data[i - 1].value=o_mov_float(flag,pre_val,0.0);
		pre_idx=o_mov_int(flag,all_client_data[i].index,pre_idx);
		pre_val=o_mov_float(flag,all_client_data[i].value,pre_val + all_client_data[i].value);
	}

	all_client_data[initialized_parameter_length - 1].index = pre_idx;
	all_client_data[initialized_parameter_length - 1].value = pre_val;
	//oblivious_sort_tuple_by_index(size);
	//quick_sort_tuple_by_id(0,size-1);
	//merge_sort_tuple_by_id(0,size-1);
	bitonicSort_tuple_by_index(0,size,ASCENDING);
}



//自己设计的算法 使用全局变量 all_client_data
void advance_primitive_proposed(double * update_params, int update_params_size, int client_size, int given_num_of_sparse_parameters, int d, int size,int nk) {
	size=-1;
    if(nk>=2*d){
        size=nk;
    }else{
        size=2*d;
    }
    // unsigned int power = ceil(log2(size));
	// int new_size = pow(2, power);
    // all_client_data=(_tuple*)malloc(sizeof(_tuple)*new_size);
    // padding(size,new_size);
    all_client_data=(_tuple*)malloc(sizeof(_tuple)*size);
    bitonicSort_tuple_by_index(0,size,ASCENDING);
    //oblivious_sort_tuple_by_index(size,new_size-size);
    int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
    int cnt=1;
    for(int i=1;i<size;i++){
        int flag = pre_idx == all_client_data[i].index;
        all_client_data[i - 1].index=o_mov_int(flag,pre_idx,MAX);
		all_client_data[i - 1].value=o_mov_float(flag,pre_val,0.0);
		pre_idx=o_mov_int(flag,all_client_data[i].index,pre_idx);
		pre_val=o_mov_float(flag,all_client_data[i].value,pre_val + all_client_data[i].value);
        cnt=o_mov_int(flag,cnt+1,cnt);
    }
    all_client_data[size - 1].index = pre_idx;
	all_client_data[size - 1].value = pre_val;
    bitonicSort_tuple_by_index(0,size,ASCENDING);
    //oblivious_sort_tuple_by_index(size,new_size-size);
    int repeatId=all_client_data[0].index;
    int repeatIdCnt=1;
    int N=2*d;
    // power = ceil(log2(N));
	// new_size = pow(2, power);
    // padding(N,new_size);

    for(int i=0;i<cnt;i++){
        all_client_data[i].index=all_client_data[i].index*N+1;
    }
    for(int i=cnt;i<d;i++){
        repeatIdCnt++;
        int dummyRead=all_client_data[i].index;
        all_client_data[i].index=repeatId*N+repeatIdCnt;
    }
    for(int i=d;i<2*d;i++){
        if(i==repeatId)
            all_client_data[i].index=all_client_data[i].index*N+repeatIdCnt;
        else    
            all_client_data[i].index=all_client_data[i].index*N+2;
        all_client_data[i].value=0;
    }
	bitonicSort_tuple_by_index(0,2*d,ASCENDING);
    int pre=0;
    int flag=0;
    for(int i=0;i<2*d;i++){
        flag=all_client_data[i].index/N==pre;
        pre=all_client_data[i].index/N;
        if(flag){
            all_client_data[i].index=MAX;
        }else{
            all_client_data[i].index=pre;
        }
    }
    //oblivious_sort_tuple_by_index(N,new_size-N);
    bitonicSort_tuple_by_index(0,2*d,ASCENDING);
	for(int i=0;i<d;i++){
		update_params[i]=all_client_data[i].value;
	}
    free(all_client_data);
}
void advance_primitive_proposed_test(int nk,int d) {
	int size=-1;
    if(nk>=2*d){
        size=nk;
    }else{
        size=2*d;
    }
    // unsigned int power = ceil(log2(size));
	// int new_size = pow(2, power);
    // all_client_data=(_tuple*)malloc(sizeof(_tuple)*new_size);
    // padding(size,new_size);
    all_client_data=(_tuple*)malloc(sizeof(_tuple)*size);
    bitonicSort_tuple_by_index(0,size,ASCENDING);
    //oblivious_sort_tuple_by_index(size,new_size-size);
    int pre_idx = all_client_data[0].index;
	float pre_val = all_client_data[0].value;
    int cnt=1;
    for(int i=1;i<size;i++){
        int flag = pre_idx == all_client_data[i].index;
        all_client_data[i - 1].index=o_mov_int(flag,pre_idx,MAX);
		all_client_data[i - 1].value=o_mov_float(flag,pre_val,0.0);
		pre_idx=o_mov_int(flag,all_client_data[i].index,pre_idx);
		pre_val=o_mov_float(flag,all_client_data[i].value,pre_val + all_client_data[i].value);
        cnt=o_mov_int(flag,cnt+1,cnt);
    }
    all_client_data[size - 1].index = pre_idx;
	all_client_data[size - 1].value = pre_val;
    bitonicSort_tuple_by_index(0,size,ASCENDING);
    //oblivious_sort_tuple_by_index(size,new_size-size);
    int repeatId=all_client_data[0].index;
    int repeatIdCnt=1;
    int N=2*d;
    // power = ceil(log2(N));
	// new_size = pow(2, power);
    // padding(N,new_size);

    for(int i=0;i<cnt;i++){
        all_client_data[i].index=all_client_data[i].index*N+1;
    }
    for(int i=cnt;i<d;i++){
        repeatIdCnt++;
        int dummyRead=all_client_data[i].index;
        all_client_data[i].index=repeatId*N+repeatIdCnt;
    }
    for(int i=d;i<2*d;i++){
        if(i==repeatId)
            all_client_data[i].index=all_client_data[i].index*N+repeatIdCnt;
        else    
            all_client_data[i].index=all_client_data[i].index*N+2;
        all_client_data[i].value=0;
    }
    // for(int i=0;i<cnt;i++){
    //     all_client_data[i].index=all_client_data[i].index*2;
    // }
    // for(int i=cnt;i<d;i++){
    //     int dummyRead=all_client_data[i].index;
    //     all_client_data[i].index=repeatId*2+1;
    //     all_client_data[i].value=0;
    // }
    // for(int i=0;i<d;i++){
    //     all_client_data[i+d].index=i*2+1;
    //     all_client_data[i].value=0;
    // }
    //oblivious_sort_tuple_by_index(N,new_size-N);
    bitonicSort_tuple_by_index(0,2*d,ASCENDING);
    int pre=0;
    int flag=0;
    for(int i=0;i<2*d;i++){
        flag=all_client_data[i].index/N==pre;
        pre=all_client_data[i].index/N;
        if(flag){
            all_client_data[i].index=MAX;
        }else{
            all_client_data[i].index=pre;
        }
    }
    //oblivious_sort_tuple_by_index(N,new_size-N);
    bitonicSort_tuple_by_index(0,2*d,ASCENDING);
    free(all_client_data);
}

//拓展数组大小为2次幂 针对tuple
int pad_max_idx_weight_to_power_of_two(int size) {
	unsigned int power = ceil(log2(size));
	int new_size = pow(2, power);
	printf("size=%d  pow=%d  newSize=%d   ", size,power,new_size);
	for (int i = size; i < new_size; i++) {
		
	    all_client_data[i].index = 0;
		all_client_data[i].value = 0.0;
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
				o_swap_int((cond1 ^ cond2), &all_client_data[l].index, &all_client_data[m].index);
			

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



void quick_sort_tuple_by_id(int start, int end) {

    if (start >= end) {
        return;  // 如果数组只有一个元素或为空，直接返回
    }
    
    _tuple pivot = all_client_data[start];  // 以第一个元素为基准
    int i = start, j = end;
    while (i < j) {
        while (i < j && all_client_data[j].index >= pivot.index) {
            j--;  // 从右往左找到第一个小于基准的元素
        }
        all_client_data[i] = all_client_data[j];
		
        while (i < j && all_client_data[i].index <= pivot.index) {
            i++;  // 从左往右找到第一个大于基准的元素
        }
        all_client_data[j] = all_client_data[i];
    }
    // arr[i] = pivot;  // 将基准放到最终位置
	all_client_data[i] = pivot;
    quick_sort_tuple_by_id(start, i - 1);  // 对左侧子数组递归排序
    quick_sort_tuple_by_id(i + 1, end);  // 对右侧子数组递归排序

}


void exchange_tuple(int i, int j) {
    _tuple t=all_client_data[i];
    all_client_data[i] = all_client_data[j];
    all_client_data[j] = t;
}
void compare_tuple_index(int i, int j, bool dir) {
    if (dir == (all_client_data[i].index > all_client_data[j].index))
        exchange_tuple(i, j);
}
int greatestPowerOfTwoLessThan(int n) {
    int k = 1;
    while (k > 0 && k < n)
        k = k << 1;
    return k >> 1;
}
void bitonicMerge_tuple_by_index(int lo, int n, bool dir) {
    if (n > 1) {
        int m = greatestPowerOfTwoLessThan(n);
        for (int i = lo; i < lo + n - m; i++)
            compare_tuple_index(i, i + m, dir);
        bitonicMerge_tuple_by_index(lo, m, dir);
        bitonicMerge_tuple_by_index(lo + m, n - m, dir);
    }
}

void bitonicSort_tuple_by_index(int lo, int n, bool dir) {
    if (n > 1) {
        int m = n / 2;
        bitonicSort_tuple_by_index(lo, m, !dir);
        bitonicSort_tuple_by_index(lo + m, n - m, dir);
        bitonicMerge_tuple_by_index(lo, n, dir);
    }
}
