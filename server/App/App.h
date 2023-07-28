#pragma once
#include <tchar.h>
#include<time.h>
#include<stdio.h>
using namespace std;
#include "sgx_urts.h"
#include "Enclave_u.h"

# define TOKEN_FILENAME   "Enclave.token"
# define ENCLAVE_FILENAME _T("D:\\VisualCode\\SecureAggregation\\x64\\Debug\\Enclave.signed.dll")
int updated;
sgx_enclave_id_t global_eid;
char token_path[MAX_PATH];
sgx_launch_token_t token;
sgx_status_t ret;


