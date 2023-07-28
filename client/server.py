import ctypes
import struct
import time
from concurrent import futures

import utils

LIB = ctypes.cdll.LoadLibrary("D:\\VisualCode\\SecureAggregation\\x64\\Debug\\App.dll")
import grpc
import secure_aggregation_pb2
import secure_aggregation_pb2_grpc


def write_client_data_to_file(encrypted_parameters, round, client_ids):
    for client_id in client_ids:
        print("write...")
        file_name="client"+str(client_id)+"_round"+str(round)+".txt"
        with open(file_name, 'wb') as f:
            f.write(encrypted_parameters)



class AggregatorServicer(secure_aggregation_pb2_grpc.AggregatorServicer):
    def __init__(self):
        self.all_clients=0
        self.all_data=[]
    def Aggregate(self, request, context):
        print("Aggregate...")
        fl_id=request.fl_id
        round=request.round
        encrypted_parameters=request.encrypted_parameters
        num_of_parameters=request.num_of_parameters
        num_of_sparse_parameters=request.num_of_sparse_parameters
        aggregation_alg=request.aggregation_alg
        client_ids=request.client_ids
        optimal_num_of_clients=request.optimal_num_of_clients
        update_params_bytes=(ctypes.c_float * num_of_parameters)()
        #print("num_of_parameters: ",num_of_parameters)
        #print("num_of_sparse_parameters",request.num_of_sparse_parameters)
        #print("len of encrypted_parameters: ",len(encrypted_parameters))
        encrypted_parameters_bytes=bytes(encrypted_parameters)
        #print("len of encrypted_parameters_bytes: ", len(encrypted_parameters_bytes))
        start_time=time.time()
        LIB.aggregate(
            encrypted_parameters_bytes,
            len(encrypted_parameters_bytes),
            update_params_bytes,
            num_of_parameters,
            len(client_ids),
            aggregation_alg
        )
        end_time = time.time()
        print("time cost: ",end_time-start_time)
        update_params=list(update_params_bytes)
        # print(update_params)
        not_zero=0
        for x in update_params:
            if x!=0:
                not_zero+=1
        print("not zero: ",not_zero)
        response = secure_aggregation_pb2.AggregateResponseParameters(
             updated_parameters=update_params,
             execution_time=1.23,
             client_ids=[4,5,6],
             round=2
             )
        return response


    def Start(self, request, context):
        print("Start...")
        # 获取客户端发送的数据
        print("fl_id: ",request.fl_id)
        print("client_ids: ",request.client_ids)
        print("sigma: ",request.sigma)
        print("clipping: ",request.clipping)
        print("alpha: ",request.alpha)
        print("sampling_ratio: ",request.sampling_ratio)
        print("aggregation_alg: ",request.aggregation_alg)
        print("num_of_parameters: ",request.num_of_parameters)
        print("num_of_sparse_parameters: ",request. num_of_sparse_parameters)
        # 向客户端响应数据
        response = secure_aggregation_pb2.StartResponseParameters(fl_id=1, round=2, client_ids=[1, 2, 3])
        return response


def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10), options=[
        ('grpc.max_receive_message_length', 100 * 1024 * 1024),
        ('grpc.max_send_message_length', 100 * 1024 * 1024),
    ])
    secure_aggregation_pb2_grpc.add_AggregatorServicer_to_server(AggregatorServicer(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    server.wait_for_termination()

if __name__ == '__main__':
    serve()


