import copy
import os
import time
from ctypes import cdll
import numpy as np
import torch
from torch import device
from torch.utils.tensorboard import SummaryWriter
from option import args_parser
from utils import *
from models import MLP, CNNMnist, CNNFashion_Mnist, CNNCifar, MLPPurchase100, ResNetCifar
from proto_client import call_grpc_start, call_grpc_aggregate
from sampling import client_iid
from update import LocalUpdate, diff_weights, l2clipping, update_global_weights


if __name__ == '__main__':
    # parse args
    args = args_parser()
    path_project = os.path.abspath('.')
    logger = SummaryWriter(os.path.join(path_project, 'log'))
    if args.gpu_id:
        torch.cuda.set_device(args.gpu_id)
    device = 'cuda' if args.gpu_id else 'cpu'
    path_project = os.path.abspath('.')
    train_dataset, test_dataset, user_groups, class_labels = get_dataset(
        args, path_project, args.num_of_label_k, args.random_num_label)
    if args.model == 'cnn':
        # Convolutional neural network
        if args.dataset == 'mnist':
            global_model = CNNMnist(args=args)
        elif args.dataset == 'fmnist':
            global_model = CNNFashion_Mnist(args=args)
        elif args.dataset == 'cifar10':
            global_model = CNNCifar(args.num_classes)
        elif args.dataset == 'cifar100':
            global_model = ResNetCifar(args.num_classes)
        else:
            exit('Error: no dataset')

    elif args.model == 'mlp':
        if args.dataset == 'purchase100':
            img_size = train_dataset[0][0].shape
            len_in = 1
            for x in img_size:
                len_in *= x
            global_model = MLPPurchase100(
                dim_in=len_in,
                dim_hidden=64,
                dim_out=args.num_classes)
        else:
            # Multi-layer preceptron
            img_size = train_dataset[0][0].shape
            len_in = 1
            for x in img_size:
                len_in *= x
            global_model = MLP(
                dim_in=len_in,
                dim_hidden=64,
                dim_out=args.num_classes)
    else:
        exit('Error: unrecognized model')

        # Set the model to train and send it to device.
    global_model.to(device)
    global_model.train()
    if args.verbose:
        print(global_model)

    # copy weights
    global_weights = global_model.state_dict()
    print(global_model)
    num_of_params = count_parameters(global_model)
    print("num_of_params: ",num_of_params)
    buffer_names = get_buffer_names(global_model)

    # Training
    train_loss, train_accuracy = [], []
    test_loss_list = []
    print_every = 20  # print training accuracy for each {print_every} epochs
    print("args.sparse_ratio: ",args.sparse_ratio)
    if args.sparse_ratio!=0:
        num_of_sparse_params = int(args.sparse_ratio * num_of_params) # 稀疏聚合
    else:
        num_of_sparse_params = 0


    for epoch in range(args.epochs):
        print(f' | Global Training Round : {epoch + 1} |')
        local_weights_diffs, local_losses = [], []
        global_model.train()
        idxs_users = client_iid(args.frac, args.num_users)
        for idx in idxs_users:
            local_model = LocalUpdate(
                dataset=train_dataset,
                idxs=user_groups[idx],
                logger=logger,
                device=device,
                local_bs=args.local_bs,
                optimizer=args.optimizer,
                lr=args.lr,
                local_ep=args.local_ep,
                momentum=args.momentum,
                verbose=args.verbose)

            w, loss = local_model.update_weights(
                model=copy.deepcopy(global_model), global_round=epoch
            )
            local_weights_diffs.append(diff_weights(global_weights, w))
            print("loss: ", loss)
            local_losses.append(copy.deepcopy(loss))

        encrypted_parameters = []
        for client_id, local_weights_diff in zip(idxs_users, local_weights_diffs):
            # 非稀疏梯度聚合
            if args.sparse_ratio==0:
                #print("dense aggregation...")
                bytes_local_weight = serialize_dense(local_weights_diff, buffer_names, num_of_params)
                # print("len  bytes_local_weight: ",len(bytes_local_weight))
            # 稀疏梯度聚合
            else:
                #print("sparse aggregation...")
                top_k_local_weights_diff, top_k_indices = zero_except_top_k_weights(local_weights_diff, buffer_names,num_of_sparse_params)
                bytes_local_weight = serialize_sparse(top_k_local_weights_diff, buffer_names, top_k_indices)
                #print("len  bytes_local_weight: ", len(bytes_local_weight))
                print(top_k_indices)

            encrypted_local_weight = sgx_encrypt(bytes_local_weight)
            encrypted_parameters.extend(encrypted_local_weight)




        # 调用远程rpc聚合
        print("call rpc...")
        flattend_aggregated_weights, execution_time, secure_sampled_client_ids,_ = call_grpc_aggregate(
            fl_id=1,
            round=epoch,
            encrypted_parameters=encrypted_parameters,
            num_of_parameters=num_of_params, # 所有的参数个数
            num_of_sparse_parameters=num_of_sparse_params,  # 稀疏参数个数
            client_ids=idxs_users,
            aggregation_alg=3, # aggregation_alg=1 普通聚合  aggregation_alg=2 安全聚合
            optimal_num_of_clients=2
        )
        learnable_parameters = get_learnable_parameters(global_weights, buffer_names)
        aggregated_weights = recover_flattened(torch.Tensor(flattend_aggregated_weights), global_weights,learnable_parameters)
        update_global_weights(global_weights, [aggregated_weights])

        # 本地聚合
        #update_global_weights(global_weights, local_weights_diffs)







