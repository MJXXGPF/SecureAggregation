#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Python version: 3.6

import argparse

def args_parser():
    parser = argparse.ArgumentParser()

    # dataset
    parser.add_argument('--dataset', type=str, help='name of dataset mnist or cifar or cifar100',default="mnist")

    # user participation parameters
    parser.add_argument('--epochs', type=int, help="number of rounds of training",default=10)
    parser.add_argument('--frac', type=float, help='the fraction of participating clients for each round',
                        default=0.3)
    parser.add_argument('--num_users', type=int, help='number of users: n',default=10)
    parser.add_argument('--data_dist', type=str, help='IID or non-IID',default="IID")
    parser.add_argument('--num_of_label_k', type=int, help='each client data label number, k (default: None)',
                        default=None)
    parser.add_argument('--random_num_label', action='store_true',
                        help='flag of client has random number of labels, otherwise constant')
    parser.add_argument('--unequal', action='store_true',
                        help='flag of whether to use unequal data splits for non-i.i.d setting')

    # model parameters
    parser.add_argument('--model', type=str, help='model name [mlp, cnn]',default="cnn")
    parser.add_argument('--num_channels', type=int, default=1, help="number of channels of imgs (default: 1)")
    parser.add_argument('--num_classes', type=int, default=10, help="number of classes (default: 10)")
    parser.add_argument('--optimizer', type=str, default='sgd', help="type of optimizer sgd or adam (default: sgd)")

    # Local training parameters
    parser.add_argument('--local_ep', type=int, default=10, help="the number of local epochs: E (default: 10)")
    parser.add_argument('--local_bs', type=int, default=10, help="local batch size: B (default: 32)")
    parser.add_argument('--lr', type=float, default=0.01, help='learning rate (default: 0.01)')
    parser.add_argument('--momentum', type=float, default=0.5, help='SGD momentum (default: 0.5)')

    # 稀疏率 稀疏 or 非稀疏
    parser.add_argument("--sparse_ratio",type=float,default=0.3)
    # parser.add_argument("--sparse_ratio", type=float, default=0.3, help="[normal_dense,secure_dense,normal_sparse,secure_sparse]")
    # Other
    parser.add_argument('--seed', type=int, default=0, help='random seed (default: 0)')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose')
    parser.add_argument('--gpu_id', type=int, default=None,
                        help="To use cuda, set to a specific GPU ID. Default set to use CPU. (default: None)")
    parser.add_argument('--prefix', type=str, default=None, help='prefix of result file')
    parser.add_argument('--local_skip', action='store_true', help='skip local learning')
    args = parser.parse_args()
    return  args
