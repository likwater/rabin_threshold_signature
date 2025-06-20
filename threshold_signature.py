from Rabin_IDA import *
from digital_signature import *

if __name__ == '__main__':

    sk, pk = creating_key(2)

    n = 9
    k = 6 
    M, shares = share_secret(sk, n, k)

    # Reconstruct from any k shares
    # 随机选择6个0-8的索引
    idxs = random.sample(range(9), 6)
    subset = [shares[i] for i in idxs]
    recovered_sk = reconstruct_secret(subset, M, idxs)

    msg = b'123'
    sig = signature(2, msg, recovered_sk)
    # print(sig)

    check_result = check(2, sig, pk, msg)
    print(check_result)