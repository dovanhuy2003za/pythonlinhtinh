import binascii
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Bản tin và khóa dưới dạng hệ thập lục phân
M_hex = '0123456789ABCDEF'
K_hex = '13345799BBCDDFF1'

# Chuyển đổi từ hex sang nhị phân
M = binascii.unhexlify(M_hex)
K = binascii.unhexlify(K_hex)

# Bảng hoán vị IP
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Bảng hoán vị cuối FP
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Bảng hoán vị mở rộng E
E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

# Bảng S-box
S_BOX = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Bảng hoán vị P
P = [16, 7, 20, 21,
     29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2, 8, 24, 14,
     32, 27, 3, 9,
     19, 13, 30, 6,
     22, 11, 4, 25]

# Hàm hoán vị
def permute(block, table):
    return [block[x - 1] for x in table]

# Hàm chuyển đổi từ nhị phân sang thập lục phân
def bin2hex(binary):
    return hex(int(''.join(str(x) for x in binary), 2))[2:].upper()

# Hàm XOR hai chuỗi nhị phân
def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

# Hàm chia khối 64-bit thành 32-bit
def split_half(block):
    return block[:32], block[32:]

# Hàm chuyển đổi từ số nguyên sang chuỗi nhị phân 6-bit
def int2bin(val, bitsize):
    return [int(x) for x in bin(val)[2:].zfill(bitsize)]

# Chuyển đổi khóa thành nhị phân
def hex2bin(key):
    return [int(x) for x in bin(int(key, 16))[2:].zfill(48)[-48:]]

# Chuyển đổi chuỗi nhị phân thành số nguyên
def bin2int(binary):
    return int(''.join(str(x) for x in binary), 2)

# Chuyển đổi chuỗi nhị phân thành khối
def string2block(string):
    return [int(x) for x in bin(int(string, 16))[2:].zfill(64)]

# Chuyển đổi từ khối nhị phân thành chuỗi
def block2string(block):
    return hex(int(''.join(str(x) for x in block), 2))[2:].upper().zfill(16)

# Hàm thực hiện hoán vị mở rộng E
def expansion(block):
    return [block[x - 1] for x in E]

# Hàm áp dụng S-box
def substitution(block):
    sub_blocks = [block[i:i + 6] for i in range(0, len(block), 6)]
    result = []
    for i, sub_block in enumerate(sub_blocks):
        row = bin2int([sub_block[0], sub_block[5]])
        col = bin2int(sub_block[1:5])
        val = S_BOX[i][row][col]
        result.extend(int2bin(val, 4))
    return result

# Hàm áp dụng hoán vị P
def permute_p(block):
    return [block[x - 1] for x in P]

# Khởi tạo bản tin và khóa dưới dạng nhị phân
M_bin = string2block(M_hex)
K_bin = string2block(K_hex)

# Hoán vị khởi tạo IP
M_ip = permute(M_bin, IP)

# Chia khối thành hai nửa 32-bit
L, R = split_half(M_ip)

# Khóa con cho mỗi vòng
sub_keys = [
    '1B02EFFC7072',
    '79AED9DBC9E5',
    '55FC8A8C08B9',
    '72ADD6DB351D',
    '7CEC07EB53A8',
    '63A53E507B2F',
    'EC84B7F618BC',
    'F74DB9460AF4',
    '3B2E8F0560EF',
    '648BD2EAD3DC',
    '635991C80FDF',
    'FAC3EFA7E906',
    'E74EAD67E33A',
    'E2DD0AFA26E5',
    'EDD54D1464A6',
    'BB719E0FBB5A'
]

# Thực hiện 16 vòng lặp của DES
for i in range(16):
    # Hoán vị mở rộng E
    R_exp = expansion(R)
    
    # XOR với khóa con
    K_round = hex2bin(sub_keys[i])
    R_xor = xor(R_exp, K_round)
    
    # Áp dụng S-box
    R_sub = substitution(R_xor)
    
    # Áp dụng hoán vị P
    R_p = permute_p(R_sub)
    
    # XOR với L
    R_new = xor(L, R_p)
    
    # Đổi chỗ L và R
    L = R
    R = R_new
    
    # In kết quả của vòng lặp hiện tại
    print(f"Vòng lặp {i + 1}:E = {R_exp} \n K = {K_round} \n f = {R_xor}\n Sbox = {R_sub} \n Qua P = {R_p}\n L = {L}|| R = {R}")

# Hoán vị cuối FP
pre_output = R + L
cipher_text = permute(pre_output, FP)

# Kết quả cuối cùng
print("Bản tin đã mã hóa:", block2string(cipher_text))
