from Crypto.Util.number import bytes_to_long, long_to_bytes
import binascii

# Bảng hoán vị PC1
PC1 = [57, 49, 41, 33, 25, 17, 9, 1,
       58, 50, 42, 34, 26, 18, 10, 2,
       59, 51, 43, 35, 27, 19, 11, 3,
       60, 52, 44, 36, 28, 20, 12, 4,
       61, 53, 45, 37, 29, 21, 13, 5,
       62, 54, 46, 38, 30, 22, 14, 6]

# Bảng hoán vị PC2
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Số lần dịch chuyển cho từng vòng
shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def hex_to_bin(key):
    return [int(bit) for bit in bin(int(key, 16))[2:].zfill(64)]

def permute(block, table):
    return [block[x - 1] for x in table]

def generate_subkeys(key):
    key_bin = hex_to_bin(key)
    key_pc1 = permute(key_bin, PC1)

    C = key_pc1[:28]
    D = key_pc1[28:]

    subkeys = []
    
    for shift in shift_schedule:
        C = C[shift:] + C[:shift]
        D = D[shift:] + D[:shift]

        subkey = permute(C + D, PC2)
        subkeys.append(subkey)

    return subkeys

K_hex = '13345799BBCDDFF1'
subkeys = generate_subkeys(K_hex)

for i, k in enumerate(subkeys):
    print(f"Khóa con cho vòng {i + 1}: {k}")