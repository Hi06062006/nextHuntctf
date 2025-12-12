HuntMe3 – nextHuntCTF

Reverse Engineering – Dynamic Key + XOR + Permutation

📌 Bước 1 — Phân tích hàm kiểm tra chính (FUN_00401367)

Hàm này thực hiện quá trình xác minh flag theo 3 công đoạn:

Độ dài flag phải đúng 53 ký tự

Mỗi ký tự flag được so sánh với giá trị đã giải mã từ:

decoded[i] = ENCRYPTED_DATA[i] XOR DynamicKey[i]


Sau khi giải mã, ký tự không đặt trực tiếp vào vị trí i, mà được hoán vị theo bảng PERM_INDICES.

=> Muốn lấy lại flag thật cần: tạo DynamicKey → XOR → trả về đúng index.

📌 Bước 2 — Phân tích bộ sinh khóa động
🔧 Hàm FUN_004012bc(i)

Sinh 1 byte khóa K[i] cho từng chỉ số i.

Cơ chế:

tạo 3 biến trạng thái 32-bit

lặp từ j = 0 → i

mỗi vòng thực hiện:

cộng hằng số vào trạng thái

cộng j*j vào trạng thái thứ hai

gọi hàm xoay bit FUN_004012a0 lên trạng thái thứ ba

🔧 Hàm FUN_004012a0

Thực hiện:

ROL(state, (j & 7))


→ tức xoay trái 32 bit theo số bit nhỏ (0–7).

🔧 Final key

Sau vòng lặp:

raw = local_c ^ local_10 ^ (local_14 >> (i & 7))
scrambled = (raw & 0xff) ^ ((raw & 0x1f) << 3)
final = scrambled ^ (scrambled >> 5)
return final & 0xff


Đây chính là byte khóa K[i].

📌 Bước 3 — Tổng hợp giải mã

Cho mỗi i từ 0–52:

Tạo khóa K[i]

Tính P = ENCRYPTED_DATA[i] XOR K[i]

Đặt P vào vị trí PERM_INDICES[i] để tái tạo flag thật.

🧠 Toàn bộ code khôi phục flag

(Giữ nguyên đoạn code bạn đưa — mình chỉ format lại cho đẹp)

import struct

# --- 1. Dữ liệu Cố định từ Chương trình ---

# Mảng Chỉ mục Hoán vị (DAT_00402040) - 53 bytes
PERM_INDICES = [
    0x2d, 0x2c, 0x32, 0x14, 0x06, 0x25, 0x0f, 0x03, 0x22, 0x07, 0x2f, 0x23, 0x00, 0x31,
    0x1c, 0x27, 0x10, 0x02, 0x30, 0x0a, 0x2a, 0x16, 0x05, 0x12, 0x1d, 0x01, 0x09, 0x17,
    0x1b, 0x1f, 0x1a, 0x08, 0x0c, 0x24, 0x04, 0x20, 0x2e, 0x34, 0x0b, 0x26, 0x0e, 0x33,
    0x15, 0x1e, 0x19, 0x29, 0x13, 0x11, 0x2b, 0x28, 0x21, 0x0d, 0x18
] # Độ dài: 53

# Mảng Giá trị Mã hóa Đúng (DAT_00402080) - 53 bytes
ENCRYPTED_DATA = [
    0xc7, 0x8e, 0x0b, 0xe5, 0x23, 0x81, 0x18, 0x23, 0x27, 0xed, 0x06, 0xa1, 0x19, 0x30,
    0x38, 0xd0, 0x2e, 0x66, 0xe2, 0x26, 0x6e, 0x23, 0xaa, 0xa1, 0x5d, 0x7d, 0x36, 0xe5,
    0x6c, 0x6d, 0x35, 0xa0, 0x34, 0x0c, 0xf9, 0x84, 0xd7, 0xc9, 0x5e, 0x56, 0xc2, 0xe9,
    0x44, 0xe0, 0x77, 0x7b, 0x20, 0x78, 0x1f, 0xd9, 0x98, 0x85, 0xf5
]

def FUN_004012a0(current_state, count_raw):
    count = count_raw & 0x1F
    mask = 0xFFFFFFFF
    current_state &= mask
    return ((current_state << count) & mask) | (current_state >> (32 - count))

def FUN_004012bc(i):
    mask = 0xFFFFFFFF
    local_c = 0x7a8ab05c
    local_10 = 0x362d12d2
    local_14 = 0x1574b128
    CONST_SHIFT = 0xE868D9FC

    for j in range(i + 1):
        local_c = (local_c + CONST_SHIFT) & mask
        local_10 = (local_10 + j * j) & mask
        local_14 = FUN_004012a0(local_14, j & 7)

    shift_amount = i & 7
    raw = local_c ^ local_10 ^ (local_14 >> shift_amount)
    raw &= mask

    scramble = (raw & 0xff) ^ ((raw & 0x1f) << 3)
    final_key = scramble ^ (scramble >> 5)

    return final_key & 0xFF

FLAG_LENGTH = 53
final_flag = [''] * FLAG_LENGTH

print("Bắt đầu Giải mã...")
for i in range(FLAG_LENGTH):
    K = FUN_004012bc(i)
    E = ENCRYPTED_DATA[i]
    I = PERM_INDICES[i]
    P_val = E ^ K
    final_flag[I] = chr(P_val)

final_flag_str = "".join(final_flag)
print("\n" + "="*50)
print(f"ĐỘ DÀI FLAG ĐÚNG: {len(final_flag_str)}")
print("🎉 THE FINAL FLAG: 🎉")
print(final_flag_str)
print("="*50)

🎉 Kết quả
