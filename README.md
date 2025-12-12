# nextHuntctf

HuntMe3 

Bước 1: Phân tích Hàm Kiểm tra Chính (FUN_00401367)

Bước 2: Phân tích Bộ tạo Khóa Động (FUN_004012bc và FUN_004012a0)


Code

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
] # Độ dài: 53

# --- 2. Mô phỏng Hàm FUN_004012a0 (Rotate Left) ---

def FUN_004012a0(current_state, count_raw):
    """
    Tái tạo logic của FUN_004012a0: Left Rotate (ROL) 32-bit.
    """
    # Lấy 5 bit thấp nhất (count & 0x1f)
    count = count_raw & 0x1F
    
    # Thực hiện xoay trái (ROL)
    # ROL(x, n) = (x << n) | (x >> (32 - n))
    
    # Đảm bảo phép toán là 32-bit (unsigned)
    mask = 0xFFFFFFFF
    current_state &= mask
    
    # Xoay trái
    rotated = ((current_state << count) & mask) | (current_state >> (32 - count))
    
    return rotated

# --- 3. Mô phỏng Hàm FUN_004012bc (Dynamic Key Generation) ---

def FUN_004012bc(i):
    """
    Tái tạo logic của FUN_004012bc(param_1 = i) để tạo ra khóa động K[i].
    """
    # Khởi tạo trạng thái ban đầu (32-bit unsigned)
    mask = 0xFFFFFFFF
    local_c = 0x7a8ab05c
    local_10 = 0x362d12d2
    local_14 = 0x1574b128
    
    # Hằng số dịch chuyển (cũng là 32-bit signed/unsigned)
    CONST_SHIFT = 0xE868D9FC # -394541699
    
    # Vòng lặp biến đổi trạng thái
    for j in range(i + 1):
        # State 1: local_c = local_c + 0xe868d9fc;
        local_c = (local_c + CONST_SHIFT) & mask
        
        # State 2: local_10 = local_10 + j * j;
        local_10 = (local_10 + j * j) & mask
        
        # State 3: local_14 = FUN_004012a0(local_14, j & 7);
        local_14 = FUN_004012a0(local_14, j & 7)

    # Tính toán Khóa Thô (Raw Key)
    # uVar1 = local_c ^ local_10 ^ local_14 >> ((byte)param_1 & 7);
    shift_amount = i & 7
    uVar1_raw = local_c ^ local_10 ^ (local_14 >> shift_amount)
    uVar1_raw &= mask # Đảm bảo 32-bit

    # Tinh chỉnh và Thu gọn Khóa (Final Key Reduction)
    
    # uVar1 = uVar1 & 0xff ^ (uVar1 & 0x1f) << 3;
    scramble_1 = (uVar1_raw & 0xFF) ^ ((uVar1_raw & 0x1F) << 3)
    
    # return uVar1 ^ uVar1 >> 5;
    final_key_32bit = scramble_1 ^ (scramble_1 >> 5)
    
    # Trả về byte thấp nhất (Khóa Động K[i])
    return final_key_32bit & 0xFF

# --- 4. Quá trình Giải mã Flag Chính ---

# Khởi tạo mảng Flag (53 ký tự)
FLAG_LENGTH = 53
final_flag = [''] * FLAG_LENGTH

# Lặp qua tất cả 53 ký tự (i = 0 đến 52)
print("Bắt đầu Giải mã...")
for i in range(FLAG_LENGTH):
    
    # 1. Lấy Khóa Động K[i]
    K = FUN_004012bc(i)
    
    # 2. Lấy Dữ liệu Mã hóa Đúng E[i]
    E = ENCRYPTED_DATA[i]
    
    # 3. Lấy Chỉ mục Hoán vị I (vị trí đích)
    I = PERM_INDICES[i]
    
    # 4. Giải mã Ký tự P: P = E ^ K
    P_val = E ^ K
    P_char = chr(P_val)
    
    # 5. Đặt Ký tự P vào vị trí đã Hoán vị I
    final_flag[I] = P_char
    
    # print(f"i={i:02d}, I={I:02d}, E={E:02X}, K={K:02X}, P={P_val:02X} ('{P_char}'): -> Flag[{I}]")

# In ra kết quả
final_flag_str = "".join(final_flag)
print("\n" + "="*50)
print(f"ĐỘ DÀI FLAG ĐÚNG: {len(final_flag_str)}")
print("🎉 THE FINAL FLAG: 🎉")
print(final_flag_str)
print("="*50)
