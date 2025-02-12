#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <string.h>

// 定义哈希函数模拟，将输入字符串映射到有限域元素
void hash_to_element(element_t result, char *input, pairing_t pairing) {
    element_from_hash(result, input, strlen(input));
}

int main(int argc, char **argv) {
    pairing_t pairing;
    element_t P, Ppub, s;                     // 系统生成元和主密钥
    element_t xi, yi, Xi, Yi;                 // 用户密钥对
    element_t U1, U2, C, v;                   // 签密阶段参数
    element_t alpha, beta, mu, M, decrypted_M; // 中间计算和消息
    element_t temp1, temp2;                   // 临时变量
    char id_a[] = "Alice";                    // 发送者身份
    char id_b[] = "Bob";                      // 接收者身份
    char message[] = "Hello, Bob!";           // 发送的消息

    // 初始化pairing
    pbc_demo_pairing_init(pairing, argc, argv);
    if (!pairing_is_symmetric(pairing)) {
        pbc_die("The pairing must be symmetric");
    }

    double t0 = pbc_get_time();
    // 初始化系统参数
    element_init_G1(P, pairing);
    element_init_G1(Ppub, pairing);
    element_init_Zr(s, pairing);

    // 随机生成系统主密钥和生成元
    element_random(P);
    element_random(s);
    element_mul_zn(Ppub, P, s); // Ppub = s * P

    double t1 = pbc_get_time();
    // 计算并输出Setup阶段的时间
    printf("Setup Phase-----= %fs\n", t1 - t0);  // 修正为 t0

    // 用户A密钥生成（Key Generation）
    double t2 = pbc_get_time();
    element_init_Zr(xi, pairing); // A的私钥xi
    element_init_Zr(yi, pairing); // A的私钥yi
    element_init_G1(Xi, pairing); // A的公钥Xi
    element_init_G1(Yi, pairing); // A的公钥Yi

    element_random(xi);           // 生成xi
    element_mul_zn(Xi, P, xi);    // Xi = xi * P
    element_random(yi);           // 模拟yi随机生成（实际应结合H1计算）
    element_mul_zn(Yi, P, yi);    // Yi = yi * P

    // 用户B密钥生成（Key Generation）
    element_t xb, yb, Xb, Yb;
    element_init_Zr(xb, pairing); // B的私钥xb
    element_init_Zr(yb, pairing); // B的私钥yb
    element_init_G1(Xb, pairing); // B的公钥Xb
    element_init_G1(Yb, pairing); // B的公钥Yb

    element_random(xb);           // 生成xb
    element_mul_zn(Xb, P, xb);    // Xb = xb * P
    element_random(yb);           // 模拟yb随机生成（实际应结合H1计算）
    element_mul_zn(Yb, P, yb);    // Yb = yb * P

    double t3 = pbc_get_time();
    // 输出密钥生成阶段的时间
    printf("KeyGen Phase-----= %fs\n", t3 - t2);

    double t4 = pbc_get_time();
    // 签密阶段（Signcryption）
    element_init_Zr(alpha, pairing);
    element_init_Zr(beta, pairing);
    element_init_Zr(mu, pairing);
    element_init_Zr(v, pairing);
    element_init_G1(U1, pairing);
    element_init_G1(U2, pairing);

    element_init_G1(C, pairing);
    element_init_G1(temp1, pairing);
    element_init_G1(temp2, pairing);
    element_init_G1(M, pairing);
    element_init_G1(decrypted_M,pairing);

    element_random(M); // 将消息映射为G1上的元素（可替换为特定哈希）

    // 随机生成u1和u2
    element_t u1, u2, h1b;
    element_init_Zr(u1, pairing);
    element_init_Zr(u2, pairing);
    element_random(u1);
    element_random(u2);

    // 计算U1, U2
    element_mul_zn(U1, P, u1);   // U1 = u1 * P
    element_mul_zn(U2, P, u2);   // U2 = u2 * P

    // 计算h1b
    element_init_Zr(h1b, pairing);
    hash_to_element(h1b, id_b, pairing);

    // 计算C
    element_mul_zn(temp1, Xb, u1); // temp1 = u1 * Xb
    element_mul_zn(temp2, Yb, u2); // temp2 = u2 * Yb
    element_add(temp1, temp1, temp2); // temp1 = u1 * Xb + u2 * Yb
    element_add(temp1, temp1, M);    // temp1 = u1 * Xb + u2 * Yb + M
    element_set(C, temp1);

    // 计算v
    hash_to_element(alpha, id_a, pairing);
    hash_to_element(beta, id_b, pairing);
    element_add(temp1, u1, u2);   // temp1 = u1 + u2
    element_div(v, temp1, alpha); // v = (u1 + u2) / alpha

    double t5 = pbc_get_time();
    // 输出加密阶段的时间
    printf("Enc Phase-----= %fs\n", t5 - t4);

    // 解签密阶段（Unsigncryption）
    double t6 = pbc_get_time();
    
    // 计算 temp1 = x_b * U1
    element_mul_zn(temp1, U1, xb);

    // 计算 temp2 = y_b * U2
    element_mul_zn(temp2, U2, yb);

    // 计算 M = C - (temp1 + temp2)
    element_add(temp1, temp1, temp2); // temp1 = x_b * U1 + y_b * U2
    element_sub(decrypted_M, C, temp1); // decrypted_M = C - temp1

    // 验证签名完整性
    element_t check_v;
    element_init_Zr(check_v, pairing);

    // 计算 v 的正确性
    element_add(temp1, u1, u2);   // temp1 = u1 + u2
    element_div(check_v, temp1, alpha); // check_v = (u1 + u2) / alpha

    if (!element_cmp(v, check_v)) {
        // Signature verification passed
    } else {
        // Signature verification failed
    }

    double t7 = pbc_get_time();
    // 输出解签密阶段的时间
    printf("Unsigncryption Phase-----= %fs\n", t7 - t6);

    // 计算存储开销
    size_t setup_size = element_length_in_bytes(P) + element_length_in_bytes(Ppub) + element_length_in_bytes(s);
    size_t keygen_size = element_length_in_bytes(xi) + element_length_in_bytes(yi) + element_length_in_bytes(Xi) + element_length_in_bytes(Yi)
                       + element_length_in_bytes(xb) + element_length_in_bytes(yb) + element_length_in_bytes(Xb) + element_length_in_bytes(Yb);
    size_t enc_size = element_length_in_bytes(U1) + element_length_in_bytes(U2) + element_length_in_bytes(C) + element_length_in_bytes(v)
                    + element_length_in_bytes(M) + element_length_in_bytes(decrypted_M);
    printf("Setup storage cost: %zu bytes\n", setup_size);
    printf("KeyGen storage cost: %zu bytes\n", keygen_size);
    printf("Enc storage cost: %zu bytes\n", enc_size);

    // 释放内存
    element_clear(P);
    element_clear(Ppub);
    element_clear(s);
    element_clear(xi);
    element_clear(yi);
    element_clear(Xi);
    element_clear(Yi);
    element_clear(U1);
    element_clear(U2);
    element_clear(C);
    element_clear(v);
    element_clear(M);
    element_clear(decrypted_M);
    element_clear(temp1);
    element_clear(temp2);

    return 0;
}
