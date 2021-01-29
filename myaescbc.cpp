#include "myaescbc.h"

MyAesCBC::MyAesCBC()
{

}

MyAesCBC::MyAesCBC(int keySize, unsigned char *keyBytes)
{
    SetNbNkNr(keySize); // 设置密钥块数, 轮数
    memcpy(key,keyBytes,keySize); // 字符串拷贝函数, 把keybytes的keySize字节复制到key中
    KeyExpansion(); // 密钥扩展, 必须提前做的初始化
}

MyAesCBC::~MyAesCBC()
{

}

DWORD MyAesCBC::OnAesEncrypt(QByteArray InBuffer, DWORD InLength, QByteArray &OutBuffer)
{
    DWORD OutLength = 0; // 加密数据长度
    long blocknum = InLength / 16; // 原始数据可分为blocknum个16字节的数据块
    long leftnum = InLength % 16; // 最后多出的leftnum个字节

    for (long i = 0; i < blocknum; i++) // 块加密
    {
        QByteArray inbuff = InBuffer.mid(16 * i, 16); // 将原始数据分成16字节的块进行加密
        Cipher(inbuff, OutBuffer); // 数据块加密
        OutLength += 16;
    }

    if (leftnum) // 多出leftnum字节, 则加密后多出16 - leftnum个字节
    {
        // 加密最后几个字节
        QByteArray inbuff = InBuffer.right(leftnum);
        inbuff = inbuff.leftJustified(16, '\0'); // 不足16为, 补'\0'
        Cipher(inbuff, OutBuffer);
        OutLength += 16;
    }

    // 新增16字节, 用以确定增加的字节数
    int extranum = 16 + (16 - leftnum) % 16; // 多出16+(16-leftnum)%16个字节
    QByteArray extrabuff;
    extrabuff.setNum(extranum);
    extrabuff = extrabuff.leftJustified(16, '\0'); // 补足16位
    Cipher(extrabuff, OutBuffer);
    OutLength += 16;
    return OutLength;
}

DWORD MyAesCBC::OnAesUncrypt(QByteArray InBuffer, DWORD InLength, QByteArray &OutBuffer)
{
    DWORD OutLength = 0; // 解密后的数据长度
    long blocknum = InLength / 16;
    long leftnum = InLength % 16;

    if (leftnum)
    {
        return 0;
    }

    for(long i = 0; i < blocknum; i++)
    {
        QByteArray inbuff = InBuffer.mid(16 * i, 16); // ?? 16 ?????????
        InvCipher(inbuff, OutBuffer); // ????
        OutLength += 16;
    }

    // 最后16个字节确定了增加的字节数, 解密后需要去掉增加的字节
    QByteArray extrabuff = OutBuffer.right(16); // 取最后16个字节
    int extranum = extrabuff.toInt();
    OutBuffer.chop(extranum); // 去掉填充和添加的字节
    DWORD dwExtraBytes = OutLength - extranum; // 解密后的真实数据长度
    return dwExtraBytes;
}

void MyAesCBC::Cipher(QByteArray input, QByteArray &output)
{
    // 加密函数
    memset(&State[0][0], 0, 16);
    for (int i = 0; i < 4 * Nb; i++) // 这里是先写列后写行, 即输入时一列一列进来的
    {
        State[i % 4][i / 4] = input[i]; // 换成险些行后写列也可, 只需要输出保持一致
    }

    AddRoundKey(0); // 轮密钥加

    for (int round = 1; round <= (Nr - 1); round++) // main round loop
    {
        SubBytes();         // 字节替换
        ShiftRows();        // 行移位
        MixColumns();       // 列混淆
        AddRoundKey(round); // 轮密钥加
    }

    SubBytes();      // 字节替换
    ShiftRows();     // 行移位
    AddRoundKey(Nr); // 轮密钥加

    // output += state
    for (int i = 0; i < (4 * Nb); i++)
    {
        output.append(State[i % 4][i / 4]);
    }
}

void MyAesCBC::InvCipher(QByteArray input, QByteArray &output)
{
    // 解密函数
    memset(&State[0][0], 0, 16);
    for (int i = 0; i < (4 * Nb); i++)
    {
        State[i % 4][ i / 4] = input[i];
    }

    AddRoundKey(Nr);

    for (int round = Nr-1; round >= 1; round--) // main round loop
    {
        InvShiftRows();
        InvSubBytes();
        AddRoundKey(round);
        InvMixColumns();
    }

    InvShiftRows();
    InvSubBytes();
    AddRoundKey(0);

    // output += state
    for (int i = 0; i < (4 * Nb); i++)
    {
        output.append(State[i % 4][i / 4]);
    }
}

void MyAesCBC::SetNbNkNr(int keySize)
{
    Nb=4;
    if (keySize == Bits128)
    {
        Nk=4; // 4*4字节, 128位密钥, 10轮加密
        Nr=10;
    }
    else if (keySize == Bits192)
    {
        Nk=6; // 6*4字节, 192位密钥, 12轮加密
        Nr=12;
    }
    else if (keySize == Bits256)
    {
        Nk=8; // 8*4字节, 256位密钥, 14轮加密
        Nr=14;
    }
}

void MyAesCBC::AddRoundKey(int round)
{
    // 轮密钥加
    int i,j; //i行 j列 因为密钥是一列一列排列的, 即 k0 k4 k8  k12
    for(j = 0; j < 4; j++)                 // k1 k5 k9  k13
    {                                      // k2 k6 k10 k14
        for(i = 0; i < 4; i++)             // k3 k7 k11 k15
        {                         // 所以i行j列的下标是 4*((round*4)+j)+i, 即 16*round+4*j+i
            State[i][j] = (unsigned char)((int)State[i][j] ^ (int)w[4 * ((round * 4) + j) + i]);
        }
    }
}

void MyAesCBC::SubBytes()
{
    // 字节替换
    int i,j;
    for (j = 0; j < 4; j++)
    {
        for (i = 0; i < 4; i++)
        {
            State[i][j] = AesSbox[State[i][j]]; // 因为 16*(State[i][j]>>4)+State[i][j]&0x0f=State[i][j]
        }
    }
}

void MyAesCBC::InvSubBytes()
{
    int i,j;
    for (j = 0; j < 4; j++)
    {
        for (i = 0; i < 4; i++)
        {
            State[i][j] = AesiSbox[State[i][j]]; // 因为 16*(State[i][j]>>4)+State[i][j]&0x0f=State[i][j]
        }
    }
}

void MyAesCBC::ShiftRows()
{
    unsigned char temp[4 * 4];
    int i,j;
    for (j = 0; j < 4; j++)
    {
        for(i = 0; i < 4; i++)
        {
            temp[4 * i + j] = State[i][j];
        }
    }
    for (i = 1; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            if (i == 1)
                State[i][j] = temp[4 * i + (j + 1) % 4]; // 第一行左移1位
            else if (i == 2)
                State[i][j] = temp[4 * i + (j + 2) % 4]; // 第二行左移2位
            else if (i == 3)
                State[i][j] = temp[4 * i + (j + 3) % 4]; // 第三行左移3位
        }
    }
}

void MyAesCBC::InvShiftRows()
{
    unsigned char temp[4 * 4];
    int i, j;
    for (j = 0; j < 4; j++)
    {
        for(i = 0; i < 4; i++)
        {
            temp[4 * i + j] = State[i][j];
        }
    }
    for (i = 1; i < 4; i++)
    {
        for (j = 0; j < 4; j++)
        {
            if (i == 1)
                State[i][j] = temp[4 * i + (j + 3) % 4]; // 第一行右移1位 j-1+4=j+3
            else if (i == 2)
                State[i][j] = temp[4 * i + (j + 2) % 4]; // 第二行右移2位 j-2+4=j+2
            else if (i == 3)
                State[i][j] = temp[4 * i + (j + 1) % 4]; // 第三行右移3位 j-3+4=j+2
        }
    }
}

void MyAesCBC::MixColumns()
{
    unsigned char temp[4 * 4];
    int i, j;
    for (j = 0; j < 4; j++)               // 2 3 1 1 列混淆矩阵
    {                                     // 1 2 3 1
        for (i = 0; i < 4; i++)           // 1 1 2 3
        {                                 // 3 1 1 2
            temp[4 * i + j] = State[i][j];
        }
    }
    for (j = 0; j < 4; j++)
    {
        State[0][j] = (unsigned char) ( (int)gfmultby02(temp[0 + j]) ^ (int)gfmultby03(temp[4 * 1 + j]) ^
                (int)gfmultby01(temp[4 * 2 + j]) ^ (int)gfmultby01(temp[4 * 3 + j]) );
        State[1][j] = (unsigned char) ( (int)gfmultby01(temp[0 + j]) ^ (int)gfmultby02(temp[4 * 1 + j]) ^
                (int)gfmultby03(temp[4 * 2 + j]) ^ (int)gfmultby01(temp[4 * 3 + j]) );
        State[2][j] = (unsigned char) ( (int)gfmultby01(temp[0 + j]) ^ (int)gfmultby01(temp[4 * 1 + j]) ^
                (int)gfmultby02(temp[4 * 2 + j]) ^ (int)gfmultby03(temp[4 * 3 + j]) );
        State[3][j] = (unsigned char) ( (int)gfmultby03(temp[0 + j]) ^ (int)gfmultby01(temp[4 * 1 + j]) ^
                (int)gfmultby01(temp[4 * 2 + j]) ^ (int)gfmultby02(temp[4 * 3 + j]) );
    }
}

void MyAesCBC::InvMixColumns()
{
    unsigned char temp[4 * 4];
    int i, j;
    for (i = 0; i < 4; i++)
    {
        for (j = 0; j < 4; j++)            // 0e 0b 0d 09 逆变换矩阵
        {                                  // 09 0e 0b 0d
            temp[4 * i + j] = State[i][j]; // 0d 09 0e 0b
        }                                  // 0b 0d 09 0e
    }

    for (j = 0; j < 4; j++)
    {
        State[0][j] = (unsigned char) ( (int)gfmultby0e(temp[j]) ^ (int)gfmultby0b(temp[4 + j]) ^
                                        (int)gfmultby0d(temp[4 * 2 + j]) ^ (int)gfmultby09(temp[4 * 3 + j]) );
        State[1][j] = (unsigned char) ( (int)gfmultby09(temp[j]) ^ (int)gfmultby0e(temp[4 + j]) ^
                                        (int)gfmultby0b(temp[4 * 2 + j]) ^ (int)gfmultby0d(temp[4 * 3 + j]) );
        State[2][j] = (unsigned char) ( (int)gfmultby0d(temp[j]) ^ (int)gfmultby09(temp[4 + j]) ^
                                        (int)gfmultby0e(temp[4 * 2 + j]) ^ (int)gfmultby0b(temp[4 * 3 + j]) );
        State[3][j] = (unsigned char) ( (int)gfmultby0b(temp[j]) ^ (int)gfmultby0d(temp[4 + j]) ^
                                        (int)gfmultby09(temp[4 * 2 + j]) ^ (int)gfmultby0e(temp[4 * 3 + j]) );
    }
}

unsigned char MyAesCBC::gfmultby01(unsigned char b)
{
    return b;
}

unsigned char MyAesCBC::gfmultby02(unsigned char b)
{
    if (b < 0x80)
        return (unsigned char)(int)(b <<1);
    else
        return (unsigned char)( (int)(b << 1) ^ (int)(0x1b) );
}

unsigned char MyAesCBC::gfmultby03(unsigned char b)
{
    return (unsigned char) ( (int)gfmultby02(b) ^ (int)b );
}

unsigned char MyAesCBC::gfmultby09(unsigned char b)
{
    return (unsigned char)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^ (int)b );
}

unsigned char MyAesCBC::gfmultby0b(unsigned char b)
{
    return (unsigned char)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                            (int)gfmultby02(b) ^ (int)b );
}

unsigned char MyAesCBC::gfmultby0d(unsigned char b)
{
    return (unsigned char)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                            (int)gfmultby02(gfmultby02(b)) ^ (int)(b) );
}

unsigned char MyAesCBC::gfmultby0e(unsigned char b)
{
    return (unsigned char)( (int)gfmultby02(gfmultby02(gfmultby02(b))) ^
                            (int)gfmultby02(gfmultby02(b)) ^(int)gfmultby02(b) );
}

void MyAesCBC::KeyExpansion()
{
    memset(w, 0 , 16 * 15);
    for (int row = 0; row < Nk; row++) // 拷贝seed密钥
    {
        w[4 * row + 0] = key[4 * row];
        w[4 * row + 1] = key[4 * row + 1];
        w[4 * row + 2] = key[4  *row + 2];
        w[4 * row + 3] = key[4 * row + 3];
    }
    byte *temp = new byte[4];
    for (int row = Nk; row < 4 * (Nr + 1); row++)
    {
        temp[0] = w[4 * row - 4]; // 当前列的前一列
        temp[1] = w[4 * row - 3];
        temp[2] = w[4 * row - 2];
        temp[3] = w[4 * row - 1];
        if (row % Nk == 0) // 逢nk时, 对当前列的前一列做特殊处理
        {
            temp = SubWord(RotWord(temp)); // 先移位, 再替换, 最后与论常量异或
            temp[0] = (byte)( (int)temp[0] ^ (int) AesRcon[4 * (row / Nk) + 0] );
            temp[1] = (byte)( (int)temp[1] ^ (int) AesRcon[4 * (row / Nk) + 1] );
            temp[2] = (byte)( (int)temp[2] ^ (int) AesRcon[4 * (row / Nk) + 2] );
            temp[3] = (byte)( (int)temp[3] ^ (int) AesRcon[4 * (row / Nk) + 3] );
        }
        else if ( Nk > 6 && (row % Nk == 4) ) // 待确定？
        {
            temp = SubWord(temp);
        }

        // w[row] = w[row-Nk] xor temp
        w[4 * row + 0] = (byte) ( (int) w[4 * (row - Nk) + 0] ^ (int)temp[0] );
        w[4 * row + 1] = (byte) ( (int) w[4 * (row - Nk) + 1] ^ (int)temp[1] );
        w[4 * row + 2] = (byte) ( (int) w[4 * (row - Nk) + 2] ^ (int)temp[2] );
        w[4 * row + 3] = (byte) ( (int) w[4 * (row - Nk) + 3] ^ (int)temp[3] );
    } // for loop
}

unsigned char *MyAesCBC::SubWord(unsigned char *word)
{
    // 密钥字节替换
    byte* temp = new byte[4];
    for (int j=0;j<4;j++)
    {
        temp[j] = AesSbox[16*(word[j] >> 4)+(word[j] & 0x0f)]; // 实际也可写成AesSbox[[j]], 因为两者相等
    }
    return temp;
}

unsigned char *MyAesCBC::RotWord(unsigned char *word)
{
    // 密钥移位函数
    byte *temp = new byte[4];
    temp[0] = word[1];
    temp[1] = word[2];
    temp[2] = word[3];
    temp[3] = word[0];
    return temp;
}
