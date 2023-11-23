using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace AesLibrary
{
    /// <summary>
    /// AESクラスのラッパー
    /// </summary>
    public class AesWrapper : IDisposable
    {
        #region メンバ変数

        /// <summary>
        /// ブロックサイズ
        /// </summary>
        private const int BLOCK_SIZE = 128;

        /// <summary>
        /// IVサイズ
        /// </summary>
        private const int IV_SIZE = 16;

        /// <summary>
        /// AESクラス
        /// </summary>
        private Aes _aes = null;

        #endregion

        /// <summary>
        /// 共通鍵
        /// </summary>
        public byte[] Key
        {
            get
            {
                return _aes.Key;
            }
            set
            {
                _aes.Key = value;
            }
        }

        /// <summary>
        /// 鍵を自動生成してAES初期化
        /// </summary>
        /// <param name="keySize">キーサイズ</param>
        public AesWrapper(KeySize keySize = KeySize.KeySize256) 
        {
            _aes = Aes.Create();
            _aes.KeySize = (int)keySize;
            _aes.BlockSize = BLOCK_SIZE;
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;
            _aes.GenerateKey();
            _aes.GenerateIV();
        }

        /// <summary>
        /// 鍵を指定してAES初期化
        /// </summary>
        /// <param name="keySize">キーサイズ</param>
        /// <param name="key">共通鍵</param>
        public AesWrapper(KeySize keySize, byte[] key)
        {
            _aes = Aes.Create();
            _aes.KeySize = (int)keySize;
            _aes.BlockSize = BLOCK_SIZE;
            _aes.Mode = CipherMode.CBC;
            _aes.Padding = PaddingMode.PKCS7;
            _aes.Key = key;
            _aes.GenerateIV();
        }

        /// <summary>
        /// 文字列を暗号化してBase64に変換
        /// </summary>
        /// <param name="text">暗号化する文字列</param>
        /// <param name="encoding">暗号化する文字列のエンコーディング</param>
        /// <returns></returns>
        public string EncryptToBase64(string text, Encoding encoding)
        {
            string ret = string.Empty;

            if (!string.IsNullOrEmpty(text))
            {
                ret = Convert.ToBase64String(Encrypt(encoding.GetBytes(text)));
            }

            return ret;
        }

        /// <summary>
        /// 暗号化してBase64変換された文字列を復号
        /// </summary>
        /// <param name="text">復号する文字列</param>
        /// <param name="encoding">復号後のエンコーディング</param>
        /// <returns></returns>
        public string DecryptFromBase64(string text, Encoding encoding)
        {
            string ret = string.Empty;

            if (!string.IsNullOrEmpty(text))
            {
                byte[] value = Convert.FromBase64String(text);
                ret = encoding.GetString(Decrypt(value));
            }

            return ret;
        }

        /// <summary>
        /// バイト配列を暗号化
        /// </summary>
        /// <param name="value">暗号化するバイト配列</param>
        /// <returns></returns>
        public byte[] Encrypt(byte[] value)
        {
            if (value == null) return null;

            using (ICryptoTransform crypto = _aes.CreateEncryptor())
            {
                byte[] ret = crypto.TransformFinalBlock(value, 0, value.Length);
                return _aes.IV.Concat(ret).ToArray();   // IV結合
            }
        }

        /// <summary>
        /// 暗号化されたバイト配列を復号
        /// </summary>
        /// <param name="value">暗号化するバイト配列</param>
        /// <returns></returns>
        public byte[] Decrypt(byte[] value)
        {
            if (value == null) return null;

            // IVと暗号化文字列に分ける
            byte[] preIv = _aes.IV;
            List<byte> list = value.ToList();
            _aes.IV = list.GetRange(0, IV_SIZE).ToArray();   // IV
            value = list.GetRange(IV_SIZE, value.Length - IV_SIZE).ToArray(); // 暗号化文字列

            using (ICryptoTransform decrypt = _aes.CreateDecryptor())
            {
                byte[] ret = decrypt.TransformFinalBlock(value, 0, value.Length);
                _aes.IV = preIv;
                return ret;
            }
        }

        /// <summary>
        /// リソース解放
        /// </summary>
        public void Dispose()
        {
            _aes?.Dispose();
        }
    }
}
