// RC5.cs
using System;

namespace RC5Encryption
{
    public class RC5
    {
        private readonly int w, r, b;
        private readonly int u;
        private readonly ulong P, Q, mask;
        private readonly int logW;
        private ulong[] S;

        public int BlockSize => 2 * u;

        public RC5(int wordSize = 16, int rounds = 8, int keyLength = 16)
        {
            if (wordSize != 16 && wordSize != 32 && wordSize != 64)
                throw new ArgumentException("w має бути 16, 32 або 64");
            if (rounds < 0 || rounds > 255)
                throw new ArgumentException("r має бути 0–255");
            if (keyLength < 0 || keyLength > 255)
                throw new ArgumentException("b має бути 0–255");

            w = wordSize; r = rounds; b = keyLength;
            u = w / 8;
            mask = (1UL << w) - 1;
            logW = w - 1;

            P = w switch { 16 => 0xB7E1UL, 32 => 0xB7E15163UL, 64 => 0xB7E151628AED2A6BUL, _ => 0 };
            Q = w switch { 16 => 0x9E37UL, 32 => 0x9E3779B9UL, 64 => 0x9E3779B97F4A7C15UL, _ => 0 };
        }

        public void SetupKey(byte[] key)
        {
            if (key == null || key.Length != b)
                throw new ArgumentException($"Ключ має бути {b} байт");

            S = GenerateSubkeys(key);
        }

        private ulong[] GenerateSubkeys(byte[] key)
        {
            int c = (b + u - 1) / u;
            ulong[] L = new ulong[c];
            for (int i = 0; i < b; i++)
                L[i / u] = (L[i / u] << 8) | key[i];

            int t = 2 * (r + 1);
            ulong[] subkeys = new ulong[t];
            subkeys[0] = P;
            for (int i = 1; i < t; i++)
                subkeys[i] = (subkeys[i - 1] + Q) & mask;

            ulong A = 0, B = 0;
            int i_idx = 0, j_idx = 0;  // ВИПРАВЛЕНО: правильна ініціалізація
            int iterations = 3 * Math.Max(t, c);

            for (int s = 0; s < iterations; s++)
            {
                A = subkeys[i_idx] = RotateLeft(subkeys[i_idx] + A + B, 3);
                B = L[j_idx] = RotateLeft(L[j_idx] + A + B, (int)((A + B) & (ulong)logW));
                i_idx = (i_idx + 1) % t;
                j_idx = (j_idx + 1) % c;
            }

            return subkeys;
        }

        public byte[] EncryptBlock(byte[] block)
        {
            if (S == null) throw new InvalidOperationException("Ключ не ініціалізовано");
            if (block.Length != BlockSize) throw new ArgumentException($"Блок має бути {BlockSize} байт");

            ulong A = BytesToWord(block, 0);
            ulong B = BytesToWord(block, u);

            A = (A + S[0]) & mask;
            B = (B + S[1]) & mask;

            for (int i = 1; i <= r; i++)
            {
                A = (RotateLeft(A ^ B, (int)(B & (ulong)logW)) + S[2 * i]) & mask;
                B = (RotateLeft(B ^ A, (int)(A & (ulong)logW)) + S[2 * i + 1]) & mask;
            }

            return WordToBytes(A, B);
        }

        public byte[] DecryptBlock(byte[] block)
        {
            if (S == null) throw new InvalidOperationException("Ключ не ініціалізовано");
            if (block.Length != BlockSize) throw new ArgumentException($"Блок має бути {BlockSize} байт");

            ulong A = BytesToWord(block, 0);
            ulong B = BytesToWord(block, u);

            for (int i = r; i >= 1; i--)
            {
                B = RotateRight((B - S[2 * i + 1]) & mask, (int)(A & (ulong)logW)) ^ A;
                A = RotateRight((A - S[2 * i]) & mask, (int)(B & (ulong)logW)) ^ B;
            }

            B = (B - S[1]) & mask;
            A = (A - S[0]) & mask;

            return WordToBytes(A, B);
        }

        private ulong RotateLeft(ulong x, int n)
        {
            n &= logW;
            return ((x << n) | (x >> (w - n))) & mask;
        }

        private ulong RotateRight(ulong x, int n)
        {
            n &= logW;
            return ((x >> n) | (x << (w - n))) & mask;
        }

        private ulong BytesToWord(byte[] b, int off)
        {
            ulong v = 0;
            for (int i = 0; i < u; i++)
                v |= (ulong)b[off + i] << (8 * i);
            return v & mask;
        }

        private byte[] WordToBytes(ulong A, ulong B)
        {
            byte[] result = new byte[2 * u];
            for (int i = 0; i < u; i++)
            {
                result[i] = (byte)(A >> (8 * i));
                result[u + i] = (byte)(B >> (8 * i));
            }
            return result;
        }

        public void DestroyKey()
        {
            if (S != null)
            {
                for (int i = 0; i < S.Length; i++) S[i] = 0;
                S = null;
            }
        }
    }
}