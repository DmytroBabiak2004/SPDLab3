using System;

namespace RC5Encryption
{
    public class PRNG
    {
        private long state;
        private const long a = 16807;
        private const long m = 2147483647;

        public PRNG(long seed = 1)
        {
            state = seed % m;
            if (state <= 0) state = 1;
        }

        public long Next()
        {
            state = (a * state) % m;
            return state;
        }

        public byte NextByte() => (byte)(Next() & 0xFF);

        public byte[] Generate(int count)
        {
            byte[] result = new byte[count];
            for (int i = 0; i < count; i++)
                result[i] = NextByte();
            return result;
        }
    }
}