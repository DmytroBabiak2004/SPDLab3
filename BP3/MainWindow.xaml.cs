// MainWindow.xaml.cs
using Microsoft.Win32;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using RC5Encryption;
using System.Windows.Controls;

namespace RC5WPFApp
{
    public partial class MainWindow : Window
    {
        private readonly RC5 rc5 = new RC5(16, 8, 16); // Варіант 1
        private PRNG prng;

        public MainWindow()
        {
            InitializeComponent();
            prng = new PRNG(DateTime.Now.Ticks);
        }

        private byte[] DeriveKeyFromPassword(string password)
        {
            using var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes(password));
            byte[] key = new byte[16];
            Array.Copy(hash, key, 16); // Молодші 128 біт
            return key;
        }

        private byte[] AddPadding(byte[] data)
        {
            int blockSize = rc5.BlockSize;
            int padLen = blockSize - (data.Length % blockSize);
            if (padLen == 0) padLen = blockSize; // Завжди додаємо
            byte[] padded = new byte[data.Length + padLen];
            Array.Copy(data, padded, data.Length);
            for (int i = 0; i < padLen; i++)
                padded[data.Length + i] = (byte)padLen;
            return padded;
        }

        private byte[] RemovePadding(byte[] padded)
        {
            int padLen = padded[padded.Length - 1];
            if (padLen < 1 || padLen > rc5.BlockSize)
                throw new InvalidOperationException("Невірний padding");
            for (int i = 1; i < padLen; i++)
                if (padded[padded.Length - i] != padLen)
                    throw new InvalidOperationException("Невірний padding");
            return padded.AsSpan(0, padded.Length - padLen).ToArray();
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = InputFileTextBox.Text;
                string output = OutputFileTextBox.Text;
                string pass = PasswordBox.Password;

                if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output) || string.IsNullOrWhiteSpace(pass))
                {
                    MessageBox.Show("Заповніть усі поля!", "Помилка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] key = DeriveKeyFromPassword(pass);
                rc5.SetupKey(key);

                byte[] data = File.ReadAllBytes(input);
                byte[] padded = AddPadding(data);

                byte[] iv = prng.Generate(rc5.BlockSize);
                byte[] encIV = rc5.EncryptBlock(iv);
                byte[] ciphertext = EncryptCBC(padded, iv);

                File.WriteAllBytes(output, encIV.Concat(ciphertext).ToArray());

                StatusTextBlock.Text = "Файл зашифровано успішно!";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка: {ex.Message}", "Помилка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                rc5.DestroyKey();
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string input = InputFileTextBox.Text;
                string output = OutputFileTextBox.Text;
                string pass = PasswordBox.Password;

                if (string.IsNullOrWhiteSpace(input) || string.IsNullOrWhiteSpace(output) || string.IsNullOrWhiteSpace(pass))
                {
                    MessageBox.Show("Заповніть усі поля!", "Помилка", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[] key = DeriveKeyFromPassword(pass);
                rc5.SetupKey(key);

                byte[] all = File.ReadAllBytes(input);
                int bs = rc5.BlockSize;
                if (all.Length < bs || (all.Length - bs) % bs != 0)
                    throw new InvalidOperationException("Невірний розмір файлу");

                byte[] encIV = all.AsSpan(0, bs).ToArray();
                byte[] ciphertext = all.AsSpan(bs).ToArray();

                byte[] iv = rc5.DecryptBlock(encIV);
                byte[] padded = DecryptCBC(ciphertext, iv);
                byte[] plain = RemovePadding(padded);

                File.WriteAllBytes(output, plain);
                StatusTextBlock.Text = "Файл розшифровано успішно!";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Помилка: {ex.Message}", "Помилка", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            finally
            {
                rc5.DestroyKey();
            }
        }

        private byte[] EncryptCBC(byte[] data, byte[] iv)
        {
            int bs = rc5.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += bs)
            {
                byte[] block = data.AsSpan(i, bs).ToArray();
                for (int j = 0; j < bs; j++) block[j] ^= prev[j];
                byte[] enc = rc5.EncryptBlock(block);
                enc.CopyTo(result, i);
                prev = enc;
            }
            return result;
        }

        private byte[] DecryptCBC(byte[] data, byte[] iv)
        {
            int bs = rc5.BlockSize;
            byte[] result = new byte[data.Length];
            byte[] prev = (byte[])iv.Clone();

            for (int i = 0; i < data.Length; i += bs)
            {
                byte[] block = data.AsSpan(i, bs).ToArray();
                byte[] dec = rc5.DecryptBlock(block);
                for (int j = 0; j < bs; j++) dec[j] ^= prev[j];
                dec.CopyTo(result, i);
                prev = block;
            }
            return result;
        }

        private void BrowseInput_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog dlg = new OpenFileDialog();
            if (dlg.ShowDialog() == true) InputFileTextBox.Text = dlg.FileName;
        }

        private void BrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog dlg = new SaveFileDialog();
            if (dlg.ShowDialog() == true) OutputFileTextBox.Text = dlg.FileName;
        }

        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            InputFileTextBox.Clear();
            OutputFileTextBox.Clear();
            PasswordBox.Clear();
            StatusTextBlock.Text = "Поля очищено";
        }

        protected override void OnClosing(System.ComponentModel.CancelEventArgs e)
        {
            rc5.DestroyKey();
            base.OnClosing(e);
        }
    }
}