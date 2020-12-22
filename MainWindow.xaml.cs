using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace cryptAes256bts
{
    /// <summary>
    /// Logique d'interaction pour MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {

        AesManaged myAes = new AesManaged();
        AesManaged myAes128 = new AesManaged();
        public MainWindow()
        {
            InitializeComponent();
        }
         private void button_Click(object sender, RoutedEventArgs e)
        {
            int nbentier = 8;
            try
            {
                nbentier = Convert.ToInt32(tXbEntier.Text);
            }
            catch { }
            myAes128.KeySize = 128;
            myAes.KeySize = 256;
            myAes.BlockSize = 128;
            string key = textBox.Text;

            while (key.Length < 32)
            {
                key = key + "o";
            }
            byte[] tmp = Encoding.UTF8.GetBytes(key);
            Buffer.BlockCopy(tmp, 0, myAes.Key, 0, 32);
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(key), 0, myAes128.Key, 0, 16);
            Buffer.BlockCopy(Encoding.UTF8.GetBytes(key), 0, myAes128.IV, 0, 16);

            Buffer.BlockCopy(Encoding.UTF8.GetBytes(key), 0, myAes.IV, 0, 16);
            byte[] datas = new byte[nbentier * 4];
            int pos = 0;
            List<TextBox> t = sk1.Children.OfType<TextBox>().ToList();
            try
            {
                foreach (TextBox b in t)
                {
                    Buffer.BlockCopy(BitConverter.GetBytes(Convert.ToInt32(b.Text)), 0, datas, pos, 4);
                    pos = pos + 4;
                    if (pos > nbentier * 4)
                    { break; }
                }

            }
            catch { }


            string base64Encoded = System.Convert.ToBase64String(datas);

            //encrypt256
            byte[] encrypted = EncryptStringToBytes_Aes(base64Encoded, myAes.Key, myAes.IV);
            crypt.Text = BitConverter.ToString(encrypted).Replace("-", " ");
            taille.Content = datas.Length.ToString();
            taille128nCrypte.Content = datas.Length.ToString();


            //encrypt128
            byte[] encrypted128 = EncryptStringToBytes_Aes(base64Encoded, myAes128.Key, myAes128.IV);
            crypt128.Text = BitConverter.ToString(encrypted128).Replace("-", " ");
            taille128.Content = encrypted128.Length.ToString();
            taille256.Content = encrypted.Length.ToString();

            //decript256
            byte[] dncrypted = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);
            nocrypt.Text = BitConverter.ToString(dncrypted).Replace("-", " ");
            //decrypt128
            byte[] dncrypted128 = DecryptStringFromBytes_Aes(encrypted128, myAes128.Key, myAes128.IV);
            nocrypt_128.Text = BitConverter.ToString(dncrypted128).Replace("-", " ");
        }
        private byte[] EncryptStringToBytes_Aes(string mess, byte[] Key, byte[] IV)
        {
            // Check arguments.

            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(mess);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }
        static byte[] DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = "";
            byte[] data;
            // Create an AesManaged object
            // with the specified key and IV.
            using (AesManaged aesAlg = new AesManaged())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                            data = Convert.FromBase64String(plaintext);
                        }
                    }
                }
            }
            return data;
        }

        private void MinimizeWindow(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
        }

        private void MaximizeClick(object sender, RoutedEventArgs e)
        {
            if (this.WindowState==WindowState.Maximized)
            {
         //       this.WindowState = WindowState.Normal;
            }
            else
            {
       //         this.WindowState = WindowState.Maximized;
            }
        }

        private void Close(object sender, RoutedEventArgs e)
        {
            this.Close();
        }

        private void Titre_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            this.DragMove();
        }

        private void Titre_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            MaximizeClick(null, null);
        }

  
     }
}
