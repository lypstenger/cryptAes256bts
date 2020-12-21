using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

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
        private void test_RijndaelManaged()
        {


            int nbentier = 8;
            try
            {
                nbentier = Convert.ToInt32(tXbEntier.Text);
            }
            catch { }

            byte[] AES_iv = new byte[] { 0x68, 0x62, 0x72, 0x75, 0x6E, 0x6F, 0x36, 0x34, 0x35, 0x36, 0x74, 0x75, 0x6F, 0x62, 0x69, 0x74 };

            byte[] AesKey_Str = Encoding.UTF8.GetBytes("01234" + "&~(-|_|-)=~{[|#!@]}BrUnOtHaLiE32");
            byte[] AES_Key = new byte[32];
            for (int i = 0; i < AES_Key.Length; i++) { AES_Key[i] = AesKey_Str[i]; }

            RijndaelManaged rm = new RijndaelManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7,
                //KeySize = 256,
                //BlockSize = 128,
                Key = AES_Key,
                IV = AES_iv
            };
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
            byte[] datascryp=   AES_Encrypt(datas,Encoding.ASCII.GetBytes("toto"));
            byte[] datadecrypt = AES_Decrypt(datascryp, Encoding.ASCII.GetBytes("toto"));
            string Resultat = "";
            try
            {

                Resultat = System.Convert.ToBase64String(rm.CreateEncryptor().TransformFinalBlock(datas, 0, datas.Length));
                rm.Clear();
              //  return Resultat;
            }
            catch {// return Donnees; 
            }
            byte[]   buffer = Convert.FromBase64String(Resultat);
            byte[] Resutat = new byte[buffer.Length];
            try
            {
            Resultat = Encoding.UTF8.GetString((rm.CreateDecryptor().TransformFinalBlock(buffer, 0, buffer.Length)));
            rm.Clear();
              //  return Resultat;
            }


            // if (Mode)
            //{
            //    byte[] buffer = Encoding.ASCII.GetBytes(Donnees);
            //    try
            //    {
            //        Resultat = System.Convert.ToBase64String(rm.CreateEncryptor().TransformFinalBlock(buffer, 0, buffer.Length));
            //        rm.Clear();
            //        return Resultat;
            //    }
            //    catch { return Donnees; }
            //}
            //else
            //{
            //    byte[] buffer = Convert.FromBase64String(Donnees);
            //    try
            //    {
            //        Resultat = Encoding.UTF8.GetString(rm.CreateDecryptor().TransformFinalBlock(buffer, 0, buffer.Length));
            //        rm.Clear();
            //        return Resultat;
            //    }
            //    catch { return Donnees; }
            //}

            catch (Exception e)
            { //return Donnees;
            }

        }
        public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
        {
            byte[] encryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            int nbentier = 8;
            try
            {
                nbentier = Convert.ToInt32(tXbEntier.Text);
            }
            catch { }

            byte[] AES_iv = new byte[] { 0x68, 0x62, 0x72, 0x75, 0x6E, 0x6F, 0x36, 0x34, 0x35, 0x36, 0x74, 0x75, 0x6F, 0x62, 0x69, 0x74 };

            byte[] AesKey_Str = Encoding.UTF8.GetBytes("01234" + "&~(-|_|-)=~{[|#!@]}BrUnOtHaLiE32");
            byte[] AES_Key = new byte[32];
            for (int i = 0; i < AES_Key.Length; i++) { AES_Key[i] = AesKey_Str[i]; }
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Key = AES_Key;
                    AES.IV = AES_iv;
               AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                        cs.Close();
                    }
                    encryptedBytes = ms.ToArray();
                }
            }
            return encryptedBytes;
        }

        public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] decryptedBytes = null;
            byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
            int nbentier = 8;
            try
            {
                nbentier = Convert.ToInt32(tXbEntier.Text);
            }
            catch { }

            byte[] AES_iv = new byte[] { 0x68, 0x62, 0x72, 0x75, 0x6E, 0x6F, 0x36, 0x34, 0x35, 0x36, 0x74, 0x75, 0x6F, 0x62, 0x69, 0x74 };

            byte[] AesKey_Str = Encoding.UTF8.GetBytes("01234" + "&~(-|_|-)=~{[|#!@]}BrUnOtHaLiE32");
            byte[] AES_Key = new byte[32];
            for (int i = 0; i < AES_Key.Length; i++) { AES_Key[i] = AesKey_Str[i]; }
            using (MemoryStream ms = new MemoryStream())
            {
                using (RijndaelManaged AES = new RijndaelManaged())
                {
                    AES.KeySize = 256;
                    AES.BlockSize = 128;
                    var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                    AES.Key = key.GetBytes(AES.KeySize / 8);
                    AES.IV = key.GetBytes(AES.BlockSize / 8);
                    AES.Key = AES_Key;
                    AES.IV = AES_iv;
                    AES.Mode = CipherMode.CBC;
                    using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cs.Close();
                    }
                    decryptedBytes = ms.ToArray();
                }
            }
            return decryptedBytes;
        }
        private void button_Click(object sender, RoutedEventArgs e)
        {
            int nbentier = 8;
            try
            {
               nbentier= Convert.ToInt32(tXbEntier.Text);
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
            byte[] datas = new byte[nbentier*4];
            int pos = 0;
            List<TextBox> t = sk1.Children.OfType<TextBox>().ToList();
            try
            { 
            foreach (TextBox b in t)
            {
                Buffer.BlockCopy(BitConverter.GetBytes(Convert.ToInt32(b.Text)), 0, datas, pos, 4);
                pos = pos + 4;
                    if (pos> nbentier*4)
                    { break; }
            }

            }
            catch { }

       
            string base64Encoded = System.Convert.ToBase64String(datas);
            //  base64Encoded= System.Convert.ToString(datas);
          //  byte[] buffer = Encoding.ASCII.GetBytes(Donnees);

            byte[] encrypted = EncryptStringToBytes_Aes(base64Encoded, myAes.Key, myAes.IV);
            taille.Content = datas.Length.ToString();
            byte[] encrypted128 = EncryptStringToBytes_Aes(base64Encoded, myAes128.Key, myAes128.IV);
            taille128.Content = encrypted128.Length.ToString();
            taille256.Content = encrypted.Length.ToString();

            byte[] dncrypted = DecryptStringFromBytes_Aes(encrypted, myAes.Key, myAes.IV);
            nocrypt.Text = BitConverter.ToString(dncrypted).Replace("-", " ");
            crypt.Text = BitConverter.ToString(encrypted).Replace("-", " ");
            crypt128.Text = BitConverter.ToString(encrypted128).Replace("-", " ");

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

        private void button1_Click(object sender, RoutedEventArgs e)
        {
            test_RijndaelManaged();
        }

        private void button2_Click(object sender, RoutedEventArgs e)
        {
            byte[] tab = new byte[] { 45, 12, 45, 0 };
                int cc = BitConverter.ToInt32(tab, 0);
                double temps_s = cc /128d;
                double  htemp = temps_s / 3600;


                int heur = (int)htemp;
                temps_s = (temps_s - heur*3600);
                int min = (int)(temps_s/60);
                temps_s = (temps_s - min*60) ;



                string t= heur.ToString("00") + ":" + min.ToString("00") + ":" + temps_s.ToString("00.00");

        }
    }
}
