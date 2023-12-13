using System;
using System.Text;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Drawing;
using System.IO;
using System.Security.Cryptography;

namespace UIchecksumCheckerByN
{
    public partial class ChecksumCheckerN : Form
    {
        string FilePath;
        public ChecksumCheckerN()
        {
            InitializeComponent();
            this.Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
        public static string EncryptString(string ishText, string password)
        {
            try
            {
                string sol = "!L-3$rrR7faYmW5fJeQ=jKQAjACPKswx";
                if (string.IsNullOrEmpty(ishText))
                    return "";
                byte[] ishTextB = Encoding.UTF8.GetBytes(ishText);
                byte[] cipherTextBytes = null;
                int iterations = 5192;
                byte[] salt = Encoding.ASCII.GetBytes(sol);
                AesManaged aes = new AesManaged();
                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                aes.Mode = CipherMode.CBC;
                ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
                using (ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream memStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(ishTextB, 0, ishTextB.Length);
                            cryptoStream.FlushFinalBlock();
                            cipherTextBytes = memStream.ToArray();
                            memStream.Close();
                            cryptoStream.Close();
                        }
                    }
                }
                aes.Clear();
                return Convert.ToBase64String(cipherTextBytes);
            }
            catch
            {
                MessageBox.Show("Произошла ошибка шифрования строки. Проверьте правильность введённого ключа.", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }
        public static string DecryptString(string ciphText, string password)
        {
            try
            {
                string sol = "!L-3$rrR7faYmW5fJeQ=jKQAjACPKswx";
                if (string.IsNullOrEmpty(ciphText))
                    return "";
                byte[] ishTextB = Encoding.UTF8.GetBytes(ciphText);
                byte[] cipherTextBytes = null;
                int iterations = 5192;
                byte[] salt = Encoding.ASCII.GetBytes(sol);
                AesManaged aes = new AesManaged();
                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                aes.Mode = CipherMode.CBC;
                cipherTextBytes = Convert.FromBase64String(ciphText);
                byte[] plainTextBytes = new byte[cipherTextBytes.Length];
                int byteCount = 0;
                using (ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream mSt = new MemoryStream(cipherTextBytes))
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(mSt, decryptor, CryptoStreamMode.Read))
                        {
                            byteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
                            mSt.Close();
                            cryptoStream.Close();
                        }
                    }
                }
                aes.Clear();
                return Encoding.UTF8.GetString(plainTextBytes, 0, byteCount);
            }
            catch
            {
                MessageBox.Show("Произошла ошибка расшифровки строки. Проверьте правильность введённого пароля, а так же наличие у программы прав на чтение файла.", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return null;
            }
        }

        public void DecryptFile(string sourceFilename, string destinationFilename, string password, string sol, int iterations)
        {
            try
            {
                byte[] salt = Encoding.ASCII.GetBytes(sol);
                AesManaged aes = new AesManaged();
                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                aes.Mode = CipherMode.CBC;
                ICryptoTransform transform = aes.CreateDecryptor(aes.Key, aes.IV);
                using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                    {
                        try
                        {
                            using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                            {
                                source.CopyTo(cryptoStream);
                            }
                        }
                        catch
                        {
                            MessageBox.Show("Произошла ошибка расшифровки файла. Убедитесь, что указанный файл существует, и что пароль, соль, и количество итераций введены правильно.", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                }
            }
            catch
            {
                MessageBox.Show("Произошла ошибка расшифровки файла. Убедитесь, что указанный файл существует, и что пароль, соль, и количество итераций введены правильно", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public void EncryptFile(string sourceFilename, string destinationFilename, string password, string sol, int iterations)
        {
            try
            {
                byte[] salt = Encoding.ASCII.GetBytes(sol);
                AesManaged aes = new AesManaged();
                aes.BlockSize = aes.LegalBlockSizes[0].MaxSize;
                aes.KeySize = aes.LegalKeySizes[0].MaxSize;
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
                aes.Key = key.GetBytes(aes.KeySize / 8);
                aes.IV = key.GetBytes(aes.BlockSize / 8);
                aes.Mode = CipherMode.CBC;
                ICryptoTransform transform = aes.CreateEncryptor(aes.Key, aes.IV);
                using (FileStream destination = new FileStream(destinationFilename, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(destination, transform, CryptoStreamMode.Write))
                    {
                        using (FileStream source = new FileStream(sourceFilename, FileMode.Open, FileAccess.Read, FileShare.Read))
                        {
                            source.CopyTo(cryptoStream);
                        }
                    }
                }
            }
            catch
            {
                MessageBox.Show("Произошла ошибка шифрования файла. Убедитесь, что программа имеет разрешение на чтение и запись файлов, а так же пароль, соль и число итераций указаны правильно.", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }

        }

        private void MD5enable_CheckedChanged(object sender, EventArgs e)
        {
            if (MD5Hash.Enabled == false)
                MD5Hash.Enabled = true;
            else MD5Hash.Enabled = false;
            MD5Hash.Clear();
        }
        private void SHA1Enable_CheckedChanged(object sender, EventArgs e)
        {
            if (SHA1Hash.Enabled == false)
                SHA1Hash.Enabled = true;
            else SHA1Hash.Enabled = false;
            SHA1Hash.Clear();
        }
        private void SHA256Enable_CheckedChanged(object sender, EventArgs e)
        {
            if (SHA256Hash.Enabled == false)
                SHA256Hash.Enabled = true;
            else SHA256Hash.Enabled = false;
            SHA256Hash.Clear();
        }
        private void SHA384Enable_CheckedChanged(object sender, EventArgs e)
        {
            if (SHA384Hash.Enabled == false)
                SHA384Hash.Enabled = true;
            else SHA384Hash.Enabled = false;
            SHA384Hash.Clear();
        }
        private void SHA512Enable_CheckedChanged(object sender, EventArgs e)
        {
            if (SHA512Hash.Enabled == false)
                SHA512Hash.Enabled = true;
            else SHA512Hash.Enabled = false;
            SHA512Hash.Clear();
        }
        private void ChooseFileButton_Click(object sender, EventArgs e)
        {

            if (OpenFileDialog.ShowDialog() == DialogResult.Cancel)
                return;
            FilePath = OpenFileDialog.FileName;
            PathTextBox.Text = OpenFileDialog.FileName;
            FileSizeTextBox.Text = Convert.ToString(new FileInfo(FilePath).Length / 1024);
            if (Convert.ToInt32(FileSizeTextBox.Text) > 1024)
            { FileSizeTextBox.Text = Convert.ToString(Convert.ToInt64(FileSizeTextBox.Text) / 1024 + " МБ"); }
            else
            { FileSizeTextBox.Text = Convert.ToString(new FileInfo(FilePath).Length / 1024 + " КБ"); }
        }
        private void BufferCopyPaste_Click(object sender, EventArgs e)
        {
            string ClipboardText = "";
            if (Clipboard.ContainsText() == true)
            {
                try
                {
                    ClipboardText = Clipboard.GetText();

                    string pass, EncString;

                    pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль либо оставьте поле пустым, если файл не был зашифрован.", "Расшифровка контрольных сумм | ChecksumCheckerN");

                    if (pass.Length != 0)
                    {
                        EncString = DecryptString(ClipboardText, pass);
                    }
                    else
                    { EncString = ClipboardText; }

                    String[] Settings = EncString.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
                    if (Settings[0] == "=====ChecksumCheckerN=====")
                    {
                        if (Settings[1] != " ")
                        {
                            MD5enable.Checked = true;
                            MD5Hash.Text = Settings[1];
                        }
                        if (Settings[2] != " ")
                        {
                            SHA1Enable.Checked = true;
                            SHA1Hash.Text = Settings[2];
                        }
                        if (Settings[3] != " ")
                        {
                            SHA256Enable.Checked = true;
                            SHA256Hash.Text = Settings[3];
                        }
                        if (Settings[4] != " ")
                        {
                            SHA384Enable.Checked = true;
                            SHA384Hash.Text = Settings[4];
                        }
                        if (Settings[5] != " ")
                        {
                            SHA512Enable.Checked = true;
                            SHA512Hash.Text = Settings[5];
                        }
                    }
                    else
                        MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====ChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch
                {
                    MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====ChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }
        private SHA512 CountSHA512Hash = SHA512.Create();
        private SHA384 CountSHA384Hash = SHA384.Create();
        private SHA256 CountSHA256Hash = SHA256.Create();
        private SHA1 CountSHA1Hash = SHA1.Create();
        private MD5 CountMD5Hash = MD5.Create();
        private byte[] GetHashSha512(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                return CountSHA512Hash.ComputeHash(stream);
            }
        }
        private byte[] GetHashSha384(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                return CountSHA384Hash.ComputeHash(stream);
            }
        }
        private byte[] GetHashSha256(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                return CountSHA256Hash.ComputeHash(stream);
            }
        }
        private byte[] GetHashSha1(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                return CountSHA1Hash.ComputeHash(stream);
            }
        }
        private byte[] GetHashMD5(string filename)
        {
            using (FileStream stream = File.OpenRead(filename))
            {
                return CountMD5Hash.ComputeHash(stream);
            }
        }
        public static string BytesToString(byte[] bytes)
        {
            string result = "";
            foreach (byte b in bytes) result += b.ToString("x2");
            return result;
        }
        private void BufferCopy_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(CreateFullHashString());
        }

        private async void CountCheckHash_Click(object sender, EventArgs e)
        {
            if (FilePath == null)
            {
                MessageBox.Show("Необходимо выбрать файл", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                ChooseFileButton.Enabled = false;
                ClearAll.Enabled = false;
                string newHash;
                HashProgressBar.Style = ProgressBarStyle.Marquee;
                HashProgressBar.MarqueeAnimationSpeed = 30;
                if (IsSumEncEnable.Checked == true)
                {
                    if (PasswordBox.Text.Length != 0 && SaltTextBox.Text.Length != 0)
                    {
                        try
                        {

                            if (FileEncryptRadio.Checked == true)
                            {
                                saveEncFile.FileName = Path.GetFileName(OpenFileDialog.FileName) + ".eNc";
                                if (saveEncFile.ShowDialog() == DialogResult.OK)
                                {
                                    await Task.Run(() =>
                         EncryptFile(FilePath, saveEncFile.FileName, PasswordBox.Text, SaltTextBox.Text, Convert.ToInt32(IterNum.Value)));
                                }
                            }

                            if (FileDecryptRadio.Checked == true)
                            {
                                saveDecFile.FileName = Path.GetFileNameWithoutExtension(OpenFileDialog.FileName);
                                if (saveDecFile.ShowDialog() == DialogResult.OK)
                                {
                                    await Task.Run(() => DecryptFile(FilePath, saveDecFile.FileName, PasswordBox.Text, SaltTextBox.Text, Convert.ToInt32(IterNum.Value)));
                                }
                            }
                        }

                        catch
                        {
                            MessageBox.Show("Произошла ошибка шифрования файла!", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                        }
                    }
                    else
                        MessageBox.Show("Для шифрования файла необходимо указать ключ, соль и число итераций!", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);

                }

                if (FileDecryptRadio.Checked == true)
                    FilePath = saveDecFile.FileName;
                try
                {
                    if (IsHashEnable.Checked == true)
                    {
                        if (MD5enable.Checked == true)
                        {
                            newHash = await Task.Run(() =>
                                 BytesToString(GetHashMD5(FilePath)));
                            if (MD5Hash.Text.Length != 0)
                            {
                                if (MD5Hash.Text == newHash)
                                {
                                    MD5Hash.ForeColor = Color.Green;
                                    MD5Hash.Text = newHash;
                                }
                                else MD5Hash.ForeColor = Color.Red;
                                { MD5Hash.Text = MD5Hash.Text; }
                            }
                            else
                                MD5Hash.Text = newHash;
                        }
                        if (SHA1Enable.Checked == true)
                        {
                            newHash = await Task.Run(() =>
                 BytesToString(GetHashSha1(FilePath)));
                            if (SHA1Hash.Text.Length != 0)
                            {
                                if (SHA1Hash.Text == newHash)
                                {
                                    SHA1Hash.ForeColor = Color.Green;
                                    SHA1Hash.Text = newHash;
                                }
                                else SHA1Hash.ForeColor = Color.Red;
                                { SHA1Hash.Text = SHA1Hash.Text; }
                            }
                            else
                                SHA1Hash.Text = newHash;
                        }
                        if (SHA256Enable.Checked == true)
                        {
                            newHash = await Task.Run(() =>
                   BytesToString(GetHashSha256(FilePath)));
                            if (SHA256Hash.Text.Length != 0)
                            {
                                if (SHA256Hash.Text == newHash)
                                {
                                    SHA256Hash.ForeColor = Color.Green;
                                    SHA256Hash.Text = newHash;
                                }
                                else SHA256Hash.ForeColor = Color.Red;
                                { SHA256Hash.Text = SHA256Hash.Text; }
                            }
                            else
                                SHA256Hash.Text = newHash;
                        }
                        if (SHA384Enable.Checked == true)
                        {
                            newHash = await Task.Run(() =>
                   BytesToString(GetHashSha384(FilePath)));
                            if (SHA384Hash.Text.Length != 0)
                            {
                                if (SHA384Hash.Text == newHash)
                                {
                                    SHA384Hash.ForeColor = Color.Green;
                                    SHA384Hash.Text = newHash;
                                }
                                else SHA384Hash.ForeColor = Color.Red;
                                { SHA384Hash.Text = SHA384Hash.Text; }
                            }
                            else
                                SHA384Hash.Text = newHash;
                        }
                        if (SHA512Enable.Checked == true)
                        {
                            newHash = await Task.Run(() =>
                   BytesToString(GetHashSha512(FilePath)));
                            if (SHA512Hash.Text.Length != 0)
                            {
                                if (SHA512Hash.Text == newHash)
                                {
                                    SHA512Hash.ForeColor = Color.Green;
                                    SHA512Hash.Text = newHash;
                                }
                                else SHA512Hash.ForeColor = Color.Red;
                                { SHA512Hash.Text = SHA512Hash.Text; }
                            }
                            else
                                SHA512Hash.Text = newHash;
                        }
                    }
                }
                catch
                {
                    MessageBox.Show("Произошла ошибка вычисления контрольных сумм!", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                HashProgressBar.Style = ProgressBarStyle.Continuous;
                HashProgressBar.Increment(100);
                HashProgressBar.MarqueeAnimationSpeed = 0;
                ChooseFileButton.Enabled = true;
                ClearAll.Enabled = true;
            }
        }
        private void ClearAll_Click(object sender, EventArgs e)
        {
            MD5Hash.Clear();
            SHA1Hash.Clear();
            SHA256Hash.Clear();
            SHA384Hash.Clear();
            SHA512Hash.Clear();
            PasswordBox.Clear();
            SaltTextBox.Clear();
            IsSumEncEnable.Checked = false;
            IsHashEnable.Checked = false;
            IterNum.Value = 2048;
            MD5Hash.ForeColor = Color.Black;
            SHA1Hash.ForeColor = Color.Black;
            SHA256Hash.ForeColor = Color.Black;
            SHA384Hash.ForeColor = Color.Black;
            SHA512Hash.ForeColor = Color.Black;
            MD5enable.Checked = false;
            SHA1Enable.Checked = false;
            SHA256Enable.Checked = false;
            SHA384Enable.Checked = false;
            SHA512Enable.Checked = false;
            HashProgressBar.Increment(-100);
        }
        private string CreateFullKeyString()
        {
            string pass;
            pass = Microsoft.VisualBasic.Interaction.InputBox("Вы можете повысить безопасность ключа и зашифровать его мастер-паролем. Введите пароль либо оставьте поле пустым для сохранения без шифрования.", "Шифрование ключа | ChecksumCheckerN");
            string FullHashString = "=====KEYChecksumCheckerN=====@";
            FullHashString = FullHashString + PasswordBox.Text;
            FullHashString = FullHashString + "@";
            FullHashString = FullHashString + SaltTextBox.Text;
            FullHashString = FullHashString + "@";
            FullHashString = FullHashString + IterNum.Text;
            FullHashString = FullHashString + "@=====KEYChecksumCheckerN=====";

            string EncString = "";
            if (pass.Length != 0)
            {
                EncString = EncryptString(FullHashString, pass);
            }
            else EncString = FullHashString;
            pass = "";
            return EncString;
        }

        private string CreateFullHashString()
        {
            string pass;
            pass = Microsoft.VisualBasic.Interaction.InputBox("Вы можете повысить безопасность файла контрольных сумм и зашифровать его мастер-паролем. Введите пароль либо оставьте поле пустым для сохранения без шифрования.", "Шифрование контрольных сумм | ChecksumCheckerN");
            string FullHashString = "=====ChecksumCheckerN=====@";
            if (MD5enable.Checked)
                FullHashString = FullHashString + MD5Hash.Text;
            else FullHashString = FullHashString + " ";
            FullHashString = FullHashString + "@";
            if (SHA1Enable.Checked)
                FullHashString = FullHashString + SHA1Hash.Text;
            else FullHashString = FullHashString + " ";
            FullHashString = FullHashString + "@";
            if (SHA256Enable.Checked)
                FullHashString = FullHashString + SHA256Hash.Text;
            else FullHashString = FullHashString + " ";
            FullHashString = FullHashString + "@";
            if (SHA384Enable.Checked && SHA384Hash.Text.Length != 0)
                FullHashString = FullHashString + SHA384Hash.Text;
            else FullHashString = FullHashString + " ";
            FullHashString = FullHashString + "@";
            if (SHA512Enable.Checked && SHA512Hash.Text.Length != 0)
                FullHashString = FullHashString + SHA512Hash.Text;
            else FullHashString = FullHashString + " ";
            FullHashString = FullHashString + "@=====ChecksumCheckerN=====";

            string EncString = "";
            if (pass.Length != 0)
            {
                EncString = EncryptString(FullHashString, pass);
            }
            else EncString = FullHashString;
            pass = "";
            return EncString;
        }
        private void SaveToFile_Click(object sender, EventArgs e)
        {
            StreamWriter writefl;
            SaveHashDialog.FileName = Path.GetFileNameWithoutExtension(OpenFileDialog.FileName);
            if (SaveHashDialog.ShowDialog() == DialogResult.OK)
            {
                writefl = File.CreateText(SaveHashDialog.FileName);
                writefl.Write(CreateFullHashString());
                writefl.Close();
            }
        }
        private void ReadFromFile_Click(object sender, EventArgs e)
        {
            if (OpenSavedHashes.ShowDialog() == DialogResult.Cancel)
                return;
            try
            {
                string pass, EncString;
                pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль либо оставьте поле пустым, если файл не был зашифрован.", "Расшифровка контрольных сумм | ChecksumCheckerN");

                string HashFile = File.ReadAllText(OpenSavedHashes.FileName);
                if (pass.Length != 0)
                {
                    EncString = DecryptString(HashFile, pass);
                }
                else
                { EncString = HashFile; }
                pass = "";
                String[] Settings = EncString.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
                if (Settings[0] == "=====ChecksumCheckerN=====")
                {
                    if (Settings[1] != " ")
                    {
                        MD5enable.Checked = true;
                        MD5Hash.Text = Settings[1];
                    }
                    if (Settings[2] != " ")
                    {
                        SHA1Enable.Checked = true;
                        SHA1Hash.Text = Settings[2];
                    }
                    if (Settings[3] != " ")
                    {
                        SHA256Enable.Checked = true;
                        SHA256Hash.Text = Settings[3];
                    }
                    if (Settings[4] != " ")
                    {
                        SHA384Enable.Checked = true;
                        SHA384Hash.Text = Settings[4];
                    }
                    if (Settings[5] != " ")
                    {
                        SHA512Enable.Checked = true;
                        SHA512Hash.Text = Settings[5];
                    }
                }
                else
                    MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====ChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch
            {
                MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====ChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void GenerateSalt_Click(object sender, EventArgs e)
        {
            SaltTextBox.Text = GenerateRandomString();
        }

        string GenerateRandomString()
        {
            string s0 = "";
            string s1 = "";
            Random rnd = new Random();
            int n;
            string st = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int j = 0; j < 32; j++)
            {
                n = rnd.Next(0, 61);
                s1 = st.Substring(n, 1);
                s0 += s1;
            }
            return s0;
        }

        private void CreateRandomPassword_Click(object sender, EventArgs e)
        {
            PasswordBox.Text = GenerateRandomString();
        }

        private void SelectAllButtom_Click(object sender, EventArgs e)
        {
            MD5enable.Checked = true;
            SHA1Enable.Checked = true;
            SHA256Enable.Checked = true;
            SHA384Enable.Checked = true;
            SHA512Enable.Checked = true;
        }

        private void ReadKeyFromFile_Click(object sender, EventArgs e)
        {
            if (KeyopenFileDialog.ShowDialog() == DialogResult.Cancel)
                return;
            try
            {
                string pass, EncString;
                pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль либо оставьте поле пустым, если файл не был зашифрован.", "Расшифровка ключа | ChecksumCheckerN");
                string KeyFile = File.ReadAllText(KeyopenFileDialog.FileName);
                if (pass.Length != 0)
                {
                    EncString = DecryptString(KeyFile, pass);
                }
                else
                { EncString = KeyFile; }
                pass = "";
                String[] Settings = EncString.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
                if (Settings[0] == "=====KEYChecksumCheckerN=====")
                {
                    PasswordBox.Text = Settings[1];
                    SaltTextBox.Text = Settings[2];
                    IterNum.Value = Convert.ToDecimal(Settings[3]);

                }
                else
                    MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====KEYChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            catch
            { MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====KEYChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error); }

        }

        private void SavePasstoBuffer_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(CreateFullKeyString());
        }

        private void ReadKeyFromBuffer_Click(object sender, EventArgs e)
        {
            string ClipboardText = "";
            if (Clipboard.ContainsText() == true)
            {
                try
                {
                    ClipboardText = Clipboard.GetText();

                    string pass, EncString;

                    pass = Microsoft.VisualBasic.Interaction.InputBox("Введите пароль либо оставьте поле пустым, если файл не был зашифрован.", "Расшифровка ключа | ChecksumCheckerN");

                    if (pass.Length != 0)
                    {
                        EncString = DecryptString(ClipboardText, pass);
                    }
                    else
                    { EncString = ClipboardText; }

                    String[] Settings = EncString.Split(new char[] { '@' }, StringSplitOptions.RemoveEmptyEntries);
                    if (Settings[0] == "=====KEYChecksumCheckerN=====")
                    {
                        PasswordBox.Text = Settings[1];
                        SaltTextBox.Text = Settings[2];
                        IterNum.Value = Convert.ToDecimal(Settings[3]);

                    }
                    else
                        MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====KEYChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
                catch
                { MessageBox.Show("Данные имеют неверный формат.\n\nУбедитесь, что копируемый текст имеет строку\n\n=====KEYChecksumCheckerN=====\n\nв начале и в конце", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error); }
            }
        }

        private void SaveKeyToFile_Click(object sender, EventArgs e)
        {
            try
            {
                StreamWriter writefl;
                KeysaveFileDialog.FileName = Path.GetFileNameWithoutExtension(OpenFileDialog.FileName);
                if (KeysaveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    writefl = File.CreateText(KeysaveFileDialog.FileName);
                    writefl.Write(CreateFullKeyString());
                    writefl.Close();
                }
            }
            catch
            {
                MessageBox.Show("Произошла ошибка сохранения файла. Убедитесь, что директория существует, и программе предоставлены все разрешения для чтения и записи.", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void IsSumEncEnable_CheckedChanged(object sender, EventArgs e)
        {
            if (SymcEnc.Enabled == false)
            { SymcEnc.Enabled = true; }
            else SymcEnc.Enabled = false;
        }

        private void IsHashEnable_CheckedChanged(object sender, EventArgs e)
        {
            if (HashCounting.Enabled == false)
            { HashCounting.Enabled = true; }
            else HashCounting.Enabled = false;
        }

        private void Author_Click(object sender, EventArgs e)
        {
            MessageBox.Show("ChecksumCheckerN v.3.1\n\nАвтор идеи и разработчик:\n\n      Naulex\n      073797@gmail.com\n                                        2023.", "Об авторе | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void RandomIterNum_Click(object sender, EventArgs e)
        {
            Random rnd = new Random();
            IterNum.Value = rnd.Next(2048, 65536);
        }

        private void ShowPass_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowPass.Checked == true)
                PasswordBox.UseSystemPasswordChar = false;
            else
                PasswordBox.UseSystemPasswordChar = true;
        }

        private void ShowSalt_CheckedChanged(object sender, EventArgs e)
        {
            if (ShowSalt.Checked == true)
                SaltTextBox.UseSystemPasswordChar = false;
            else
                SaltTextBox.UseSystemPasswordChar = true;
        }

        private void SaltTextBox_Leave(object sender, EventArgs e)
        {
            if (Convert.ToInt32(SaltTextBox.Text.Length) / 8 == 0)
            {
                MessageBox.Show("Длина соли должна быть кратна 8!", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
        private void PasswordBox_Leave(object sender, EventArgs e)
        {
            if (Convert.ToInt32(PasswordBox.Text.Length) == 0)
            {
                MessageBox.Show("Укажите пароль!", "Ошибка | ChecksumCheckerN", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

    }

}


