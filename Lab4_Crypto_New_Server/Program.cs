using System;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;
using System.IO;
using System.Linq;
using System.Collections.Generic;

namespace SocketServer
{

    class Program
    {
        // Общий Ключ шифрования сервера аутентификаций(AS) и сервера выдачи разрешений(TGS) 
        public static string K_as_tgs = "FC71228417A9D7A700778C3C0DAE74F2993452DFF9EBC27BEEAB37531B627761";

        // Общий ключ шифрования клиента(c) и сервера аутентификаций(AS)
        public static string K_c;

        // Общий ключ шифрования клиента(c) и сервера выдачи разрешений(TGS)
        public static string K_c_tgs;

        // Общий ключ шифрования с service server(ss) и сервера выдачи разрешений(TGS)
        public static string K_tgs_ss;

        // Словарь, хранящий общие ключи шифрования клиентов и сервера аутентификации(AS)
        public static Dictionary<string, string> Client_Keys = new Dictionary<string, string>();

        // Список разрешений, где содежрится идентификатор клиента(c) и service server(ss)
        public static List<Tuple<string, string>> Permissions = new List<Tuple<string, string>>();

        // Общие ключи шифрования service server(ss) и сервера выдачи разрешений(TGS)
        public static Dictionary<string, string> KeysTGS = new Dictionary<string, string>();

        // Шифрование AES
        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
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
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        // Расшифрование AES
        static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
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
                        }
                    }
                }
            }

            return plaintext;
        }

        // Перевод байтов в строку в 16-ой системе счисления
        public static string ByteArrayToStringHex(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }

        // Перевод строки из 16-ой системы счисления в массив байтов
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        // Генерация ключей 32 байта (256 бит)
        public static string GenerateKey()
        {

            RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();

            byte[] key = new byte[32];

            rngCsp.GetBytes(key);

            return ByteArrayToStringHex(key);
        }

        // Разделение строки в массив строк с разделителем (пробел)
        public static string[] SplitData(byte[] bytes_data)
        {
            string data_string = Encoding.UTF8.GetString(bytes_data);

            var data = data_string.Split(' ');

            return data;
        }

        // Имеет ли клиент(c) разрешения обращаться к service server(ss)
        static bool HasPermissions(string client, string ss)
        {
            foreach (var perm in Permissions)
            {
                if (perm.Item1 == client && perm.Item2 == ss)
                    return true;
            }
            return false;
        }

        // Получение общего ключа между service server(ss) и сервером выдачи разрешений(tgs)
        static string GetTGS_SS_Key(string ss)
        {
            return KeysTGS[ss];
        }

        // Получение общего ключа между клиентом(c) и сервером аутентификации(AS)
        static string GetClientKey(string client)
        {
            return Client_Keys[client];
        }

        // Этап общения клиента(c) и сервера аутентификации(ss)
        static byte[] ASToClient(string client)
        {
            // Поиск общего ключа между сервером аутентификации(AS) и клиентом(c)
            K_c = GetClientKey(client);

            // Генерация общего ключа между клиентом(c) и сервером выдачи разрешений(TGS)
            K_c_tgs = GenerateKey();

            // Билет на получение билета(TGT)
            // Состоит из:
            // 1. идентификатора клиента
            // 2. идентификатора сервера выдачи разрешений
            // 3. метка времени
            // 4. период действия билета
            // 5. общий ключ между клиентом(c) и сервером выдачи разрешений(TGS)
            string tgt = $"{client} TGS {DateTime.Now} 60 {K_c_tgs}";

            // Шифрование билета на получение билета(TGT) общим ключом между
            // сервером аутентификации(AS) и сервером выдачи разрешений(TGS)
            var tgt_encrypt = ByteArrayToStringHex(EncryptStringToBytes_Aes(tgt, StringToByteArray(K_as_tgs), StringToByteArray(K_as_tgs.Substring(0, 32))));

            // Шифрование зашифрованного TGT и общего ключа между
            // сервером аутентификации(AS) и сервером выдачи разрешений(TGS)
            // Общим ключом между клиентом(c) и сервером аутентификации(AS)
            var data_out = EncryptStringToBytes_Aes(tgt_encrypt + " " + K_c_tgs, StringToByteArray(K_c), StringToByteArray(K_c.Substring(0, 32)));

            return data_out;
        }

        // Этап общения клиента(c) и сервера выдачи разрешений(TGS)
        static byte[] TGSToClient(string tgt_string, string Auth1, string ss)
        {
            // Расшифрование TGT(от AS) общим ключом AS и TGS
            var tgt_decrypt = DecryptStringFromBytes_Aes(StringToByteArray(tgt_string), StringToByteArray(K_as_tgs), StringToByteArray(K_as_tgs.Substring(0, 32)));

            var tgt_decrypt_split = tgt_decrypt.Split(' ');

            // Расшифрованный идентификатор клиента
            string c = tgt_decrypt_split[0];

            // Расшифрованный идентификатор сервера выдачи разрешений
            string tgs = tgt_decrypt_split[1];

            // Расшифрованная метка времени
            DateTime t1 = DateTime.Parse(tgt_decrypt_split[2] + " " + tgt_decrypt_split[3]);

            // Расшифрованный период действия билета
            int p1 = int.Parse(tgt_decrypt_split[4]);

            // Расшифрованный общий ключ между клиентом(c) и сервером выдачи разрешений(TGS)
            string _K_c_tgs = tgt_decrypt_split[5];

            // Расшифрование аутентификационнго блока общим ключом клиента(c) и TGS
            var Auth1_decrypt = DecryptStringFromBytes_Aes(StringToByteArray(Auth1), StringToByteArray(_K_c_tgs), StringToByteArray(_K_c_tgs.Substring(0, 32)));

            var Auth1_decrypt_split = Auth1_decrypt.Split(' ');

            // Расшифрованный идентификатор клиента
            string _c = Auth1_decrypt_split[0];

            // Расшифрованная метка времени
            DateTime t2 = DateTime.Parse(Auth1_decrypt_split[1] + " " + Auth1_decrypt_split[2]);

            // Проверка, что идентификаторы клиента совпадают
            // Идентификатор, полученный из аутентификационного блока
            // Идентификатор, полученный из TGT
            if (c != _c)
            {
                Console.WriteLine("Ошибка! Метка в аутентификационном блоке не совпадает с меткой в билете!");
                return EncryptStringToBytes_Aes("Ошибка;Метка в аутентификационном блоке не совпадает с меткой в билете!", StringToByteArray(_K_c_tgs), StringToByteArray(_K_c_tgs.Substring(0, 32)));
            }

            Console.WriteLine("t2" + t2);
            Console.WriteLine("t1" + t1);
            Console.WriteLine("t1 + 1" + t1.AddMinutes(p1));
            // Проверка, что TGT не просрочен
            if (t2 > t1.AddMinutes(p1))
            {
                Console.WriteLine("Ошибка! Время действия метки истекло!");
                return EncryptStringToBytes_Aes("Ошибка;Время действия метки истекло!", StringToByteArray(_K_c_tgs), StringToByteArray(_K_c_tgs.Substring(0, 32)));
            }

            // Проверка, имеет ли клиент(с) обращаться к service server(ss)
            if (!HasPermissions(c, ss))
            {
                Console.WriteLine("Ошибка! У вас нет соотвествующих прав!");
                return EncryptStringToBytes_Aes("Ошибка;У вас нет соотвествующих прав!", StringToByteArray(_K_c_tgs), StringToByteArray(_K_c_tgs.Substring(0, 32)));
            }

            // Генерация сеансового ключа между клиентом(c) и service server(ss)
            string K_c_ss = GenerateKey();

            // Билет для доступа к SS (TGS)
            // Состоит из:
            // 1. идентификатора клиента
            // 2. идентификатор service server(ss)
            // 3. метка времени
            // 4. период действия билета
            // 5. сеансовый ключ между клиентом(c) и service server(ss)
            string _tgs = $"{c} {ss} {DateTime.Now} 60 {K_c_ss}";

            // Получение общего ключа между TGS и SS
            K_tgs_ss = GetTGS_SS_Key(ss);

            // Шифрование TGS общим ключом TGS и SS
            string tgs_encrypt = ByteArrayToStringHex(EncryptStringToBytes_Aes(_tgs, StringToByteArray(K_tgs_ss), StringToByteArray(K_tgs_ss.Substring(0, 32))));

            // Шифрование зашифрованного TGS и сеансового ключа клиента и SS
            // общим ключом клиента и сервера выдачи разрешений
            var data_out = EncryptStringToBytes_Aes(tgs_encrypt + ";" + K_c_ss, StringToByteArray(_K_c_tgs), StringToByteArray(_K_c_tgs.Substring(0, 32)));

            return data_out;
        }

        // Этап общения клиента(c) и serive server(ss)
        // * Должен проводиться на стороне ss
        static byte[] FromClientToSS(string tgs_string, string Auth2)
        {
            // Расшифрование TGS(от TGS) общим ключом SS и TGS
            var tgs_decrypt = DecryptStringFromBytes_Aes(StringToByteArray(tgs_string), StringToByteArray(K_tgs_ss), StringToByteArray(K_tgs_ss.Substring(0, 32)));

            var tgs_decrypt_split = tgs_decrypt.Split(' ');

            // Расшифрованный идентификатор клиента
            string c = tgs_decrypt_split[0];

            // Расшифрованный идентификатор SS
            string ss = tgs_decrypt_split[1];

            // Расшифрованная метка времени
            DateTime t3 = DateTime.Parse(tgs_decrypt_split[2] + " " + tgs_decrypt_split[3]);

            // Расшифрованный период действия билета
            int p2 = int.Parse(tgs_decrypt_split[4]);

            // Расшифрованный сеансовый ключ между клиентом(c) и service server(ss)
            string K_c_ss = tgs_decrypt_split[5];

            // Расшифрование аутентификационнго блока сеансовым ключом клиента и SS 
            var Auth2_decrypt = DecryptStringFromBytes_Aes(StringToByteArray(Auth2), StringToByteArray(K_c_ss), StringToByteArray(K_c_ss.Substring(0, 32)));

            var Auth2_decrypt_split = Auth2_decrypt.Split(' ');

            // Расшифрованный идентификатор клиента
            string _c = Auth2_decrypt_split[0];

            // Расшифрованная метка времени
            DateTime t4 = DateTime.Parse(Auth2_decrypt_split[1] + " " + Auth2_decrypt_split[2]);

            // Проверка, что идентификаторы клиента совпадают
            // Идентификатор, полученный из аутентификационного бло ка
            // Идентификатор, полученный из TGS
            if (c != _c)
            {
                Console.WriteLine("Ошибка! Метка в аутентификационном блоке не совпадает с меткой в билете!");
                return EncryptStringToBytes_Aes("Ошибка;Метка в аутентификационном блоке не совпадает с меткой в билете!", StringToByteArray(K_c_ss), StringToByteArray(K_c_ss.Substring(0, 32)));
            }

            // Проверка, что TGS не просрочен
            if (t4 > t3.AddMinutes(p2))
            {
                Console.WriteLine("Ошибка! Время действия метки истекло!");
                return EncryptStringToBytes_Aes("Ошибка;Время действия метки истекло!", StringToByteArray(K_c_ss), StringToByteArray(K_c_ss.Substring(0, 32)));
            }

            Console.WriteLine("Подлинность клиента подтверждена!");

            // Увеличение метки времени из аутентификационного блока на одну минуту
            // Нужно для того, чтобы доказать клиенту свою подлинность
            DateTime _t4 = t4.AddMinutes(1);

            // Шифруем новую метку времени сеансовым ключом клиента и SS
            var data_out = EncryptStringToBytes_Aes(_t4.ToString(), StringToByteArray(K_c_ss), StringToByteArray(K_c_ss.Substring(0, 32)));

            return data_out;
        }

        static void Main(string[] args)
        {
            // Общие ключи клиентов и сервера аутентификации(AS)
            Client_Keys.Add("John", "17DC3303CD10E0824497A0874A4B86275E63C943E3FEFBA5F5760959DD525FC2");
            Client_Keys.Add("Bob", "97938DF8A1D10EBC9DE9B3F02D164EA1B8677E322ABD7F8DF448DA9A64FDA792");

            // Добавление разрешений 
            Permissions.Add(Tuple.Create("John", "SS1"));

            // Добавление общих ключей service server(SS) и сервером выдачи разрешений(TGS)
            KeysTGS.Add("SS1", "1BC3201A9F24A2FE48F634F90D406AAF6CBF5E36E292870ECBA98D74B065EE1B");
            KeysTGS.Add("SS2", "EC54E99514663EDB97ADEF400FBF34A77DAAE108303D3DA8008A7DFB4CDF0F52");

            // Устанавливаем для сокета локальную конечную точку
            IPHostEntry ipHost = Dns.GetHostEntry("localhost");
            IPAddress ipAddr = ipHost.AddressList[0];
            IPEndPoint ipEndPoint = new IPEndPoint(ipAddr, 11000);

            // Создаем сокет Tcp/Ip
            Socket sListener = new Socket(ipAddr.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            // Назначаем сокет локальной конечной точке и слушаем входящие сокеты
            try
            {
                sListener.Bind(ipEndPoint);
                sListener.Listen(10);

                // Начинаем слушать соединения
                while (true)
                {
                    Console.WriteLine("Ожидаем соединение через порт {0}", ipEndPoint);

                    // Программа приостанавливается, ожидая входящее соединение
                    Socket handler = sListener.Accept();

                    // Мы дождались клиента, пытающегося с нами соединиться

                    // Буфер для принятия сообщения от клиента
                    byte[] recieved_bytes = new byte[2048];

                    // Получение сообщения от клиента
                    int bytesRec = handler.Receive(recieved_bytes);

                    var new_recieved_bytes = new byte[bytesRec];

                    Array.Copy(recieved_bytes, new_recieved_bytes, bytesRec);

                    var data = SplitData(new_recieved_bytes);

                    // Смотрим заголовок, в сообщении, которое нам прислал клиент
                    switch (data[0])
                    {
                        // Взаимодействие клиента с сервером аутентификации
                        case "FromClientToAS":
                            {
                                // Отправляем сообщение клиенту
                                handler.Send(ASToClient(data[1]));
                                break;
                            }
                        // Взаимодействие клиента с сервером выдачи разрешений
                        case "FromClientToTGS":
                            {
                                // Отправляем сообщение клиенту
                                handler.Send(TGSToClient(data[1], data[2], data[3]));
                                break;
                            }
                        // Взаимодействие клиента с service server
                        case "FromClientToSS":
                            {
                                // Отправляем сообщение клиенту
                                handler.Send(FromClientToSS(data[1], data[2]));
                                break;
                            }
                    }

                    // Закрываем соединение
                    handler.Shutdown(SocketShutdown.Both);
                    handler.Close();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
            finally
            {
                Console.ReadLine();
            }
        }
    }
}
