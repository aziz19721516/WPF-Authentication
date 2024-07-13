using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
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

namespace WPF_Authentication
{

    public partial class LoginWindow : UserControl
    {
        private const string CredentialFilePath = "credentials.txt";
        private readonly MainWindow _mainWindow;
        private string connectionString = string.Empty;

        public LoginWindow(MainWindow mainWindow)
        {
            InitializeComponent();
            
            connectionString = ConfigurationManager.ConnectionStrings["UserDataBaseConnectionString"].ConnectionString;

             _mainWindow = mainWindow;
            LoadCredentials();
        }

        private void TogglePasswordVisibility_Click(object sender, RoutedEventArgs e)
        {   
            if (PasswordBox.Visibility == Visibility.Visible)
            {
                PasswordBox.Visibility = Visibility.Collapsed;
                VisiblePasswordTextBox.Visibility = Visibility.Visible;
                VisiblePasswordTextBox.Text = PasswordBox.Password;
            }
            else
            {
                PasswordBox.Visibility = Visibility.Visible;
                VisiblePasswordTextBox.Visibility = Visibility.Collapsed;
                PasswordBox.Password = VisiblePasswordTextBox.Text;
            }
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameTextBox.Text;
            string password = (PasswordBox.Password.Length > 0) ? PasswordBox.Password : VisiblePasswordTextBox.Text;

            if (RememberMeCheckBox.IsChecked == true)
            {
                File.WriteAllText(CredentialFilePath, $"{username}\n{password}");
            }

            string userNameInFile = string.Empty;
            string passwordInFile = string.Empty;

            if (File.Exists(CredentialFilePath))
            {
                var lines = File.ReadAllLines(CredentialFilePath);
                if (lines.Length == 2)
                {
                    userNameInFile = lines[0];
                    passwordInFile = lines[1];
                }
            }
            
           if (LoginUser(username, password))
           {
               MessageBox.Show("Login successfull!", "Information", MessageBoxButton.OK, MessageBoxImage.Information);
           } else
            {
                MessageBox.Show("Invalid username or password", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            _mainWindow.ShowRegistration();
        }

        /// <summary>
        /// Loads user's information if any data available
        /// </summary>
        private void LoadCredentials()
        {
            if (File.Exists(CredentialFilePath))
            {
                var lines = File.ReadAllLines(CredentialFilePath);
                if (lines.Length == 2)
                {
                    UsernameTextBox.Text = lines[0];
                    PasswordBox.Password = lines[1];
                }
            }
        }

        /// <summary>
        /// Gets username and password that a user entered, hashs the password with Salt in DB and compares with the one in DB
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns>Returns true if the users already registered</returns>
        private bool LoginUser(string username, string password)
        {
            using(SqlConnection sqlConnection = new SqlConnection(connectionString))
            {
                sqlConnection.Open();

                SqlCommand sqlCommand = new SqlCommand("SELECT PasswordHash, Salt FROM Users WHERE Username = @Username", sqlConnection);
                sqlCommand.Parameters.AddWithValue("@Username", username);

                using(var reader = sqlCommand.ExecuteReader())
                {
                    if(reader.Read())
                    {
                        var storedPasswordHash = reader["PasswordHash"].ToString();
                        var storedSalt = reader["Salt"].ToString();

                        var passwordHash = HashPassword(password, storedSalt);
                        return (storedPasswordHash == passwordHash) ? true : false;
                    } 

                    return false;
                }
            }
        }

        /// <summary>
        /// Hashes a password with a given salt using SHA-256.
        /// </summary>
        /// <param name="password">The plain text password to be hashed.</param>
        /// <param name="salt">The salt to be added to the password before hashing.</param>
        /// <returns>A base64 encoded string representing the hashed password.</returns>
        private string HashPassword(string password, string salt)
         {
            using (var sha256 = SHA256.Create())
            {
                var saltedPassword = password + salt;
                var saltedPasswordBytes = Encoding.UTF8.GetBytes(saltedPassword);
                var hashBytes = sha256.ComputeHash(saltedPasswordBytes);
                return Convert.ToBase64String(hashBytes);
            }
         }
    }
}
