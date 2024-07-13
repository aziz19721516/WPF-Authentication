using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;


namespace WPF_Authentication
{
    public partial class RegistrationWindow : UserControl
    {
        private readonly MainWindow _mainWindow;
        private string password = string.Empty;
        private string connectionString = string.Empty;

        public RegistrationWindow(MainWindow mainWindow)
        {
            InitializeComponent();

            connectionString = ConfigurationManager.ConnectionStrings["UserDataBaseConnectionString"].ConnectionString;

            _mainWindow = mainWindow;
        }

        private void TogglePasswordVisibility_Click(object sender, RoutedEventArgs e)
        {
            if (PasswordBox_Reg.Visibility == Visibility.Visible)
            {   
                password = PasswordBox_Reg.Password;

                PasswordBox_Reg.Visibility = Visibility.Collapsed;
                VisiblePasswordTextBox.Visibility = Visibility.Visible;
                VisiblePasswordTextBox.Text = PasswordBox_Reg.Password;

            }
            else
            {
                password = VisiblePasswordTextBox.Text;

                PasswordBox_Reg.Visibility = Visibility.Visible;
                VisiblePasswordTextBox.Visibility = Visibility.Collapsed;
                PasswordBox_Reg.Password = VisiblePasswordTextBox.Text;
            }
        }

        private void ToggleConfirmPasswordVisibility_Click(object sender, RoutedEventArgs e)
        {
            if (ConfirmPasswordBox.Visibility == Visibility.Visible)
            {
                ConfirmPasswordBox.Visibility = Visibility.Collapsed;
                VisibleConfirmPasswordTextBox.Visibility = Visibility.Visible;
                VisibleConfirmPasswordTextBox.Text = ConfirmPasswordBox.Password;
            }
            else
            {
                ConfirmPasswordBox.Visibility = Visibility.Visible;
                VisibleConfirmPasswordTextBox.Visibility = Visibility.Collapsed;
                ConfirmPasswordBox.Password = VisibleConfirmPasswordTextBox.Text;
            }
        }

        private void RegisterButton_Click(object sender, RoutedEventArgs e)
        {
            string username = UsernameTextBox.Text;
            string confirmPassword = (ConfirmPasswordBox.Password.Length > 0) ? ConfirmPasswordBox.Password : VisibleConfirmPasswordTextBox.Text;

            password = (PasswordBox_Reg.Password.Length > 0) ? PasswordBox_Reg.Password : VisiblePasswordTextBox.Text;

            if (password != confirmPassword)
            {
                MessageBox.Show("Passwords do not match.");
                return;
            }

            if (ValidateCredentials(username, password))
            {
               if(RegisterUser(username, password))
               {
                    MessageBox.Show("Registered successfully!", "Information", MessageBoxButton.OK, MessageBoxImage.Information);

                    BackToLoginPageWithPopulatedCredentials(username, password);
               }  
            }

        }

        /// <summary>
        /// Saves a users to DB
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns>If registration is succeed, then return true</returns>
        private bool RegisterUser(string username, string password)
        {
             using(SqlConnection sqlConnection = new SqlConnection(connectionString))
             {
                sqlConnection.Open();
                
                var salt = GenerateSalt();
                var passwordHash = HashPassword(password, salt);

                SqlCommand sqlCommand = new SqlCommand("INSERT INTO Users (Username, PasswordHash, Salt) VALUES (@Username, @PasswordHash, @Salt)", sqlConnection);

                sqlCommand.Parameters.AddWithValue("@Username", username);
                sqlCommand.Parameters.AddWithValue("@PasswordHash", passwordHash);
                sqlCommand.Parameters.AddWithValue("@Salt", salt);

                try
                {
                    sqlCommand.ExecuteNonQuery();
                    return true; 

                } catch(Exception ex)
                {   
                    MessageBox.Show($"{ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);MessageBox.Show(ex.Message);
                    return false;
                }
             }
        }

        public void BackToLogin_Click(object sender, EventArgs e)
        {
            _mainWindow.ShowLogin();
        }

        /// <summary>
        /// Generates a random salt value to be used for password hashing.
        /// </summary>
        /// <returns>A base64 encoded string representing the generated salt.</returns>
        private string GenerateSalt()
        {
            var rng = new RNGCryptoServiceProvider();
            var saltBytes = new byte[32];
            rng.GetBytes(saltBytes);

            return Convert.ToBase64String(saltBytes);
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

        /// <summary>
        /// Validate username and password
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns>If everything is OK, then return true</returns>
        private bool ValidateCredentials(string username, string password)
        {
            // Regex pattern for username: at least 8 characters
            string usernamePattern = @".{8,}";
            // Regex pattern for password: at least 8 characters, one uppercase letter, and one digit
            string passwordPattern = @"^(?=.*[A-Z])(?=.*\d).{8,}$";

            // Validate username
            if (!Regex.IsMatch(username, usernamePattern))
            {
                MessageBox.Show("Username must be at least 8 characters!");
                return false;
            }

            // Validate password
            if (!Regex.IsMatch(password, passwordPattern))
            {
                MessageBox.Show("Password must be at least 8 characters, contain an uppercase character, and a digit!");
                return false;
            }

            return true;
        }

        private void BackToLoginPageWithPopulatedCredentials(string username, string password)
        {
             // Open login window with populated credentials
            _mainWindow.ShowLogin();
            ((LoginWindow)_mainWindow.MainContentControl.Content).UsernameTextBox.Text = username;
            ((LoginWindow)_mainWindow.MainContentControl.Content).PasswordBox.Password = password;
        }
    }
}
