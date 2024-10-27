from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart



# Генерація пари ключів RSA
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Секретний ключ
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Публічний ключ
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    print("RSA ключі згенеровано та збережено.")


# Шифрування повідомлення RSA
def encrypt_message(message, public_key_path):
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(encrypted_message)


# Розшифрування повідомлення RSA
def decrypt_message(encrypted_message, private_key_path):
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    decrypted_message = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return decrypted_message.decode()


# Відправка повідомлення через SMTP
def send_email(encrypted_message, sender_email, receiver_email, subject="Зашифроване повідомлення"):
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = "your@gmail.com"  # Заміна на реальний email
    smtp_password = "your created app password"  # Заміна на реальний пароль

    # Створення повідомлення
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject

    body = f"Зашифроване повідомлення:\n{encrypted_message.decode()}"
    msg.attach(MIMEText(body, 'plain'))

    # Підключення до сервера та відправка
    server = smtplib.SMTP(smtp_server, smtp_port)
    server.starttls()
    server.login(smtp_user, smtp_password)
    server.sendmail(sender_email, receiver_email, msg.as_string())
    server.quit()

    print(f"Зашифроване повідомлення відправлено на {receiver_email}.")


# Основна функція
def main():
    # Генерація ключів (виконується один раз)
    generate_rsa_keys()

    # Текст повідомлення
    message = "Привіт! Це зашифроване повідомлення."

    # Шифрування повідомлення
    encrypted_message = encrypt_message(message, "public_key.pem")
    print(f"Зашифроване повідомлення: {encrypted_message.decode()}")

    # Відправка зашифрованого повідомлення
    send_email(encrypted_message, "your@gmail.com", "reciever@gmail.com")

    # Розшифрування повідомлення (на стороні отримувача)
    decrypted_message = decrypt_message(encrypted_message, "private_key.pem")
    print(f"Розшифроване повідомлення: {decrypted_message}")


if __name__ == "__main__":
    main()