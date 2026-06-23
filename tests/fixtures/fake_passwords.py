# 3 настоящих совпадения — детектор должен их найти
password = "qwerty123"          # severity: high (9 символов < 12)
secret = "my_very_long_secret"  # severity: medium (19 символов >= 12)
api_key = "abcdef789012"        # severity: medium (12 символов >= 12)

# 2 исключения — детектор должен их пропустить
password = None
token = "<password>"