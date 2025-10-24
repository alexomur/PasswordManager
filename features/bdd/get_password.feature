Feature: Получение сохранённого пароля
  Scenario: Given пароль сохранён, When запрашиваю доступ, Then получаю пароль
    Given сохранён пароль для сервиса "test_service" и логина "test_login" со значением "test_password"
    When запрашиваю пароль для сервиса "test_service" и логина "test_login"
    Then я получаю пароль "test_password"
