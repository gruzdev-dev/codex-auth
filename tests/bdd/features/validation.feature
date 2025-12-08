Feature: Валидация данных при регистрации
  Как Администратор безопасности
  Я хочу, чтобы API отклонял некорректные данные
  Чтобы предотвратить инъекции и создание слабых аккаунтов

  Background:
    Given база данных очищена

  Rule: Пароль должен быть определенной длины

  Scenario Outline: Проверка граничных значений длины пароля
    Given я подготавливаю запрос на регистрацию
    When я указываю email "valid@example.com"
    And я указываю пароль длиной <length> символов
    And я отправляю запрос регистрации
    Then я должен получить HTTP статус <status>
    And тело ответа должно содержать текст "<body>"

    Examples:
      | length | status | body                     |
      | 7      | 400    | password is too short     |
      | 73     | 400    | password is too long      |
      | 0      | 400    | password hash is required |
      | 8      | 201    | id                        |

  Rule: Email должен иметь корректный формат

  Scenario: Регистрация с некорректным email
    Given я подготавливаю запрос на регистрацию
    When я указываю email "invalid-email-no-at"
    And я указываю пароль "validPass123"
    And я отправляю запрос регистрации
    Then я должен получить HTTP статус 400
    And тело ответа должно содержать текст "invalid email format"