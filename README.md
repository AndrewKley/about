# README
Знаю, что нужен был, какой-нибудь конкретный код, но не смог выбрать какой лучше подойдет, поэтому взял отовсюду по немногу, выберите тот, который вам более интересен)

## _skills.scss
Использовался при верстке шаблона из figma. [GitHub](https://github.com/AndrewKley/den-lan)
В проекте испльзовалась динамическая верстка и scss, этот файл преобразовывался в чистый css, просто удобнее писать в формате scss, а потом уже переводить в css

## index.html
Использовался в том же проекте что и _skills.scss, сложность была в создании звезд под логотипами (размещается "навык" и уровень его владения под ним в виде 5 звезд и уровень владения ими)

## PlayerWallet.cs
Класс кошелька пользователя, код из проекта игры на Unity | C#, [GitHub](https://github.com/AndrewKley/BearInRandomGame)
В проекте использовал новую для себя в тот момент систему событий. Чтобы результаты сохранялись использовал сохранение в памяти через PlayerPrefs. В методе списания нет проверки на отрицательность баланса (нет проверки что при покупке скина хватит денег), такая проверка была в методе что его вызывал

## strpls_sprintf.c
[GitHub](https://github.com/AndrewKley/string_plus)
Просто сложно), реализация функции sprintf в си, сложность в том что на языке си, так еще и неопределенное количество параметров в функции, для меня тогда это было новой концепцией. Сама функция берет аргументы и записывает их в строку.

## UserService.java
Часть REST API написанного мною на Java, [GitHub](https://github.com/AndrewKley/SocialMedia)
В проекте создается пользователь, его заметки и управление ими чере REST API, для защиты от неавторизованных пользователей или без определенных прав использовалась технология JWT (Json Web Token). В приведенном коде определяются методы для работы с пользователем (поиск пользователя, изменение, преобразование его в DTO - объекты для удаления избыточности в проекте), пароль пользователя шифруется специальным кодировщиком. В проекте есть такие слои абстракиии как: модель, репозиторий, сервис и контроллер. Данный файл - файл сервиса. Использовал при написании проекта технолигию внедрения зависимостей

## vector.tpp
Вектор - динамически расширяющийся массив, заголовочный файл в проекте реализации контейнера вектор в С++, на гитхабе его пока нет.
Наблюдается вся красота и лаконичность C++)) Использовал обобщенные типы (дженерики), переопределение операторов, правило пяти (про конструкторы и переопределение операторов '=') и сопутствующие методы работы с вектором