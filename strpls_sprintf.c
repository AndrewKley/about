#include "../src_h_files/string_plus.h"

int strpls_sprintf(char *str, const char *format, ...) {
  char *str_begining = str;
  va_list v;
  int len = 0;
  flags flags = {0};

  va_start(v, format);
  while (*format) {
    if (*format != '%') {
      *str++ = *format++;
    } else {
      format++;
      strpls_memset(&flags, 0, sizeof(flags));
      format = parser_flags(format, &flags);
      format = parser_width(format, &flags);
      format = parser_precision(format, &flags);
      format = parser_length(format, &flags);

      flags.specifier = *format;
      format++;

      char buf[CHAR_BUFF_SIZE] = {0};
      get_value(buf, flags, v, len);
      for (int i = strpls_strlen(buf) - 1; i >= 0; i--, str++) {
        *str = buf[i];
        len++;
      }
    }
    *str = '\0';
    va_end(v);
  }
  return str - str_begining;
}

const char *parser_flags(const char *format, flags *flags) {
  while (*format == '-' || *format == '+' || *format == ' ' || *format == '#' ||
         *format == '0') {
    switch (*format) {
      case '-':
        flags->minus = 1;
        format++;
        break;
      case '+':
        flags->plus = 1;
        format++;
        break;
      case ' ':
        flags->space = 1;
        format++;
        break;
      case '#':
        flags->sharp = 1;
        format++;
        break;
      case '0':
        flags->zero = 1;
        format++;
        break;
    }
  }
  return format;
}

const char *parser_width(const char *format, flags *flags) {
  if (strpls_is_digit(*format)) {
    char digit_string[1024] = {'\0'};
    int i = 0;
    while (strpls_is_digit(*format)) {
      digit_string[i] = *format++;
      i++;
    }
    flags->width = strpls_atoi(digit_string);
  } else if (*format == '*') {
    flags->width_is_star = 1;
    format++;
  }
  return format;
}

const char *parser_precision(const char *format, flags *flags) {
  if (*format == '.') {
    flags->precision = -1;
    format++;
    if (strpls_is_digit(*format)) {
      char digit_string[1024] = {'\0'};
      int i = 0;
      while (strpls_is_digit(*format)) {
        digit_string[i] = *format++;
        i++;
      }
      flags->precision =
          strpls_atoi(digit_string) == 0 ? -1 : strpls_atoi(digit_string);
    } else if (*format == '*') {
      flags->precision_is_star = 1;
      format++;
    }
  }
  return format;
}

const char *parser_length(const char *format, flags *flags) {
  switch (*format) {
    case 'h':
      flags->length = 'h';
      format++;
      break;
    case 'l':
      flags->length = 'l';
      format++;
      break;
    case 'L':
      flags->length = 'L';
      format++;
      break;
    default:
      break;
  }
  return format;
}

int strpls_atoi(const char *str) {
  int res = 0;
  int len = strpls_strlen(str);
  for (int i = len - 1; i >= 0; i--) {
    res += (str[i] - 48) * pow(10, (len - i - 1));
  }
  return res;
}

int strpls_is_digit(char c) { return ((c >= 48) && (c <= 57)) ? 1 : 0; }

void strpls_itoa(char *buf, int64_t var, int base) {
  int i = 0;
  int minus = var < 0 ? 1 : 0;
  var = var < 0 ? -var : var;
  if (var == 0) {
    buf[i++] = '0';
  } else {
    while (var > 0) {
      buf[i++] = "0123456789abcdef"[var % base];
      var /= base;
    }
  }
  buf[i] = (minus == 1) ? '-' : '\0';
}

void u_strpls_itoa(char *buf, uint64_t var, int base) {
  int i = 0;
  if (var == 0) {
    buf[i++] = '0';
  } else {
    while (var > 0 && base > 0) {
      buf[i++] = "0123456789abcdef"[var % base];
      var /= base;
    }
  }
}

void char_to_string(char *buf, unsigned char c) { buf[0] = c; }

void get_value(char *buf, flags flags, va_list v, int len) {
  if (flags.width_is_star) {
    flags.width = va_arg(v, int);
  }
  if (flags.precision_is_star) {
    flags.precision = va_arg(v, int);
  }
  if (flags.specifier == 'c') {
    flags.space = 0;
    flags.plus = 0;
    char_to_string(buf, va_arg(v, int));
    edit_width(buf, flags);
    edit_flags(buf, flags);
  } else if (flags.specifier == 'd' || flags.specifier == 'i') {
    get_int(flags, buf, v);
    edit_presicion(buf, flags);
    edit_width(buf, flags);
    edit_flags(buf, flags);
  } else if (flags.specifier == 'e') {
    parse_e(buf, flags, v);
  } else if (flags.specifier == 'E') {
    parse_e(buf, flags, v);
    to_upper(buf);
  } else if (flags.specifier == 'f') {
    parse_f(buf, flags, v);
  } else if (flags.specifier == 's') {
    parse_string(buf, flags, v);
  } else if (flags.specifier == 'u') {
    get_u_int(flags, buf, v);
    edit_width(buf, flags);
    edit_presicion(buf, flags);
    flags.space = 0;
    flags.plus = 0;
    edit_flags(buf, flags);
  } else if (flags.specifier == '%') {
    buf[0] = '%';
  } else if (flags.specifier == 'x') {
    parse_x(buf, flags, v);
  } else if (flags.specifier == 'X') {
    parse_x(buf, flags, v);
    to_upper(buf);
  } else if (flags.specifier == 'o') {
    get_o_int(flags, buf, v);
    edit_sharp(buf, flags);
    edit_width(buf, flags);
    edit_flags(buf, flags);
    edit_presicion(buf, flags);
  } else if (flags.specifier == 'p') {
    get_p_int(flags, buf, v);
    edit_width(buf, flags);
  } else if (flags.specifier == 'n') {
    parse_n(v, len);
  }
}

void parse_string(char *buf, flags flags, va_list v) {
  int count_spaces = 0;
  if (flags.precision > 0) {
    char *res = strpls_NULL;
    res = va_arg(v, char *);
    if (res) {
      char temp[CHAR_BUFF_SIZE] = {0};
      reverse_str(buf, strpls_strncpy(temp, res, flags.precision));
    }
  } else if (flags.precision == 0) {
    reverse_str(buf, va_arg(v, char *));
  }
  count_spaces = edit_width(buf, flags);
  if (flags.minus) {
    moove_left(buf, count_spaces);
  }
  flags.space = 0;
  flags.plus = 0;
  edit_flags(buf, flags);
}

void parse_f(char *buf, flags flags, va_list v) {
  if (flags.precision == 0) {
    flags.precision = 6;
  }
  if (flags.length == 'L') {
    double_to_string_six(buf, va_arg(v, long double), flags);
  } else {
    double_to_string_six(buf, va_arg(v, double), flags);
  }
  edit_width(buf, flags);
  edit_flags(buf, flags);
}

void parse_e(char *buf, flags flags, va_list v) {
  if (flags.length == 'L') {
    double_to_string_e(buf, va_arg(v, long double), flags);
  } else {
    double_to_string_e(buf, va_arg(v, double), flags);
  }
  edit_width(buf, flags);
  edit_flags(buf, flags);
}

void parse_x(char *buf, flags flags, va_list v) {
  get_x_int(flags, buf, v);
  edit_presicion(buf, flags);
  edit_sharp(buf, flags);
  edit_width(buf, flags);
  edit_flags(buf, flags);
}

void parse_n(va_list v, int len) {
  int *p = va_arg(v, int *);
  *p = len;
}

void moove_left(char *buf, int count_spaces) {
  int len = strpls_strlen(buf);
  for (int i = 0; i < count_spaces; i++) {
    for (int k = len - 1; k > 0; k--) {
      char tmp = buf[k];
      buf[k] = buf[k - 1];
      buf[k - 1] = tmp;
    }
  }
}

void edit_presicion(char *buf, flags flags) {
  if (flags.precision > 0) {
    int minus = buf[strpls_strlen(buf) - 1] == '-' ? 1 : 0;
    buf[strpls_strlen(buf) - 1] = minus == 1 ? '\0' : buf[strpls_strlen(buf) - 1];
    if ((int)strpls_strlen(buf) < flags.precision) {
      for (int i = strpls_strlen(buf); i < flags.precision; i++) {
        buf[i] = '0';
      }
    }
    buf[strpls_strlen(buf)] = minus == 1 ? '-' : buf[strpls_strlen(buf)];
  } else if (flags.precision == -1) {
    if (buf[0] == '0' && buf[1] == '\0') {
      buf[0] = '\0';
    }
  }
}

int edit_width(char *buf, flags flags) {
  int count = 0;
  int minus = 0;
  char *tmp = buf + strpls_strlen(buf) - 1;
  if (strpls_strlen(buf) > 0) {
    minus = *tmp == '-' ? 1 : 0;
  }
  while (flags.width > (int)strpls_strlen(buf)) {
    tmp++;
    if (flags.zero && minus) {
      *(tmp - 1) = '0';
      *tmp = '-';
    } else {
      *tmp = flags.zero ? '0' : ' ';
    }
    count++;
  }
  return count;
}

void edit_flags(char *buf, flags flags) {
  int count_spaces = 0;
  for (int i = 0; buf[i] != '\0'; i++) {
    if (buf[i] == ' ') {
      count_spaces++;
    }
  }
  if (flags.minus && flags.width && count_spaces) {
    if (flags.specifier != 's') {
      for (int i = strpls_strlen(buf) - 1; i >= 0; i--) {
        if (buf[i] != ' ') {
          buf[i + count_spaces] = buf[i];
          buf[i] = ' ';
        }
      }
    }
  }
  int last_symb = strpls_strlen(buf);
  if (flags.plus) {
    if (strpls_strlen(buf) > 0) {
      for (int i = strpls_strlen(buf) - 1; buf[i] == ' '; i--) {
        last_symb = i;
      }
    }
    buf[last_symb] = buf[last_symb - 1] == '-' ? buf[last_symb] : '+';
  } else if (flags.space) {
    if (strpls_strlen(buf) > 0) {
      for (int i = strpls_strlen(buf) - 1; buf[i] == ' ' && i > 0; i--) {
        last_symb = i;
      }
      buf[last_symb] = buf[last_symb - 1] == '-' ? buf[last_symb] : ' ';
    }
  }
}

void edit_sharp(char *buf, flags flags) {
  if (flags.sharp) {
    if (flags.specifier == 'o') {
      buf[strpls_strlen(buf)] = '0';
    } else if (flags.specifier == 'x' || flags.specifier == 'X') {
      if (strpls_strspn(buf, "0") != strpls_strlen(buf)) {
        strpls_strcat(buf, "x0");
      }
    }
  }
}

void get_int(flags flags, char *buf, va_list v) {
  int64_t var = va_arg(v, int64_t);
  switch (flags.length) {
    case 0:
      var = (int32_t)var;
      break;
    case 'h':
      var = (int16_t)var;
      break;
  }
  strpls_itoa(buf, var, 10);
}

void get_u_int(flags flags, char *buf, va_list v) {
  uint64_t var = va_arg(v, uint64_t);
  switch (flags.length) {
    case 0:
      var = (uint32_t)var;
      break;
    case 'h':
      var = (uint16_t)var;
      break;
  }
  u_strpls_itoa(buf, var, 10);
}

void get_x_int(flags flags, char *buf, va_list v) {
  uint64_t var = va_arg(v, uint64_t);
  switch (flags.length) {
    case 0:
      var = (uint32_t)var;
      break;
    case 'h':
      var = (uint16_t)var;
      break;
  }
  u_strpls_itoa(buf, var, 16);
}

void get_o_int(flags flags, char *buf, va_list v) {
  uint64_t var = va_arg(v, uint64_t);
  switch (flags.length) {
    case 0:
      var = (uint32_t)var;
      break;
    case 'h':
      var = (uint16_t)var;
      break;
  }
  u_strpls_itoa(buf, var, 8);
}

void get_p_int(flags flags, char *buf, va_list v) {
  uint64_t var = va_arg(v, uint64_t);
  u_strpls_itoa(buf, var, 16);
  edit_presicion(buf, flags);
  buf[strpls_strlen(buf)] = 'x';
  buf[strpls_strlen(buf)] = '0';
}

void double_to_string_e(char *buf, long double var, flags flags) {
  if (flags.precision == 0) {
    flags.precision = 6;
  }
  int minus = var < 0 ? 1 : 0;
  var = var < 0 ? -var : var;
  int exp = 0;

  while (var >= 10) {
    var /= 10;
    exp++;
  }
  while (var < 1 && var > 0) {
    var *= 10;
    exp--;
  }
  for (int i = 0; i < flags.precision; i++) {
    var *= 10;
  }
  var = roundl(var);
  for (int i = 0; i < flags.precision; i++) {
    var /= 10;
  }

  double_to_string_six(buf, var, flags);
  insert_e_notation(buf, exp);
  if (minus) {
    buf[strpls_strlen(buf)] = '-';
  }
}

void insert_last_char(char *buf, char c) {
  for (int i = strpls_strlen(buf) - 1; i >= 0; i--) {
    buf[i + 1] = buf[i];
  }
  buf[0] = c;
}

void to_upper(char *buf) {
  for (int i = 0; buf[i] != '\0'; i++) {
    if (buf[i] >= 97 && buf[i] <= 122) {
      buf[i] = buf[i] - 32;
    }
  }
}

void double_to_string_six(char *buf, long double var, flags flags) {
  if (flags.precision == -1) {
    var = roundl(var);
  }
  int minus = var < 0 ? 1 : 0;
  var = var < 0 ? -var : var;
  long double left = 0;
  long double right = modfl(var, &left);
  long long lleft = left;
  char left_str[50] = {'\0'};
  char right_str[50] = {'\0'};
  for (int i = 0; i < flags.precision; i++) {
    right *= 10;
  }
  long long rright = roundl(right);
  if (rright) {
    strpls_itoa(right_str, rright, 10);
  }
  while (flags.precision != -1 &&
         (int)strpls_strlen(right_str) < flags.precision) {
    right_str[strpls_strlen(right_str)] = '0';
  }
  strpls_itoa(left_str, lleft, 10);
  if (strpls_strlen(right_str)) {
    strpls_strcat(buf, right_str);
    strpls_strcat(buf, ".");
  }
  strpls_strcat(buf, left_str);

  if (minus) {
    buf[strpls_strlen(buf)] = '-';
  }
}

void reverse_str(char *dest, char *src) {
  if (src) {
    int k = 0;
    for (int i = strpls_strlen(src) - 1; i >= 0; i--) {
      dest[k++] = src[i];
    }
  }
}

void insert_e_notation(char *buf, int exp) {
  insert_last_char(buf, 'e');
  char tmp[50] = {'\0'};
  if (exp < 0) {
    insert_last_char(buf, '-');
    exp *= -1;
  } else {
    insert_last_char(buf, '+');
  }
  strpls_itoa(tmp, exp, 10);
  if (strpls_strlen(tmp) == 1) {
    insert_last_char(buf, '0');
    insert_last_char(buf, tmp[0]);
  } else {
    for (int i = 0; i < (int)strpls_strlen(tmp); i++) {
      insert_last_char(buf, tmp[strpls_strlen(tmp) - i - 1]);
    }
  }
}
