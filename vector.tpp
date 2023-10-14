namespace abr {

template <typename T>
abr::vector<T>::vector(std::initializer_list<T> const &items) {
  size_ = capacity_ = items.size();
  array_ = new T[size_];
  std::copy(items.begin(), items.end(), array_);
}

template <typename T>
abr::vector<T>::vector(const vector<T> &v) {
  size_ = v.size_;
  capacity_ = v.capacity_;
  array_ = new T[size_];
  for (size_type i = 0; i < size_; i++) {
    array_[i] = v.array_[i];
  }
}

template <typename T>
abr::vector<T>::vector(vector<T> &&v) {
  size_ = v.size_;
  capacity_ = v.capacity_;
  array_ = v.array_;
  v.size_ = 0;
  v.capacity_ = 0;
  v.array_ = nullptr;
}

template <typename T>
abr::vector<T> &abr::vector<T>::operator=(vector &&v) noexcept {
  if (this != &v) {
    delete[] array_;
    size_ = v.size_;
    capacity_ = v.capacity_;
    array_ = v.array_;
    v.size_ = 0;
    v.capacity_ = 0;
    v.array_ = nullptr;
  }

  return *this;
}

template <typename T>
typename abr::vector<T>::reference abr::vector<T>::at(size_type pos) {
  if (pos >= size_) {
    throw std::out_of_range("Index out of range");
  }
  return array_[pos];
}

template <typename T>
typename abr::vector<T>::reference abr::vector<T>::operator[](size_type pos) {
  if (pos >= size_) {
    throw std::out_of_range("Index out of range");
  }
  return array_[pos];
}

template <typename T>
void abr::vector<T>::reserve(size_type size) {
  if (size > vector::max_size()) {
    throw std::length_error("The size cannot be larger than the max size");
  }

  if (size_ < size) {
    T *new_array = new T[size];
    std::copy(array_, array_ + size_, new_array);
    delete[] array_;
    array_ = new_array;
    capacity_ = size;
  }
}

template <typename T>
void abr::vector<T>::shrink_to_fit() noexcept {
  if (size_ < capacity_) {
    capacity_ = size_;
    T *tmp_arr = new T[size_];
    for (size_type i = 0; i < size_; i++) {
      tmp_arr[i] = array_[i];
    }
    delete[] array_;
    array_ = tmp_arr;
    tmp_arr = nullptr;
  }
}

template <typename T>
void abr::vector<T>::clear() noexcept {
  delete[] array_;
  array_ = nullptr;
  size_ = 0;
}

template <typename T>
typename abr::vector<T>::iterator abr::vector<T>::insert(
    iterator pos, const_reference value) {
  size_type i = &(*pos) - array_;
  if (i >= size_ && size_ != 0) {
    throw std::out_of_range("Index out of range");
  } else if (size_ == 0) {
    array_ = new value_type[1];
    size_ = 1;
    capacity_ = 1;
    array_[0] = value;
  } else {
    if (size_ + 1 >= capacity_) {
      reserve(size_ == 0 ? 1 : size_ * 2);
    }

    size_++;
    value_type tmp = array_[i];
    array_[i] = value;

    for (size_type j = i + 1; j < size_; j++) {
      value_type cur = array_[j];
      array_[j] = tmp;
      tmp = cur;
    }
  }

  return pos;
}

template <typename T>
void abr::vector<T>::erase(iterator pos) {
  size_type i = &(*pos) - array_;
  if (i >= size_) {
    throw std::out_of_range("Index out of range");
  }

  i = pos == end() - 1 ? i + 1 : i;
  for (i++; i < size_; i++) {
    array_[i - 1] = array_[i];
  }
  size_--;
}

template <typename T>
void abr::vector<T>::push_back(const_reference value) {
  if (size_ == capacity_) {
    reserve(size_ == 0 ? 1 : size_ * 2);
  }
  array_[size_++] = value;
}

template <typename T>
void abr::vector<T>::swap(vector &other) {
  std::swap(size_, other.size_);
  std::swap(capacity_, other.capacity_);
  std::swap(array_, other.array_);
}

}  // namespace abr
