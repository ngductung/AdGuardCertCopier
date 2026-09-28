# R8 rules cho bản release.
# libsu, OkHttp, coroutines và AndroidX đã kèm consumer rules riêng nên không cần khai báo thêm.
# App không dùng reflection; nếu sau này thêm code gọi qua reflection thì bổ sung -keep tại đây.

# Giữ số dòng trong stack trace để đọc crash log (kết hợp với build/outputs/mapping/release/mapping.txt)
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
