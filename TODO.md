# TODO - Sửa giao diện Sender (bên phải thêm UI thể loại xu hướng)

- [ ] Bước 1: Xác định chính xác vùng “cột phải” đang rỗng trong `music_security/sender_app.py` (trong CYBERPUNK_UI)
- [ ] Bước 2: Chèn khối UI “Thể loại / Xu hướng” dạng **dọc** chỉ trong cột phải (khối `col-span-1`)
- [ ] Bước 3: Tạo data JavaScript cho các thể loại xu hướng (danh sách bài có `name/artist/img/url/time`)
- [ ] Bước 4: Thêm logic click thể loại → mở panel danh sách bài (gọn trong cột phải)
- [ ] Bước 5: Nút “Chọn” phải gọi `selectForEncrypt(...)` và đồng bộ với `music_file` input
- [ ] Bước 6: Test chạy Flask sender, bấm vào thể loại & chọn bài

