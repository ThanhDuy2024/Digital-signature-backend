const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');
const cors = require('cors')
const app = express();
app.use(express.json());
app.use(cors());

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname)
});
const upload = multer({ storage }); //Dùng để lưu, nhận file bên phía frontend gửi qua backend

// Đọc khóa từ folders keys 
const privateKey = fs.readFileSync(path.join(__dirname, 'keys', 'private.pem'), 'utf8'); 
const publicKey = fs.readFileSync(path.join(__dirname, 'keys', 'public.pem'), 'utf8');

//API ký file
app.post('/sign-file', upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Không có file tải lên' });

  const fileData = fs.readFileSync(req.file.path);

  const sign = crypto.createSign('SHA256');
  sign.update(fileData);
  sign.end();

  const signature = sign.sign(privateKey, 'base64');

  // Tạo tên file .sig dựa trên tên file gốc
  const sigFileName = req.file.filename + '.sig';
  const sigFilePath = path.join(__dirname, 'uploads', sigFileName);

  // Ghi signature vào file .sig
  fs.writeFileSync(sigFilePath, signature);

  // Xóa file gốc sau khi ký (nếu không cần nữa)
  fs.unlinkSync(req.file.path);

  // Trả về file .sig cho client
  res.download(sigFilePath, sigFileName, (err) => {
    if (err) {
      console.error('❌ Lỗi gửi file:', err);
      res.status(500).send('Lỗi khi gửi file .sig');
    }

    // Xóa file .sig sau khi đã gửi xong
    fs.unlinkSync(sigFilePath);
  });
});

const verifyUpload = upload.fields([
  { name: 'file', maxCount: 1 },
  { name: 'signatureFile', maxCount: 1 }
]);

app.post('/verify-file', verifyUpload, (req, res) => {
  const file = req.files?.file?.[0];
  const signatureFile = req.files?.signatureFile?.[0];

  if (!file || !signatureFile) {
    return res.status(400).json({ error: 'Thiếu file hoặc file chữ ký (.sig)' });
  }

  const fileData = fs.readFileSync(file.path);
  const signature = fs.readFileSync(signatureFile.path, 'utf8');

  const verify = crypto.createVerify('SHA256');
  verify.update(fileData);
  verify.end();

  const isValid = verify.verify(publicKey, signature, 'base64');

  // Dọn dẹp file sau khi xử lý
  fs.unlinkSync(file.path);
  fs.unlinkSync(signatureFile.path);

  res.json({
    isValid,
    message: isValid ? '✅ Chữ ký hợp lệ' : '❌ Chữ ký không hợp lệ'
  });
});
  

const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Server chạy tại http://localhost:${PORT}`));
