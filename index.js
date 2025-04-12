const express = require('express');
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const multer = require('multer');

const app = express();
app.use(express.json());

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

  console.log(req.file.originalname);
  const fileData = fs.readFileSync(req.file.path); //đọc file từ phía frontend gửi lên 

  const sign = crypto.createSign('SHA256'); //Tạo đối tượng để ký cho 
  sign.update(fileData);
  sign.end();

  const signature = sign.sign(privateKey, 'base64');

  // Xóa file sau khi xử lý
  fs.unlinkSync(req.file.path);

  const timeSign = Date.now();
  const date = new Date(timeSign);
  const timeInRealLife = date.toLocaleString();

  const datFinal = {
    signature,
    timeInRealLife
  }
  res.json(datFinal);
});

app.post('/verify-file', upload.single('file'), (req, res) => {
    const { signature, timeInRealLife} = req.body;
    if (!req.file || !signature) return res.status(400).json({ error: 'Thiếu file hoặc chữ ký' });
    const fileData = fs.readFileSync(req.file.path);
  
    const verify = crypto.createVerify('SHA256');
    verify.update(fileData);
    verify.end();
  
    const isValid = verify.verify(publicKey, signature, 'base64');
  
    // Xóa file sau khi xử lý
    fs.unlinkSync(req.file.path);
    res.json({
      isValid,
      timeInRealLife: isValid ? timeInRealLife : null
    });
  });
  

const PORT = 3000;
app.listen(PORT, () => console.log(`✅ Server chạy tại http://localhost:${PORT}`));
