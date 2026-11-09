# NUDL Backend — FastAPI

دا د ننګرهار پوهنتون د ډیجیټل کتابتون Backend دی.

## امکانات
- د محصل، استاد او اډمین حسابونه
- ثبت، Login او JWT authentication
- د PDF اپلوډ (تر 25MB پورې)
- د اډمین تر تأیید وروسته د کتاب خپرېدل
- د PDF ډاونلوډ او د ډاونلوډ شمېر
- د کتابونو لټون، کتګورۍ او څانګې
- د اډمین Dashboard، د کتابونو تأیید/رد/ړنګول
- د کاروونکو لېست او د حساب فعال/غیرفعال کول
- د ډېرو ډاونلوډ شویو کتابونو راپور

## په Windows 11 کې چلول
1. Python 3.10+ نصب کړئ.
2. د دې فولډر دننه Terminal خلاص کړئ.
3. دا امرونه ولیکئ:

```powershell
py -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

4. API: `http://127.0.0.1:8000`
5. د API ازموینه: `http://127.0.0.1:8000/docs`

## لومړنی اډمین
- Email: `admin@nudl.edu`
- Password: `ChangeMe123!`

دا یوازې د محلي ازموینې لپاره دی. د خپرولو مخکې په `.env` یا Hosting Environment کې قوي `NUDL_SECRET_KEY` او نوی `NUDL_ADMIN_PASSWORD` وټاکئ. هېڅکله د اصلي پوهنتون د کار لپاره پورته Default پاسورډ مه پرېږدئ.

## د Frontend سره نښلول
- د ثبت API: `POST /api/auth/register`
- د ننوتلو API: `POST /api/auth/login`
- د کاروونکي معلومات: `GET /api/auth/me`
- کتابونه: `GET /api/books`
- اپلوډ: `POST /api/books/upload` (FormData کې `pdf_file`)
- ډاونلوډ: `GET /api/books/{id}/download`
- اډمین راپور: `GET /api/admin/dashboard`

د Login ځواب کې `access_token` راځي. د نورو خوندي API غوښتنو Header داسې واستوئ:
`Authorization: Bearer YOUR_ACCESS_TOKEN`

## مهم امنیتي یادښت
دا د پراختیا او لومړني Prototype Backend دی. د رسمي استعمال لپاره HTTPS، د ایمیل تایید، د پاسورډ بیا ترلاسه کول، د Rate limiting، د فایلونو malware scanning، د بیک اپ تګلاره، د کتابونو د کاپي‌رایټ اجازه، د محرمیت تګلاره او د اډمین لپاره قوي امنیت باید اضافه شي. د څو سرورونو یا لویو فایلونو لپاره د SQLite پر ځای PostgreSQL او د فایلونو لپاره خوندي object storage وکاروئ.
