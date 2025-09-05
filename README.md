اشکان تاریوردی 401105753، آیین پوست‌فروشان 401105742، نیما موذن 401106599
# QUIC

---

## فهرست مطالب
- [تاریخچهٔ توسعه](#تاریخچهٔ-توسعه)  
- [چرا از TCP به QUIC تغییر دادیم؟](#چرا-از-tcp-به-quic-تغییر-دادیم)  
- [اصول طراحی و مفاهیم کلیدی](#اصول-طراحی-و-مفاهیم-کلیدی)  
   - [ساختار بسته‌ها: Headerهای بلند و کوتاه](#ساختار-بستهها-headerهای-بلند-و-کوتاه)  
   - [فریم‌های اساسی QUIC](#فریمهای-اساسی-quic)  
   - [کنترل Flow و Streams](#streams-و-flow-control)  
   - [نسخه‌گذاری (Versioning) و Negotiation](#نسخهگذاری-versioning-و-negotiation)  
- [رمزنگاری و TLS 1.3 در QUIC](#رمزنگاری-و-tls-13-در-quic)  
- [مدیریت خطا، از دست رفتن بسته و کنترل ازدحام](#مدیریت-خطا-از-دست-رفت-بسته-و-کنترل-ازدحام)  
- [مهاجرت اتصال (Connection Migration)](#مهاجرت-اتصال-connection-migration)  
- [ابزارها و فرمت‌های لاگ و مشاهده (Observability)](#ابزارها-و-فرمتهای-لاگ-و-مشاهده-observability)  
- [روند پذیرش و آمار خلاصه‌شده](#روند-پذیرش-و-آمار-خلاصهشده)
- [چالش‌ها، مسائل امنیتی و حریم خصوصی](#چالشها-مسائل-امنیتی-و-حریم-خصوصی)
- [نمونهٔ کد — سرور و کلاینت ساده با aioquic (Python)](#نمونهٔ-کد--سرور-و-کلاینت-ساده-با-aioquic-python)
- [عیب‌یابی و troubleshooting](#بخش-e--عیبیابی-و-troubleshooting-رایج)
- [پرسش‌های متداول (FAQ)](#پرسشهای-متداول-faq)
- [منابع و مراجع فنی](#منابع-و-مراجع-فنی)
---

## تاریخچهٔ توسعه
- **پیش‌زمینهٔ مفهوم:** از اواخر دههٔ 2000 تیم‌های فنی به‌دنبال راه‌هایی برای کاهش تاخیر صفحات وب و بهبود تجربهٔ کاربران موبایل بودند. TCP به‌دلیل سال‌ها سازوکار و تعامل با تجهیزات شبکه دستخوش «ossification» شده بود؛ این مسئله توسعهٔ ویژگی‌های جدید در لایهٔ انتقال را کند می‌کرد.  
- **۲۰۱۲ — آغاز در گوگل:** مهندسان Chromium/Google (از جمله Jim Roskind و دیگران) شروع به طراحی یک پروتکل مبتنی بر UDP کردند تا handshake و لایهٔ رمزنگاری سریع‌تری فراهم شود. نسخهٔ اولیه «Google QUIC» شامل مولفه‌های مسیریابی، رمزنگاری و multiplexing بود.  
- **۲۰۱۳–۲۰۱6 — آزمایش و استقرار داخلی:** گوگل آزمایش‌های گسترده‌ای روی ترافیک داخلی و سرویس‌هایش انجام داد؛ نتایج اولیه نشان داد که QUIC می‌تواند زمان بارگذاری را کاهش دهد و تجربهٔ کاربر را بهبود بخشد.  
- **۲۰۱6–2021 — استانداردسازی توسط IETF:** با توجه به نتایج امیدوارکننده، طرح به IETF منتقل شد تا به‌صورت یک استاندارد باز و قابل پیاده‌سازی گسترده مطرح شود. کارگروه‌های IETF مفاهیم را بازنویسی کردند تا با اهداف بین‌المللی و تعامل میان پیاده‌سازی‌ها سازگار شوند.  
- **۲۰۲۱ — RFCها و QUIC v1:** مجموعه‌ای از RFCها (مانند RFC 9000, 9001 و 9002) منتشر و QUIC v1 رسمی شد. پس از آن، مرورگرها و CDNها در مسیر پذیرش و استقرار گسترده‌تر قرار گرفتند.  
- **۲۰۲۱–تا کنون:** پذیرش تجاری و ابزارهای پشتیبانی افزایش یافت؛ جامعهٔ متن‌باز منابع متعدد (quiche, msquic, ngtcp2, aioquic و غیره) را توسعه داد و تحقیقات عملی و نظری زیادی پیرامون مسائل مثل مهاجرت اتصال، congestion control و مانیتورینگ انجام شد.

---

## چرا از TCP به QUIC تغییر دادیم؟
1. **Ossification در اکوسیستم شبکه:** تجهیزات میانی (فایروال‌ها، NATها، load balancerها) رفتار TCP را به‌عنوان فرض پیش‌فرض دارند و بسیاری از تغییرات جدید را بلاک یا تغییر می‌دهند. با انتقال به UDP و رمزنگاری سرآیندها، QUIC می‌تواند ویژگی‌های جدید را بدون برخورد با این گونه محدودیت‌ها توسعه دهد.  
2. **بهبود زمان برقراری ارتباط:** در TCP+TLS سنتی ابتدا TCP handshake (دو یا سه‌طرفه) و سپس TLS handshake انجام می‌شود. QUIC این دو مرحله را ترکیب یا به هم نزدیک می‌کند و امکان 0-RTT/1-RTT را فراهم می‌آورد؛ مخصوصاً برای ارتباطات مکرر این به‌معنای کاهش مشهود تاخیر است.  
3. **کاهش Head-of-Line Blocking در سطح حمل‌ونقل:** حتی اگر HTTP/2 روی TCP multiplexing را فراهم کند، بستهٔ از دست‌رفته در TCP باعث توقف تمام جریان‌ها می‌شود. QUIC با streamهای جداگانه که هر کدام وضعیت تحویل خود را دارند، این مشکل را کاهش می‌دهد.  
4. **انعطاف‌پذیری در کنترلی از قبیل congestion control:** QUIC پیاده‌سازی‌ها را قادر می‌سازد تا الگوریتم کنترل ازدحام خود را انتخاب یا تعویض کنند بدون نیاز به تغییر در لایهٔ شبکه. این موضوع برای بهینه‌سازی در محیط‌های مختلف (موبایل، ماهواره، شبکه‌های با تأخیر بالا) حیاتی است.  
5. **مهاجرت اتصال و مدیریت حرکت کلاینت:** QUIC با استفاده از Connection ID امکان حفظ‌های session را هنگام تغییر 4‑tuple آدرس/پورت فراهم می‌کند (مثلاً تغییر بین شبکه‌های موبایل و Wi‑Fi).

---

## اصول طراحی و مفاهیم کلیدی

### ساختار بسته‌ها: Headerهای بلند و کوتاه
QUIC دو نوع header اصلی دارد: **Long Header** و **Short Header**.
- **Long Header:** برای رویدادهایی مانند برقراری اولیهٔ اتصال (Initial)، version negotiation، و handshakes استفاده می‌شود. این header شامل فیلد نسخه و اطلاعاتی برای negotiation است.  
- **Short Header:** پس از ختم handshake و زمان داشتن کلیدهای ارتباطی کوتاه، از short header استفاده می‌شود که کم‌حجم‌تر است و برای ارسال داده‌های معمولی (1-RTT) به‌کار می‌رود.

### فریم‌های اساسی QUIC
QUIC اطلاعات را در قالب فریم‌ها جابجا می‌کند. برخی از فریم‌های مهم شامل:
- **STREAM:** حمل داده‌های یک stream مشخص.  
- **ACK:** تأیید دریافت بسته‌ها؛ QUIC از بازه‌های ACK و گزارش‌های SACK‑مانند پشتیبانی می‌کند.  
- **PADDING:** فضاگیر کردن بسته برای جلوگیری از تحلیل اندازه یا مسائل MTU.  
- **CONNECTION_CLOSE / APPLICATION_CLOSE:** بستن اتصال.  
- **MAX_DATA / MAX_STREAM_DATA:** کنترل جریان کلی و جریان هر stream.  
- **NEW_CONNECTION_ID / RETIRE_CONNECTION_ID:** مدیریت Connection ID برای مهاجرت و load balancing.  
- **PATH_CHALLENGE / PATH_RESPONSE:** برای اعتبارسنجی مسیر در مهاجرت اتصال.  
- **HANDSHAKE / CRYPTO:** فریم‌های مرتبط با تبادل داده‌های TLS و سرآیندهای رمزنگاری.

> هر پیاده‌سازی ممکن است تعداد بیشتری فریم پشتیبانی کند؛ RFCها فهرست کامل را ارائه می‌دهند.

### Streams و Flow Control
- Streams می‌توانند دوطرفه یا یک‌طرفه باشند و هر stream دارای window کنترل جریان (flow control window) است. این مکانیزم باعث جلوگیری از مصرف بی‌حد و حصر حافظهٔ طرف گیرنده می‌شود.  
- Flow control در دو سطح اجرا می‌شود: سطح اتصال (MAX_DATA) و سطح هر stream (MAX_STREAM_DATA).

### نسخه‌گذاری (Versioning) و Version Negotiation
QUIC از فیلد نسخه در header جهت مدیریت تکامل استفاده می‌کند. در صورتی که دو طرف نسخهٔ متفاوتی پشتیبانی کنند، mekanism version negotiation روشن می‌شود که به آن‌ها اجازه می‌دهد نسخهٔ مشترک را انتخاب یا fallback انجام دهند.

---

## رمزنگاری و TLS 1.3 در QUIC
- QUIC از TLS 1.3 برای مذاکرهٔ کلیدها و تأمین محرمانگی و یکپارچگی استفاده می‌کند، اما اجرای TLS در QUIC تفاوت‌هایی با TCP+TLS دارد: داده‌های TLS داخل فریم‌های QUIC (CRYPTO) منتقل می‌شوند و پس از تکمیل handshake کلیدهای مناسب برای رمزنگاری بسته‌های QUIC تولید می‌شوند.  
- **0-RTT:** QUIC امکان ارسال داده‌های اولیه (0-RTT) را در شرایطی که کلاینت قبلاً ارتباطی داشته و توکن/پارامترهای لازم را دارد، فراهم می‌کند؛ این موضوع با ریسک بازپخش (replay) همراه است و باید محتاطانه استفاده شود.  
- **Header Encryption:** بسیاری از قسمت‌های header و سرآیندهای حمل‌ونقلی در QUIC محافظت یا رمزگذاری می‌شوند تا مانع تحلیل و تغییر در مسیر شوند.

---

## مدیریت خطا، از دست رفتن بسته و کنترل ازدحام
- **Loss Detection:** QUIC از ترکیبی از ACK-based و timer-based detection استفاده می‌کند (مانند PTO — Probe Timeout). الگوریتم‌های تشخیص از دست رفتن بسته مشابه TCP اما با تفاوت در اینکه QUIC می‌تواند بسته‌های مستقل stream را مجدداً ارسال کند.  
- **Pacing و Congestion Control:** QUIC به‌طور کلی اجازهٔ اجرای الگوریتم‌های مختلف کنترل ازدحام (CUBIC, BBR و غیره) را می‌دهد. برخی پیاده‌سازی‌ها نسخه‌های بهینه‌شده‌ای برای محیط‌های خاص ارائه کرده‌اند.  
- **Recovery:** QUIC دارای مکانیزم‌های بازیابی برای ارسال مجدد بسته‌ها، تنظیم ریت و مدیریت retransmission است.

---

## مهاجرت اتصال (Connection Migration)
- **Connection ID:** شناسهٔ اتصال مستقل از 4‑tuple آدرس/پورت است. کلاینت/سرور می‌توانند چند Connection ID صادر کنند تا امکان مهاجرت و load balancing فراهم گردد.  
- **مسیر و چالش‌ها:** وقتی کلاینت IP خود را تغییر می‌دهد، سرور ممکن است قبل از پذیرش مسیر جدید، PATH_CHALLENGE ارسال کند تا صحت مسیر و مالکیت آدرس را بررسی نماید.  
- **عملیات در عمل:** بسیاری از پیاده‌سازی‌ها مهاجرت را پشتیبانی می‌کنند، اما عملکرد واقعی در اینترنت عمومی به پشتیبانی تجهیزات شبکه و NAT بستگی دارد.

---

## ابزارها و فرمت‌های لاگ و مشاهده (Observability)
- **Wireshark:** از QUIC و TLS 1.3 پشتیبانی می‌کند (با توجه به نسخه‌ها و فایل‌های تکمیل‌شده برای رمزگشایی).  
- **qlog / qvis:** فرمت لاگ متن‌باز برای ذخیرهٔ اطلاعات تعامل QUIC؛ ابزارهایی برای نمایش گرافیکی آن وجود دارد.  
- **quictrace / ngtcp2 tools:** ابزارهای کمکی برای تحلیل ترافیک و اندازه‌گیری.  
- **Server-side telemetry:** به دلیل رمزنگاری، جمع‌آوری متریک‌ها و Telemetry در سمت سرور اهمیت بیشتری دارد (latency histograms, loss, RTT, PTO counts, stream stats).

---

## روند پذیرش و آمار خلاصه‌شده

در چند سال اخیر پذیرش QUIC و HTTP/3 رشد سریعی داشته است؛ در ادامه آمارهای گزیده، منابع و نکاتی برای فهم بهتر وضعیت فعلی آورده شده است — دقت کنید که آمارها براساس معیارهای متفاوت (درصد وب‌سایت‌ها، درصد ترافیک، منطقهٔ جغرافیایی) متغیرند و برای تصمیم‌گیری‌های دقیق باید به گزارش اصلی مراجعه کنید.

- **سهم استفادهٔ HTTP/3 در وب‌سایت‌ها:** گزارش W3Techs نشان می‌دهد که HTTP/3 توسط حدود **۳۵.۵٪** از وب‌سایت‌ها استفاده می‌شود (آمار مربوط به آگوست ۲۰۲۵).

- **سهم استفادهٔ QUIC به‌عنوان المان سایت:** W3Techs همچنین گزارش می‌دهد که **QUIC** به‌عنوان المان سایت در حدود **۸.۸٪** از وب‌سایت‌ها مشاهده می‌شود (این معیار متفاوت از «HTTP/3 روی ترافیک» است و بیشتر نشان‌دهندهٔ پیکربندی سرورهاست).

- **سهم ترافیک HTTP/3 در شبکه‌ها (مثال Cloudflare):** تحلیل‌های Cloudflare نشان می‌دهند که درصد ترافیک HTTP/3 در دوره‌هایی به حدود **۴۵٪** رسیده و سپس به‌طور نوسانی در محدودهٔ حدود **۴۰٪** دیده شده است — الگوها به منطقه و نوع ترافیک بستگی دارد (مثلاً دسکتاپ در مقابل موبایل تفاوت‌هایی نشان می‌دهد). این ارقام نشان‌دهندهٔ سهم ترافیک (requests) است، نه صرفاً درصد سایت‌ها.

- **نمونهٔ منطقه‌ای:** در گزارش‌های منطقه‌ای Cloudflare (مثلاً ایالات متحده) مقادیر متفاوتی گزارش شده‌اند؛ برای مثال در یک سال مشخص گزارش‌هایی مانند **~۱۷٪** ترافیک HTTP/3 در ایالات متحده نیز ثبت شده است — این مثال نشان‌دهندهٔ تنوع قابل‌توجه بین مناطق است. برای تحلیل منطقه‌ای به صفحات Cloudflare Radar مراجعه کنید.

- **منابع تحلیلی بلندمدت:** HTTP Archive و Web Almanac فصل‌هایی دربارهٔ رشد HTTP/3 و پیامدهای آن منتشر کرده‌اند که روند بلندمدت افزایش پشتیبانی کلاینت‌ها/سرور‌ها و تأثیر بر زمان بارگذاری صفحات را نشان می‌دهد. این منابع برای تحلیل تاریخی و مقایسهٔ معیارها بسیار مفید هستند.

**نکات مهم در تفسیر آمار:**  
1. «درصد سایت‌ها» (مثل W3Techs) نشان می‌دهد چه تعداد سایت پشتیبانی را فعال کرده‌اند، اما لزوماً نشان‌دهندهٔ سهم ترافیک واقعی نیست (سایت‌های پر ترافیک وزن بیشتری در بررسی ترافیک دارند).  
2. «درصد ترافیک» (مثل Cloudflare Radar) منعکس‌کنندهٔ واقعیاتی است که کاربران تجربه می‌کنند، اما تحت تأثیر ترکیب مشتریان ترافیکی آن CDN قرار دارد.  
3. برای گزارش‌ها و تصمیم‌گیری‌های عملی همیشه از منبع اصلی (Cloudflare/W3Techs/HTTP Archive) و بازهٔ زمانی مشخص استفاده کنید؛ ارقام سریع تغییر می‌کنند و معیارها (سایت‌ها vs ترافیک) تفاوت معنی‌داری دارند.

## چالش‌ها، مسائل امنیتی و حریم خصوصی
- **بازپخش RTT-0:** 0-RTT می‌تواند داده‌ها را آسیب‌پذیر به replay کند؛ توصیه می‌شود از آن فقط برای درخواست‌های idempotent استفاده شود یا مکانیزم‌های محافظتی اتخاذ گردد.  
- **ردیابی Connection ID:** Connection ID می‌تواند برای تعقیب جلسات توسط شرکت‌های میانی مورد سوءاستفاده قرار گیرد؛ طراحی IDها باید حریم خصوصی را در نظر بگیرد (مثلاً rotation، کوتاه بودن عمر).  
- **تجزیه و تحلیل ترافیک رمزنگاری‌شده:** به‌دلیل رمزنگاری، تحلیل ترافیک دشوارتر است و ممکن است مانیتورینگ داخلی نیازمند توسعهٔ ابزارهای جدید باشد.  
- **حفره‌های ناشی از پیاده‌سازی:** همانند همه پروتکل‌ها، پیاده‌سازی‌ها ممکن است با نقص‌هایی همراه باشند؛ بنابرین استفاده از نسخه‌های به‌روز و audit اهمیت دارد.

---

## نمونهٔ کد — سرور و کلاینت ساده با aioquic (Python)
**سرور ساده (server.py):**
```python

import argparse
import asyncio
from typing import Optional

from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


class EchoProtocol(QuicConnectionProtocol):
    """A minimal QUIC echo protocol.

    For every received stream fragment, immediately echo it back on the same stream.
    """

    def quic_event_received(self, event: QuicEvent) -> None:  # type: ignore[override]
        if isinstance(event, StreamDataReceived):
            # Echo back the bytes and mirror end_stream so the client sees EOF.
            self._quic.send_stream_data(event.stream_id, event.data, end_stream=event.end_stream)
            self.transmit()


async def main(host: str, port: int, certificate: str, private_key: str, secrets_log: Optional[str]) -> None:
    # Configure QUIC with a self-signed certificate. ALPN "hq-29" is fine for a raw QUIC demo.
    configuration = QuicConfiguration(is_client=False, alpn_protocols=["hq-29"])  # type: ignore[arg-type]
    configuration.load_cert_chain(certificate, private_key)

    if secrets_log:
        configuration.secrets_log_file = open(secrets_log, "a")

    server = await serve(
        host,
        port,
        configuration=configuration,
        create_protocol=EchoProtocol,
        retry=False,
    )
    print(f"QUIC echo server listening on {host}:{port}")

    try:
        # Run until Ctrl+C
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal QUIC echo server (aioquic)")
    parser.add_argument("--host", default="127.0.0.1", help="Listen address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4433, help="UDP port (default: 4433)")
    parser.add_argument("--certificate", default="quic.crt", help="Path to certificate (PEM)")
    parser.add_argument("--private-key", dest="private_key", default="quic.key", help="Path to private key (PEM)")
    parser.add_argument("--secrets-log", default="ssl_keylog.txt", help="Optional TLS secrets log file for Wireshark")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.certificate, args.private_key, args.secrets_log))
```

**کلاینت ساده (client.py):**
```python

import argparse
import asyncio
import ssl
from typing import Optional

from aioquic.asyncio import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


class SimpleClient(QuicConnectionProtocol):
    """A tiny QUIC client that sends one message and collects the echo."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()

    def quic_event_received(self, event: QuicEvent) -> None:  # type: ignore[override]
        if isinstance(event, StreamDataReceived):
            # Collect echoed data from the server
            self._queue.put_nowait(event.data)

    async def send_and_receive(self, data: bytes) -> bytes:
        stream_id = self._quic.get_next_available_stream_id()
        self._quic.send_stream_data(stream_id, data, end_stream=True)
        self.transmit()
        return await asyncio.wait_for(self._queue.get(), timeout=5.0)


async def main(host: str, port: int, message: str, secrets_log: Optional[str]) -> None:
    # Client QUIC configuration. We disable cert verification for this local demo.
    configuration = QuicConfiguration(is_client=True, alpn_protocols=["hq-29"])  # type: ignore[arg-type]
    configuration.verify_mode = ssl.CERT_NONE  # trust our self-signed server for the demo

    if secrets_log:
        configuration.secrets_log_file = open(secrets_log, "a")

    async with connect(host, port, configuration=configuration, create_protocol=SimpleClient) as client:
        proto: SimpleClient = client  # type: ignore[assignment]
        data = await proto.send_and_receive(message.encode("utf-8"))
        print(data.decode("utf-8"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Minimal QUIC client (aioquic)")
    parser.add_argument("--host", default="127.0.0.1", help="Server address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4433, help="UDP port (default: 4433)")
    parser.add_argument("--message", default="Hello on QUIC Protocol!", help="Message to send")
    parser.add_argument("--secrets-log", default="ssl_keylog.txt", help="Optional TLS secrets log file for Wireshark")
    args = parser.parse_args()

    asyncio.run(main(args.host, args.port, args.message, args.secrets_log))

```
**نحوه اجرا**:
آماده‌سازی محیط
```bash
sudo apt-get update
sudo apt-get install -y python3-venv wireshark openssl
cd "$HOME/web/quic_demo"
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

**ایجاد یک گواهی محلی**:
```bash
openssl req -x509 -newkey rsa:2048 -keyout quic.key -out quic.crt -days 365 -nodes -subj "/CN=localhost"
```

**اجرای سرور**:
```bash
cd "$HOME/web/quic_demo"
source .venv/bin/activate
python3 server.py --host 127.0.0.1 --port 4433 --certificate quic.crt --private-key quic.key
```

**اجرای کلاینت**:
```bash
cd "$HOME/web/quic_demo"
source .venv/bin/activate
python3 client.py --host 127.0.0.1 --port 4433 --message "Hello on QUIC Protocol!"
```
---

## عیب‌یابی و Troubleshooting رایج

### 1) handshake failure / TLS errors
- بررسی لاگ‌های سرور (NGINX/Envoy/Caddy) و لاگ‌های پیاده‌سازی QUIC.  
- با curl `-v` و سوئیچ `--http3` تست کنید؛ خروجی handshake و ALPN را بررسی کنید:  
```bash
curl -v --http3 https://example.com
```
- اگر از self-signed استفاده می‌کنید برای تست از `--insecure` در محیط توسعه استفاده کنید.

### 2) HTTP/3 negotiation fail (client falls back to HTTP/2)
- بررسی هدر `Alt-Svc` در پاسخ‌ها (سرور باید اعلام کند که HTTP/3 در پورت/آدرس مشخص فعال است).  
- بررسی پشتیبانی QUIC در مسیر (firewall/NAT/ISP ممکن است UDP را مسدود کند).

### 3) Path validation یا migration failure
- اگر مهاجرت مسیر ناموفق است، در لاگ‌ها دنبال `PATH_CHALLENGE`/`PATH_RESPONSE` و خطاهای validation بگردید.  
- بررسی کنید که NATها یا middleboxها آدرس/پورت جدید را مسدود نمی‌کنند.

### 4) Packet loss یا throughput پایین
- با qlog/qvis و متریک‌های Prometheus میزان lost/retransmission و RTT را تحلیل کنید.  
- تست با شبیه‌سازهای شبکه (tc/netem) برای تولید loss/latency و بررسی رفتار congestion control مفید است.

### 5) Problems with load balancer / affinity
- بررسی کنید load balancer شما چگونه Connection IDها را مدیریت می‌کند؛ نیاز به sticky behavior یا اشتراک state بین نمونه‌ها ممکن است وجود داشته باشد.

---

## پرسش‌های متداول (FAQ)
**آیا QUIC جایگزین TCP می‌شود؟**  
نه لزوماً؛ QUIC رقیبی برای TCP در بسیاری از سناریوهاست، مخصوصاً در انتقال‌های HTTP/3، اما TCP به‌خصوص در مواردی مانند برخی پروتکل‌های قدیمی‌تر یا لایه‌های پایین‌تر هنوز کاربرد دارد.

**آیا همه مرورگرها HTTP/3 را پشتیبانی می‌کنند؟**  
بسیاری از مرورگرهای مدرن پشتیبانی را افزوده‌اند، اما برای اطلاعات دقیق نسخه‌ها و وضعیت پشتیبانی باید به اسناد رسمی مرورگرها و گزارش‌های آماری مراجعه کرد.

**آیا فعال‌سازی QUIC همیشه باعث بهبود می‌شود؟**  
در اکثر موارد بله، اما نتیجهٔ واقعی بستگی به شبکهٔ کاربر، پشتیبانی میانه‌راه (NAT، firewalls) و پیکربندی سرور دارد.

---

## منابع و مراجع فنی
- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://datatracker.ietf.org/doc/html/rfc9000) 
- [RFC 9001 — Using TLS to Secure QUIC](https://datatracker.ietf.org/doc/html/rfc9001)
- [RFC 9002 — QUIC Loss Detection and Congestion Control](https://datatracker.ietf.org/doc/html/rfc9002)  
- [QUIC — a multiplexed transport over UDP](https://www.chromium.org/quic/?utm_source=chatgpt.com)
- [Cloudflare Radar / Year in Review](https://blog.cloudflare.com/radar-2024-year-in-review/?utm_source=chatgpt.com/)
- [W3Techs — Usage Statistics of HTTP/3](https://w3techs.com/technologies/details/ce-http3?utm_source=chatgpt.com)
- [HTTP Archive — Web Almanac](https://almanac.httparchive.org/en/2024/http?utm_source=chatgpt.com)
- [Aioquic Documentation](https://aioquic.readthedocs.io/en/latest/)
