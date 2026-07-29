# Plain-language explanations, keyed by finding id

This file holds one plain-language explanation for every finding ClaudeGuardIL can produce,
written for non-expert "vibecoders" — people who built an app with an AI tool (Base44, Lovable,
Cursor, v0, Bolt) and do not speak security jargon.

The renderer looks up the entry by the finding's `id` (for example `CG-DB-001`) and prints it as
a single **"בפשטות / In plain words"** line beneath the technical finding. Each entry has two
parts: `HE` (Hebrew) and `EN` (English).

**Hebrew is the authoritative version for this audience.** English is provided for completeness,
but when the two differ in tone, trust the Hebrew — it is the one written for the reader.

Every explanation follows the same shape: what is actually exposed or broken, why it matters in
real terms, and one concrete thing to do. Findings that are uncertain (evidence is weak) say so
plainly — "ייתכן", "כדאי לבדוק" — and are never presented as proven.

---

## CG-ENV-001
**HE:** המפתח הכי חזק של מסד הנתונים שלך — כזה שנותן שליטה מלאה — נשלח לדפדפן של כל מי שנכנס לאתר. כל אחד יכול ללחוץ F12, למצוא אותו, ולקרוא או למחוק את כל המידע, כולל של המשתמשים שלך. זו לא "אולי" בעיה — זו דלת פתוחה לרווחה. מה עושים: מחליפים את המפתח עכשיו (הישן כבר נחשף), ומעבירים אותו לצד השרת שבו רק הקוד שלך רואה אותו.
**EN:** The most powerful key to your database — the one that grants full control — is being sent to the browser of everyone who visits your site. Anyone can press F12, find it, and read or delete all your data, including your users'. This is not a "maybe" — it is a wide-open door. What to do: rotate the key now (the old one is already burned) and move it to the server side, where only your code can see it.

## CG-ENV-002
**HE:** משתנה בשם שנראה כמו מפתח סודי מוגדר להישלח לדפדפן (מאחורי קידומת ציבורית כמו NEXT_PUBLIC_). זה לא בהכרח בעיה — הרבה מפתחות כאלה נועדו להיות ציבוריים, למשל מפתח מפה או מזהה של שירות ניתוח. כדאי לבדוק מה המפתח הזה עושה בפועל: אם הוא רק מזהה ציבורי, הכול תקין; אם הוא נותן גישה אמיתית למידע, זו חשיפה שצריך לתקן מיד. פשוט ודאו איזה סוג מפתח זה.
**EN:** A variable whose name looks like a secret is set to be sent to the browser (behind a public prefix like NEXT_PUBLIC_). This is not necessarily a problem — many such keys are meant to be public, like a maps key or an analytics id. It is worth checking what this key actually does: if it is only a public identifier, all is fine; if it grants real access to data, this is an exposure to fix now. Just confirm which kind of key it is.

## CG-ENV-003
**HE:** משתנה סביבה נקרא מתוך קוד שרץ בדפדפן, אבל אין לו קידומת ציבורית — ולכן הוא פשוט לא יגיע לדפדפן ויהיה ריק (undefined) שם. זו לא חשיפת מידע: אף אחד לא רואה כלום, פשוט הפיצ'ר שתלוי במשתנה הזה לא יעבוד כמו שצריך. שימו לב שהפיתוי הוא "לתקן" את זה בהוספת קידומת ציבורית — אבל דווקא זה כן יחשוף סוד; הפתרון הנכון הוא להעביר את הקריאה לצד השרת.
**EN:** An environment variable is read from code that runs in the browser, but it has no public prefix — so it simply will not reach the browser and will be empty (undefined) there. This is not a data leak: no one sees anything, the feature that depends on this variable just will not work correctly. Note that the tempting "fix" is to add a public prefix — but that is exactly what would expose a secret; the right fix is to move the read to the server side.

## CG-ENV-004
**HE:** בקובץ הדוגמה .env.example יש שילוב מסוכן: שם שנראה כמו סוד יחד עם קידומת ציבורית (כמו NEXT_PUBLIC_). כרגע אין כאן שום סוד אמיתי — הקובץ ריק מערכים. אבל האדם הבא שימלא את הקובץ לפי הדוגמה ישלח סוד אמיתי היישר לדפדפן, בלי לשים לב. שווה לתקן את התבנית עכשיו כדי למנוע טעות עתידית.
**EN:** The example file .env.example contains a dangerous combination: a name that looks like a secret together with a public prefix (like NEXT_PUBLIC_). Right now there is no real secret here — the file has no values. But the next person who fills it in by following the example will send a real secret straight to the browser, without noticing. It is worth fixing the template now to prevent a future mistake.

## CG-WEB-001
**HE:** לנקודת הקצה (endpoint — כתובת שהשרת שלך חושף) הזו לא נמצא אימות גלוי, כלומר לא ראינו קוד שבודק שהמשתמש מחובר. ייתכן שהבדיקה קיימת בקובץ אחר שהקוד הזה משתמש בו, ולכן כדאי לבדוק. אם באמת אין אימות, כל אחד באינטרנט יכול לקרוא לנקודה הזו בלי להתחבר — ולפי מה שהיא עושה, לקרוא או לשנות מידע של משתמשים. ודאו שיש כאן בדיקת התחברות לפני שהפעולה מתבצעת.
**EN:** This endpoint (an address your server exposes) has no visible authentication — we saw no code that checks the user is logged in. It is possible the check lives in another file this code imports, so it is worth verifying. If there really is no auth, anyone on the internet can call this endpoint without logging in — and depending on what it does, read or change users' data. Make sure there is a login check before the action runs.

## CG-WEB-002
**HE:** הנתיב הזה מקבל מידע מהמשתמש (גוף הבקשה) אבל לא בודק שהמידע תקין לפני שהוא משתמש בו. מישהו יכול לשלוח שדות שלא ציפית להם, והם יזרמו ישר למסד הנתונים או לשירות אחר — פתח לבאגים ולשינוי שדות שהמשתמש לא אמור לגעת בהם. הפתרון: להוסיף בדיקת תקינות (validation) שמוודאת שכל שדה הוא בדיוק מה שציפית לו. ייתכן שהבדיקה כבר נעשית במקום אחר, אז שווה לוודא.
**EN:** This route receives data from the user (the request body) but does not check that the data is valid before using it. Someone can send fields you never expected, and they flow straight into the database or another service — an opening for bugs and for changing fields the user should never touch. The fix: add validation that confirms each field is exactly what you expected. The check may already happen elsewhere, so it is worth verifying.

## CG-WEB-003
**HE:** נקודת הקצה הזו קשורה להתחברות או להרשמה, ואין בה הגבלה על מספר הניסיונות. תוקף יכול לנחש סיסמאות או קודים חד-פעמיים במהירות, שוב ושוב, עד שהוא נכנס לחשבון של מישהו — התקפה נפוצה מאוד נגד דפי כניסה. הפתרון: להוסיף הגבלת קצב (rate limit) שחוסמת אחרי כמה ניסיונות. ייתכן שההגבלה כבר קיימת אצל ספק ההתחברות שלכם, אז שווה לבדוק.
**EN:** This endpoint is tied to login or signup, and it has no limit on the number of attempts. An attacker can guess passwords or one-time codes rapidly, again and again, until they break into someone's account — a very common attack against login pages. The fix: add a rate limit that blocks after a few attempts. The limit may already exist at your auth provider, so it is worth checking.

## CG-WEB-004
**HE:** הנתיב הזה מאחזר רשומה לפי מזהה (id) מתוך הבקשה, ומשתמש במפתח החזק של מסד הנתונים שעוקף את כל בדיקות ההרשאה — אבל לא ראינו בדיקה שהרשומה באמת שייכת למי שביקש אותה. המשמעות: משתמש מחובר יכול פשוט לשנות את המספר בכתובת ולראות או לערוך רשומות של אנשים אחרים. כדאי לוודא שהקוד בודק בעלות, כך שכל משתמש ניגש רק לרשומות שלו; ייתכן שהבדיקה נעשית בקובץ אחר, אז שווה לבדוק.
**EN:** This route fetches a record by an id from the request, and uses the powerful database key that bypasses all permission checks — but we did not see a check that the record actually belongs to the person who asked for it. That means a logged-in user can simply change the number in the URL and read or edit other people's records. Make sure the code checks ownership, so each user only reaches their own records; the check may live in another file, so it is worth verifying.

## CG-WEB-010
**HE:** בהגדרות של האתר (next.config) לא מוגדרות "כותרות אבטחה" — הוראות שהאתר שולח לדפדפן ומצמצמות נזק אם משהו משתבש, למשל הגנה מפני הזרקת קוד זדוני או מפני הטמעת הדף באתר אחר. בלעדיהן, כל באג קטן אחר הופך למסוכן יותר. זו לא פרצה בפני עצמה, אלא הסרה של רשת ביטחון. הפתרון: להוסיף פונקציית headers() עם הגנות בסיסיות כמו CSP.
**EN:** Your site's config (next.config) sets no "security headers" — instructions the site sends to the browser that limit damage if something goes wrong, like protection against injected malicious scripts or against your page being embedded in another site. Without them, every other small bug becomes more dangerous. This is not a breach on its own, but the removal of a safety net. The fix: add a headers() function with basic protections like a CSP.

## CG-WEB-020
**HE:** הגדרת `env:` בקובץ ה-next.config מטמיעה משתנים ישירות בקוד שנשלח לדפדפן — גם בלי קידומת ציבורית. זה עוקף את הכלל שכל האפליקציה מסתמכת עליו כדי לשמור סודות בצד השרת. אם אחד המשתנים שם הוא סוד אמיתי, הוא נחשף לכל מי שפותח את הדפדפן. כדאי לבדוק אילו משתנים נמצאים בבלוק הזה ולהעביר כל דבר רגיש חזרה לצד השרת.
**EN:** The `env:` setting in your next.config bakes variables directly into the code sent to the browser — even without a public prefix. This bypasses the very rule your whole app relies on to keep secrets on the server side. If one of the variables there is a real secret, it is exposed to anyone who opens the browser. Check which variables are in this block and move anything sensitive back to the server side.

## CG-WEB-021
**HE:** הבלוק `publicRuntimeConfig` ב-next.config נשלח במלואו לדפדפן — כל ערך שנמצא בו נכתב לתוך הדף וקריא לכל אחד. בדיוק כמו `env:`, זו דרך עוקפת שמעבירה הגדרות מהשרת לדפדפן בלי הגנה. אם יש שם ערך רגיש, הוא חשוף. כדאי לעבור על הבלוק ולהוציא ממנו כל דבר שאסור שיהיה ציבורי.
**EN:** The `publicRuntimeConfig` block in next.config is sent to the browser in full — every value in it is written into the page and readable by anyone. Just like `env:`, this is a bypass that moves settings from the server to the browser with no protection. If there is a sensitive value there, it is exposed. Go over the block and remove anything that must not be public.

## CG-WEB-022
**HE:** האתר מפרסם "מפות מקור" (source maps) בסביבת הייצור — קבצים שחושפים את קוד המקור המקורי שלכם, כולל הערות ושמות פנימיים. זה לא פורץ שום דבר בעצמו, אבל מקל מאוד על תוקף להבין איך האתר בנוי ולמצוא חולשות אחרות — כמו לתת למישהו את התוכניות של הבניין. כדאי לכבות פרסום של מפות מקור בייצור.
**EN:** The site publishes source maps in production — files that reveal your original source code, including comments and internal names. This does not break anything by itself, but it makes it much easier for an attacker to understand how the site is built and find other weaknesses — like handing someone the building's blueprints. It is worth disabling source-map publishing in production.

## CG-WEB-023
**HE:** ההגדרה שמדלגת על שגיאות TypeScript בזמן הבנייה דלוקה — כלומר הקוד עולה לאוויר גם אם יש בו שגיאות שהמערכת הייתה תופסת. שגיאות כאלה יכולות לכלול בדיקת הרשאות שבורה שאחרת הייתה נחסמת. זו הסרה של רשת ביטחון ששאר הקוד מניח שקיימת. כדאי לכבות את ההגדרה ולתקן את השגיאות שיצוצו.
**EN:** The setting that skips TypeScript errors at build time is on — meaning the code ships even if it contains errors the system would have caught. Such errors can include a broken permission check that would otherwise be blocked. This removes a safety net the rest of the code assumes is there. It is worth turning the setting off and fixing the errors that surface.

## CG-WEB-024
**HE:** ההגדרה שמשתיקה את ESLint בזמן הבנייה דלוקה — כלומר כללי הבדיקה האוטומטיים, כולל כאלה שמזהים בעיות אבטחה, לא רצים בכלל. אין כאן התקפה ישירה, אבל אתם מוותרים על שכבת בדיקה ששאר הקוד מסתמך עליה. כדאי להפעיל את ESLint בחזרה ולטפל באזהרות.
**EN:** The setting that silences ESLint at build time is on — meaning the automatic check rules, including ones that spot security problems, do not run at all. There is no direct attack here, but you are giving up a layer of checks the rest of the code relies on. It is worth turning ESLint back on and addressing the warnings.

## CG-WEB-025
**HE:** הגדרת התמונות באתר (remotePatterns) מתירה לטעון תמונות מכל דומיין באינטרנט, בלי הגבלה. תוקף יכול לנצל את זה כדי להעביר תוכן שרירותי דרך מנגנון התמונות שלכם, או לגרום לשרת שלכם לשלוח בקשות למקומות שהוא בחר. התוצאה: הדומיין שלכם מגיש תוכן של תוקף, והשרת שלכם עושה בקשות בשמו. כדאי להגביל את הרשימה לדומיינים ספציפיים שאתם סומכים עליהם.
**EN:** Your site's image config (remotePatterns) allows loading images from any domain on the internet, with no restriction. An attacker can abuse this to route arbitrary content through your image system, or make your server send requests to places they choose. The result: your domain serves an attacker's content, and your server makes requests on their behalf. Restrict the list to specific domains you trust.

## CG-DB-001
**HE:** טבלת הנתונים הזו פתוחה לכל אחד. כרגע כל גולש באינטרנט — בלי להתחבר ובלי סיסמה — יכול לקרוא, לשנות או למחוק את כל השורות בטבלה. זה כמו חנות שמעולם לא התקינו לה מנעול על הדלת. התיקון לוקח כמה דקות: מפעילים "הגנת שורות" (RLS) ומגדירים שכל משתמש רואה רק את המידע שלו.
**EN:** This database table is open to anyone. Right now any visitor on the internet — with no login and no password — can read, change, or delete every row in it. It is like a shop whose front door was never given a lock. The fix takes minutes: turn on Row Level Security (RLS) and add a rule so each user sees only their own data.

## CG-DB-002
**HE:** הגנת השורות (RLS) בטבלה הזו דלוקה — אבל אחת המדיניות שהוגדרו מתירה גישה לכולם. זה כמו להתקין מנעול חדש על הדלת ואז להשאיר אותו פתוח: בלוח הבקרה זה נראה מוגן, אבל בפועל כל אחד עם המפתח האנונימי (שמגיע לכל דפדפן) יכול לגשת לכל השורות. הפתרון: להחליף את המדיניות ה"מתירה לכולם" במדיניות שמגבילה כל משתמש למידע שלו בלבד.
**EN:** Row Level Security (RLS) on this table is on — but one of the defined policies allows access to everyone. It is like installing a new lock on the door and then leaving it open: in the dashboard it looks protected, but in practice anyone with the anonymous key (which ships to every browser) can reach every row. The fix: replace the "allow everyone" policy with one that limits each user to only their own data.

## CG-DB-003
**HE:** הגנת השורות (RLS) בטבלה הזו דלוקה, אבל אין אף מדיניות שמתירה גישה — ולכן כרגע אף אחד לא יכול לקרוא ממנה כלום, כולל המשתמשים החוקיים שלכם. מבחינת אבטחה זה הכיוון הבטוח, אין כאן שום סכנה. הבעיה היא שהפיצ'ר שמשתמש בטבלה כנראה פשוט לא עובד. כשמתקנים, חשוב לכתוב מדיניות ממוקדת (שכל משתמש רואה את שלו) ולא מדיניות שמתירה לכולם.
**EN:** Row Level Security (RLS) on this table is on but there is no policy granting access — so right now no one can read anything from it, including your legitimate users. Security-wise this is the safe direction; there is no danger here. The problem is that the feature using this table probably just does not work. When you fix it, be sure to write a scoped policy (each user sees their own) and not one that allows everyone.

## CG-DB-004
**HE:** יש במסד הנתונים פונקציה שרצה עם ההרשאות של הבעלים ועוקפת את כל בדיקות ההגנה (RLS) — ובגוף שלה אין שום בדיקה מי המשתמש שקורא לה. כל אחד יכול להפעיל אותה מרחוק, בלי להתחבר, ולפעול כאילו הוא הבעלים של מסד הנתונים. זו עקיפה מלאה של כל ההגנות שהגדרתם. הפתרון: להוסיף בתוך הפונקציה בדיקה שמוודאת מי המשתמש (למשל auth.uid()) לפני שהיא עושה משהו.
**EN:** There is a database function that runs with the owner's privileges and bypasses all the protection checks (RLS) — and its body has no check of who is calling it. Anyone can invoke it remotely, without logging in, and act as if they own the database. This is a complete bypass of every protection you set up. The fix: add a check inside the function that confirms who the user is (for example auth.uid()) before it does anything.

## CG-DB-005
**HE:** פונקציה במסד הנתונים שרצה עם הרשאות הבעלים אינה מקבעת את ה-search_path — ההגדרה שקובעת היכן הפונקציה מחפשת טבלאות ופונקציות אחרות. בלי קיבוע, תוקף שיכול ליצור אובייקטים במסד הנתונים יכול "להחליף" משהו שהפונקציה קוראת לו, והקוד שלו ירוץ עם הרשאות הבעלים — כלומר הסלמת הרשאות. הפתרון פשוט: להוסיף `set search_path` לפונקציה.
**EN:** A database function that runs with owner privileges does not pin its search_path — the setting that decides where the function looks for other tables and functions. Without pinning, an attacker who can create objects in the database can "swap in" something the function calls, and their code runs with owner privileges — that is, privilege escalation. The fix is simple: add `set search_path` to the function.

## CG-DB-006
**HE:** לקוח Supabase שנבנה עם המפתח החזק ביותר (service-role) — כזה שעוקף את כל ההגנות — נמצא בקוד שעלול להגיע לדפדפן. אם הקוד הזה אכן נשלח לדפדפן, המפתח החזק נחשף לכל מי שמסתכל, וכל ההגנות (RLS) מפסיקות להיות רלוונטיות. המשמעות: גישה מלאה למסד הנתונים לכל גולש. כדאי לוודא שהלקוח הזה נבנה רק בצד השרת, ולעולם לא בקוד שרץ בדפדפן.
**EN:** A Supabase client built with the most powerful key (service-role) — one that bypasses all protections — sits in code that may reach the browser. If this code does ship to the browser, the powerful key is exposed to anyone looking, and all protections (RLS) stop mattering. That means full database access for any visitor. Make sure this client is built only on the server side, never in code that runs in the browser.

## CG-DB-COVERAGE
**HE:** לא הצלחנו לקבוע אם הגנת השורות (RLS) דלוקה על חלק מהטבלאות שלכם, כי אין בקוד קבצי מיגרציה שמתעדים את מבנה מסד הנתונים — הוא קיים רק בלוח הבקרה של Supabase. אם RLS כבוי על אחת מהן, כל אחד עם המפתח האנונימי יכול לקרוא ולשנות את כל הטבלה — אבל ייתכן גם שהכול תקין, ואי אפשר לדעת מהקוד לבד. אפשר לענות על זה בעשר שניות: הריצו את השאילתה שהכלי מספק מול מסד הנתונים שלכם ותראו את התשובה האמיתית.
**EN:** We could not determine whether Row Level Security (RLS) is on for some of your tables, because the repo has no migration files documenting the database structure — it lives only in the Supabase dashboard. If RLS is off on one of them, anyone with the anonymous key can read and change the whole table — but it is also possible everything is fine, and there is no way to tell from the code alone. You can answer this in ten seconds: run the query the tool provides against your database and see the real answer.

## CG-LLM-001
**HE:** ה-SDK של מודל ה-AI שלכם מוגדר לרוץ בדפדפן (עם ההגדרה dangerouslyAllowBrowser), שמכבה את ההגנה המובנית שמונעת שליחת מפתח ה-API ללקוח. המשמעות: מפתח ה-API נמצא בקוד שכל אחד יכול לקרוא — ולחייב את החשבון שלכם בשימוש משלו. התוצאה: הוצאות בלתי מוגבלות על הכרטיס שלכם, ושימוש חופשי במכסה שלכם על ידי זרים. הפתרון: להעביר את הקריאה למודל לצד השרת, כך שהמפתח לעולם לא מגיע לדפדפן.
**EN:** Your AI model's SDK is configured to run in the browser (with the dangerouslyAllowBrowser setting), which turns off the built-in guard that prevents sending the API key to the client. That means the API key sits in code anyone can read — and bill your account for their own use. The result: unbounded charges on your card, and strangers freely using your quota. The fix: move the model call to the server side, so the key never reaches the browser.

## CG-LLM-002
**HE:** נקודת הקריאה למודל ה-AI שלך אינה מגבילה כמה פעמים אפשר לקרוא לה. מישהו יכול להריץ אותה בלולאה, וכל קריאה מחויבת בכסף אמיתי — לך. זה נקרא "denial of wallet", וזו הטעות היקרה הכי נפוצה בקהילה. הפתרון: מוסיפים הגבלת קצב (rate limit) שחוסמת אחרי כמה בקשות בדקה.
**EN:** Your AI model endpoint puts no limit on how often it can be called. Someone can loop it, and every call is billed — to you. This is "denial of wallet", the most common expensive mistake in this community. The fix: add a rate limit that blocks after a few requests per minute.

## CG-LLM-003
**HE:** קלט מהמשתמש נכנס ישירות לתוך הפרומפט של המודל, ובאותו מקום המודל גם יכול להפעיל "כלים" — פעולות אמיתיות כמו קריאת מידע, שליחת מייל או חיוב כסף. תוקף יכול לכתוב בתוך הקלט שלו הוראות שהמודל יציית להן, ולהפעיל כלי בשמו — זה נקרא "הזרקת פרומפט". התוצאה: כל מה שהכלים יכולים לעשות, גם משתמש אנונימי יכול להפעיל. כדאי להפריד בבירור בין ההוראות שלכם למודל לבין הקלט, ולהגביל מה הכלים יכולים לעשות (ייתכן שהקלט מסונן במקום אחר, אז שווה לבדוק).
**EN:** User input flows straight into the model's prompt, and at the same place the model can also invoke "tools" — real actions like reading data, sending mail, or charging money. An attacker can write instructions inside their input that the model obeys, invoking a tool on their behalf — this is called prompt injection. The result: whatever the tools can do, an anonymous user can now trigger too. Clearly separate your instructions to the model from the user's input, and limit what the tools can do (the input may be sanitized elsewhere, so it is worth checking).

## CG-LLM-004
**HE:** לקריאה למודל ה-AI אין תקרת טוקנים — כלומר אין גבול על כמה טקסט המודל יכול לייצר בתשובה אחת. מישהו יכול לנסח קלט שגורם למודל לייצר עד המקסימום שהספק מרשה, בכל בקשה מחדש, וכל תו כזה עולה כסף. בשילוב עם היעדר הגבלת קצב, ככה נוצר חשבון מפתיע בבוקר. הפתרון פשוט וזול: להגדיר max_tokens (או maxTokens) בכל קריאה.
**EN:** The AI model call has no token ceiling — meaning no limit on how much text the model can produce in a single response. Someone can craft input that makes the model generate up to the provider's maximum, on every request, and each such character costs money. Combined with a missing rate limit, this is how a surprise bill appears in the morning. The fix is simple and cheap: set max_tokens (or maxTokens) on every call.

## CG-SEC-001
**HE:** ייתכן שסוד (מפתח, סיסמה או אסימון גישה) נשמר בטעות בתוך קוד המקור שהעליתם ל-git. כל מי שיש לו גישה למאגר — או להיסטוריה שלו — יכול להעתיק את הערך ולהשתמש בו. חשוב לזכור: גם אם תמחקו את השורה עכשיו, הערך נשאר בהיסטוריה של git ונחשב "שרוף". מה עושים: אם זה סוד שנותן גישה אמיתית — החליפו אותו מיד; אם זה מזהה ציבורי שנועד להיחשף, סמנו אותו ברשימת ההיתרים כדי שלא יופיע שוב.
**EN:** A secret (a key, password, or access token) may have been accidentally saved inside source code you pushed to git. Anyone with access to the repository — or its history — can copy the value and use it. Important to remember: even if you delete the line now, the value stays in git history and must be treated as "burned". What to do: if it is a secret that grants real access — rotate it immediately; if it is a public identifier meant to be exposed, mark it allowlisted so it does not appear again.

## CG-SAST-001
**HE:** כלי סריקה אוטומטי בשם semgrep זיהה בקוד שלכם דפוס שהוא מקשר לבעיית אבטחה אפשרית. זה רמז לבדיקה, לא הוכחה — הכלי מזהה צורות שנראות כמו בעיה, אבל לפעמים הן תקינות בפועל. כדאי לפתוח את המקום שצוין ולהבין מה הכלל מצא ולמה. אם זו באמת בעיה, תקנו אותה לפי ההסבר של הכלל; אם לא, אפשר להתעלם ממנה.
**EN:** An automated scanning tool called semgrep spotted a pattern in your code it associates with a possible security problem. This is a lead to check, not a proof — the tool matches shapes that look like a problem, but sometimes they are fine in practice. It is worth opening the flagged location to understand what the rule found and why. If it really is a problem, fix it per the rule's explanation; if not, you can dismiss it.

## CG-DEP-001
**HE:** אחת מספריות הקוד החיצוניות שהאפליקציה שלכם משתמשת בהן ידועה כפגיעה — יש עליה התראת אבטחה מתועדת. תוקף שינצל את החולשה עלול לפגוע באפליקציה, אבל זה תלוי אם הקוד שלכם באמת משתמש בחלק הפגיע — הרבה חולשות יושבות בקוד שהאפליקציה לעולם לא מפעילה. מה עושים: עדכנו את הספרייה לגרסה מתוקנת. זו לרוב פעולה פשוטה של הרצת פקודת עדכון.
**EN:** One of the external code libraries your app uses is known to be vulnerable — it has a documented security advisory. An attacker who exploits the weakness could harm the app, but that depends on whether your code actually uses the vulnerable part — many weaknesses sit in code the app never runs. What to do: update the library to a patched version. This is usually a simple matter of running an update command.

## CG-AND-001
**HE:** אפליקציית האנדרואיד שלכם מסומנת כ"ניתנת לניפוי שגיאות" (debuggable) בקובץ ההגדרות. המשמעות: כל מי שיש לו את האפליקציה מותקנת יכול לחבר אליה כלי ניפוי, לקרוא את הזיכרון ואת המידע השמור, ולעקוב אחרי הלוגיקה שלה שלב-שלב. כל סוד שהאפליקציה מחזיקה בזמן ריצה — אסימונים, מפתחות, מידע של משתמשים — קריא במכשיר. הפתרון: לכבות את android:debuggable לפני פרסום גרסת ייצור.
**EN:** Your Android app is marked "debuggable" in its config file. That means anyone with the app installed can attach a debugging tool to it, read its memory and stored data, and step through its logic. Every secret the app holds at runtime — tokens, keys, user data — is readable on the device. The fix: turn off android:debuggable before publishing a production build.

## CG-AND-002
**HE:** אפליקציית האנדרואיד מתירה תעבורת HTTP לא מוצפנת לכל שרת, בלי הגבלה. מישהו שנמצא על אותה רשת Wi-Fi — בבית קפה, בשדה תעופה — יכול לקרוא ולשנות את התעבורה של האפליקציה, כולל אסימוני התחברות. התוצאה: השתלטות על חשבונות וזיוף תוכן בכל רשת לא מהימנה. הפתרון: לכבות את usesCleartextTraffic, או להגביל אותו לדומיינים ספציפיים דרך קובץ network security config.
**EN:** The Android app permits unencrypted HTTP traffic to any server, with no restriction. Someone on the same Wi-Fi network — at a cafe, at an airport — can read and change the app's traffic, including login tokens. The result: account takeover and content tampering on any untrusted network. The fix: turn off usesCleartextTraffic, or restrict it to specific domains via a network security config file.

## CG-AND-003
**HE:** הגדרת allowBackup באפליקציה דלוקה, מה שמאפשר לגבות את המידע הפרטי של האפליקציה דרך המחשב (adb backup). מישהו עם גישה פיזית קצרה למכשיר לא נעול יכול להעתיק את האחסון הפרטי של האפליקציה דרך USB, בלי הרשאות מיוחדות — וכך אסימונים ומידע מקומי יוצאים מהמכשיר. הפתרון: להגדיר android:allowBackup="false".
**EN:** The app's allowBackup setting is on, which allows the app's private data to be backed up over a computer (adb backup). Someone with brief physical access to an unlocked device can copy the app's private storage over USB, with no special privileges — and that way tokens and local data leave the device. The fix: set android:allowBackup="false".

## CG-AND-004
**HE:** רכיב באפליקציה שלכם מוגדר כ"מיוצא" (exported) בלי שום הרשאה שמגנה עליו — כלומר כל אפליקציה אחרת שמותקנת על אותו מכשיר יכולה להפעיל אותו ישירות. אפליקציה זדונית שמותקנת לצדכם יכולה לגשת לרכיב הזה בלי שהמשתמש בכלל יודע, ולעקוף את מה שהממשק שלכם היה דורש. אם הרכיב הוא ספק תוכן (provider), היא אפילו יכולה לקרוא או לשנות מידע ישירות. הפתרון: להוסיף הרשאה (android:permission) לרכיב, או לכבות את הייצוא אם הוא לא נחוץ.
**EN:** A component in your app is marked "exported" with no permission protecting it — meaning any other app installed on the same device can invoke it directly. A malicious app installed alongside yours can reach this component without the user even knowing, bypassing whatever your UI would have required. If the component is a content provider, it can even read or write data directly. The fix: add a permission (android:permission) to the component, or turn off the export if it is not needed.

## CG-IOS-001
**HE:** באפליקציית ה-iOS שלכם מנגנון App Transport Security — הדרישה של המערכת שכל התקשורת תהיה מוצפנת (HTTPS) — כבוי עבור כל השרתים (NSAllowsArbitraryLoads). המשמעות: מישהו על אותה רשת יכול לקרוא ולשנות את התעבורה של האפליקציה, כולל אסימוני התחברות. התוצאה: השתלטות על חשבונות וזיוף תוכן בכל רשת לא מהימנה. הפתרון: להפעיל את ATS בחזרה, ואם צריך חריג — להגביל אותו לדומיינים ספציפיים בלבד.
**EN:** In your iOS app, App Transport Security — the system's requirement that all communication be encrypted (HTTPS) — is turned off for all servers (NSAllowsArbitraryLoads). That means someone on the same network can read and change the app's traffic, including login tokens. The result: account takeover and content tampering on any untrusted network. The fix: turn ATS back on, and if you need an exception, limit it to specific domains only.

## CG-IOS-002
**HE:** באפליקציית ה-iOS מנגנון App Transport Security כבוי בתוך תצוגות ווב (web views) — האזורים שבהם האפליקציה מציגה דפי אינטרנט. המשמעות: תוכן שנטען בתצוגת ווב יכול להישתנות בדרך על ידי מישהו שמאזין לרשת, ואז לרוץ בתוך ההקשר של האפליקציה שלכם. התוצאה: הזרקת תוכן זדוני לתוך האפליקציה בכל רשת לא מהימנה. הפתרון: להסיר את NSAllowsArbitraryLoadsInWebContent ולוודא שתצוגות הווב טוענות רק HTTPS.
**EN:** In your iOS app, App Transport Security is turned off inside web views — the areas where the app displays web pages. That means content loaded in a web view can be altered in transit by someone listening on the network, and then run inside your app's context. The result: injection of malicious content into the app on any untrusted network. The fix: remove NSAllowsArbitraryLoadsInWebContent and make sure web views load only HTTPS.

## CG-LIVE-TLS
**HE:** האתר שלכם מוגש ב-HTTP רגיל, בלי הצפנה. כל מי שנמצא על אותה רשת יכול לקרוא ולשנות את התעבורה בין המשתמשים לאתר, כולל עוגיות ההתחברות שלהם. התוצאה: גניבת מפגשים וזיוף תוכן לכל מבקר שנמצא על רשת לא מהימנה. הפתרון: להפעיל HTTPS (בדרך כלל בחינם ובכמה קליקים אצל ספק האחסון) ולהפנות אליו את כל התעבורה.
**EN:** Your site is served over plain HTTP, with no encryption. Anyone on the same network can read and change the traffic between users and the site, including their login cookies. The result: session theft and content tampering for every visitor on an untrusted network. The fix: enable HTTPS (usually free and a few clicks at your host) and redirect all traffic to it.

## CG-LIVE-HSTS
**HE:** לאתר אין את כותרת Strict-Transport-Security — הוראה שאומרת לדפדפן "תמיד תתחבר אליי דרך HTTPS בלבד". בלעדיה, ביקור ראשון של משתמש עלול להתחיל ב-HTTP ולהיחטף רגע לפני שהוא מופנה ל-HTTPS. זה חלון צר אבל אמיתי לחטיפה, בכל מכשיר חדש. הפתרון: להוסיף את כותרת HSTS.
**EN:** The site is missing the Strict-Transport-Security header — an instruction that tells the browser "always connect to me over HTTPS only". Without it, a user's first visit may start over HTTP and be intercepted just before it is redirected to HTTPS. This is a narrow but real window for interception, on each new device. The fix: add the HSTS header.

## CG-LIVE-CSP
**HE:** לאתר אין כותרת Content-Security-Policy — מדיניות שמגבילה מאילו מקורות מותר להריץ קוד ולאן מותר לשלוח מידע. בלעדיה, אם קוד זדוני נכנס איכשהו לדף, הוא יכול לרוץ בלי שום מגבלה ולשלוח מידע לאן שירצה. ככה באג קטן של הזרקת קוד הופך להשתלטות מלאה על חשבון. הפתרון: להגדיר CSP.
**EN:** The site is missing a Content-Security-Policy header — a policy that restricts which sources may run code and where data may be sent. Without it, if malicious code somehow enters the page, it can run with no restriction and send data anywhere it wants. That is how a small injection bug turns into full account takeover. The fix: configure a CSP.

## CG-LIVE-XCTO
**HE:** לאתר אין את הכותרת X-Content-Type-Options: nosniff. בלעדיה, הדפדפן עלול "לנחש" את סוג הקובץ שהועלה ולהריץ אותו כקוד — למשל קובץ שמשתמש העלה. כך העלאת קבצים יכולה להפוך לנתיב להזרקת קוד. הפתרון פשוט: להוסיף את הכותרת הזו.
**EN:** The site is missing the X-Content-Type-Options: nosniff header. Without it, the browser may "guess" the type of an uploaded file and run it as code — for example a file a user uploaded. That way file uploads can become a path for code injection. The fix is simple: add this header.

## CG-LIVE-XFO
**HE:** אפשר להטמיע את הדף שלכם בתוך אתר אחר (כמו חלון בתוך חלון), ואין הגנה שמונעת זאת. תוקף יכול להטמיע את הדף באופן שקוף, מעל כפתורים מזויפים, ולגרום למשתמש מחובר ללחוץ על דברים בלי לדעת. התוצאה: פעולות לא מכוונות שמשתמשים אמיתיים מבצעים על החשבון שלהם. הפתרון: להגדיר frame-ancestors ב-CSP או את הכותרת X-Frame-Options.
**EN:** Your page can be embedded inside another site (like a window within a window), with no protection preventing it. An attacker can embed the page invisibly, over fake buttons, and trick a logged-in user into clicking things without knowing. The result: unintended actions that real users perform on their own account. The fix: set frame-ancestors in your CSP or the X-Frame-Options header.

## CG-LIVE-REF
**HE:** לאתר אין כותרת Referrer-Policy. בלעדיה, כשמשתמש עובר מהאתר שלכם לאתר אחר, הדפדפן שולח את הכתובת המלאה של הדף שהוא הגיע ממנו — כולל כל דבר שנמצא בכתובת, כמו אסימונים. כך מידע רגיש שנמצא בכתובת דולף בשקט לאתרים חיצוניים. הפתרון: להוסיף את כותרת Referrer-Policy.
**EN:** The site is missing a Referrer-Policy header. Without it, when a user moves from your site to another, the browser sends the full address of the page they came from — including anything in that address, like tokens. That way sensitive information placed in a URL quietly leaks to third-party sites. The fix: add a Referrer-Policy header.

## CG-LIVE-CORS
**HE:** הגדרת ה-CORS של ה-API שלכם מתירה לכל אתר באינטרנט לקרוא תשובות מזוהות, עם פרטי ההזדהות של המשתמש. המשמעות: אתר זדוני שהמשתמש שלכם מבקר בו יכול לקרוא נתונים פרטיים מה-API שלכם, תוך שימוש במפגש המחובר של המשתמש עצמו. התוצאה: גניבת מידע בין-אתרית ממשתמשים מחוברים. הפתרון: להגביל את CORS לדומיינים ספציפיים בלבד, ולא להשתמש בכוכבית יחד עם credentials.
**EN:** Your API's CORS setting allows any website on the internet to read authenticated responses, with the user's credentials. That means a malicious site your user visits can read private data from your API, using the user's own logged-in session. The result: cross-site data theft from logged-in users. The fix: restrict CORS to specific domains only, and never use a wildcard together with credentials.

## CG-LIVE-COOKIE
**HE:** אחת העוגיות שהאתר שולח מוגדרת בלי הדגל HttpOnly. המשמעות: אם קוד זדוני מצליח לרוץ בדף, הוא יכול לקרוא את העוגייה ישירות (דרך document.cookie) — וגם עוגיית התחברות אחת שנגנבת מספיקה כדי להיכנס לחשבון של המשתמש. הפתרון פשוט: להוסיף את הדגל HttpOnly לעוגיות רגישות, במיוחד עוגיות מפגש.
**EN:** One of the cookies the site sets is configured without the HttpOnly flag. That means if malicious code manages to run in the page, it can read the cookie directly (via document.cookie) — and stealing a single login cookie is enough to get into the user's account. The fix is simple: add the HttpOnly flag to sensitive cookies, especially session cookies.

## CG-LIVE-COOKIE2
**HE:** אחת העוגיות שהאתר שולח מוגדרת בלי הדגל Secure. בלי הדגל הזה, אם בקשה כלשהי יורדת ל-HTTP לא מוצפן, העוגייה תישלח גם היא בלי הצפנה — וחשופה למי שמאזין לרשת. זה חלון צר לחשיפת מפגש, אבל קל למנוע. הפתרון: להוסיף את הדגל Secure לעוגיות.
**EN:** One of the cookies the site sets is configured without the Secure flag. Without this flag, if any request ever downgrades to unencrypted HTTP, the cookie is sent unencrypted too — and exposed to anyone listening on the network. This is a narrow window for session disclosure, but easy to prevent. The fix: add the Secure flag to cookies.

## CG-LIVE-EXPOSE
**HE:** נתיב רגיש באתר שלכם קריא לכל אחד באינטרנט — כלומר מישהו יכול פשוט לגשת לכתובת ולקרוא את התוכן. נתיבים מהסוג הזה בדרך כלל מכילים הגדרות או סודות, כך שהחשיפה עלולה להיות רצינית, תלוי בקובץ. כדאי לגשת לנתיב שצוין, לראות מה יש בו, ולחסום את הגישה אליו מבחוץ.
**EN:** A sensitive path on your site is readable by anyone on the internet — meaning someone can simply visit the address and read its contents. Paths of this kind usually contain configuration or secrets, so the exposure could be serious, depending on the file. Visit the flagged path, see what is in it, and block outside access to it.

## CG-LIVE-RLS
**HE:** זה לא "אולי" — נבדק בפועל מול המערכת החיה: המפתח האנונימי (שמגיע לכל דפדפן) הצליח למשוך שורות מהטבלה. כלומר כל אחד יכול להריץ בדיוק את אותה שאילתה, עם המפתח שנמצא בבנדל שלכם, ולקרוא את תוכן הטבלה. זו חשיפה מלאה של המידע בטבלה. מה עושים: הפעילו הגנת שורות (RLS) על הטבלה והגדירו מדיניות שמגבילה כל משתמש למידע שלו — עכשיו.
**EN:** This is not a "maybe" — it was actually tested against the live system: the anonymous key (which ships to every browser) successfully pulled rows from the table. That means anyone can run the exact same query, with the key from your bundle, and read the table's contents. This is a full exposure of the data in the table. What to do: turn on Row Level Security (RLS) for the table and set a policy that limits each user to their own data — now.

## CG-DAST-XSS
**HE:** נבדק בפועל: תגית קוד שהוזרקה לאתר הוחזרה חזרה בלי "בריחה" (escaping) — כלומר האתר הריץ אותה במקום להציג אותה כטקסט. תוקף יכול לשלוח לקורבן קישור שמכיל קוד, והקוד ירוץ בתוך האתר שלכם, בהקשר של המשתמש. התוצאה: גניבת מפגש וביצוע פעולות בשם הקורבן. הפתרון: לוודא שכל קלט משתמש עובר "בריחה" נכונה לפני שהוא מוצג בדף.
**EN:** Actually tested: a code tag injected into the site was returned without "escaping" — meaning the site ran it instead of showing it as text. An attacker can send a victim a link containing code, and the code runs inside your site, in the user's context. The result: session theft and actions performed as the victim. The fix: make sure all user input is properly escaped before it is displayed on the page.

## CG-DAST-SQLI
**HE:** נבדק בפועל: שליחת תו גרש (') לאחת מנקודות הקצה יצרה שגיאת מסד נתונים. זה סימן חזק לכך שהקלט מגיע ישירות לתוך שאילתת SQL בלי סינון — מה שמאפשר לתוקף לשכתב את השאילתה ולקרוא או לשנות כל דבר שמשתמש מסד הנתונים יכול להגיע אליו. ייתכן שהשגיאה מגיעה משכבת סינון ולא מבניית השאילתה, אז שווה לבדוק. הפתרון: להשתמש בשאילתות עם פרמטרים (parameterised queries) שמפרידות בין הקוד לנתונים.
**EN:** Actually tested: sending a quote character (') to one of the endpoints produced a database error. This is a strong sign that the input reaches an SQL query directly without filtering — which lets an attacker rewrite the query and read or change anything the database user can reach. It is possible the error comes from a validation layer rather than query construction, so it is worth checking. The fix: use parameterised queries that separate code from data.

## CG-DAST-REDIR
**HE:** נבדק בפועל: אחת מנקודות הקצה מפנה את המשתמש לכל כתובת שנשלחת אליה — כולל דומיין בשליטת תוקף. המשמעות: קישור פישינג יכול להתחיל בדומיין המהימן שלכם ולנחות אצל התוקף, כך שהמשתמש סומך על הקישור בגלל השם שלכם. התוצאה: הדומיין שלכם משאיל את האמינות שלו לדף פישינג. הפתרון: לאפשר הפניה רק לכתובות מרשימה מאושרת מראש.
**EN:** Actually tested: one of the endpoints redirects the user to any address sent to it — including a domain controlled by an attacker. That means a phishing link can start on your trusted domain and land on the attacker's, so the user trusts the link because of your name. The result: your domain lends its credibility to a phishing page. The fix: only allow redirects to addresses on a pre-approved list.