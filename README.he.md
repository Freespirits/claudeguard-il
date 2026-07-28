<div dir="rtl">

# 🛡️ ClaudeGuardIL

**כלי אבטחה לאפליקציות vibecoding.** מפנים אותו לפרויקט ומקבלים דוח מדורג של פרצות אבטחה אמיתיות
עם ראיות, ולצידן קוד הגנה מוכן להדבקה — לאתרים ואפליקציות web, פיצ'רים של AI/LLM,
Supabase/Firebase, אנדרואיד, iOS, Electron, backend/IaC ו-CI/CD.

> **פרויקט קהילתי — אינו מוצר רשמי של Anthropic.**
> נבנה עבור [קהילת Claude הישראלית](https://www.facebook.com/groups/cladue).

---

## למה זה נבנה

מפתחים ב-vibecoding משחררים מהר עם Claude Code, Cursor, Lovable, Base44, Bolt ו-v0 — ואגב כך
חושפים מפתחות `service_role`, מעלים אפליקציות בלי RLS ב-Supabase, שמים מפתחות API של LLM בצד
הלקוח, ומעלים קבצי `.env` ל-git. הקהילה כבר מתמודדת עם זה בשטח. הכלי הזה מוצא את הבעיות **ומייצר
את ההגנות**.

## שתי דרכים להשתמש

### 1) תוסף ל-Claude Code (מנוע מלא)
סורק את כל ה-repo, מריץ סורקים, ויכול לייצר ולהחיל תיקונים.

<div dir="ltr">

```
/plugin marketplace add <owner>/<repo>
/plugin install claudeguard-il@claudeguard-il
```

</div>

ואז, בתוך הפרויקט:

<div dir="ltr">

```
/cg-scan            # בדיקה סטטית (Tier 0) — בטוחה, קריאה בלבד, ברירת המחדל
/cg-harden          # ייצור קוד הגנה מוכן להדבקה
/cg-fix             # החלת ההגנות (קודם diff יבש, אתם מאשרים)
/cg-live  <url>     # Tier 1 בדיקות live פסיביות (יעד שבבעלותכם)
/cg-dast  <url>     # Tier 2 בדיקת DAST אקטיבית (יעד שבבעלותכם + הרשאה)
```

</div>

### 2) Skill ל-claude.ai / Claude Desktop (ידע + דוח)
למי שלא עובד בטרמינל. בונים את קובץ ה-zip ומעלים אותו ב-claude.ai (הגדרות → יכולות → Skills):

<div dir="ltr">

```
node scripts/build.mjs          # מייצר claudeguard-skill.zip
```

</div>

ואז מדביקים או מעלים את הקוד/קונפיג ושואלים: *"בדוק את האבטחה של האפליקציה"*. אותו ידע, אותו דוח
דו-לשוני; בלי סריקת repo, subagents או תיקון אוטומטי.

---

## שלוש רמות בדיקה

| רמה | מה | בטיחות |
|------|------|--------|
| **0 · סטטית** | קורא קוד, קונפיג, תלויות, `.env`, RLS, manifests, היסטוריית git. | ברירת מחדל. בלי רשת, בלי סיסמאות. |
| **1 · live פסיבית** | בדיקות קריאה-בלבד על URL חי (TLS, headers, cookies, קבצים חשופים). | דורש `claudeguard.scope.yml` עם הצהרת בעלות. GET/HEAD בלבד. |
| **2 · DAST אקטיבית** | תעבורת תקיפה אמיתית (injection, IDOR, fuzzing). | דורש הצהרת הרשאה-בכתב + בעלות, רשימת יעדים מותרים, הגבלת קצב; dry-run כברירת מחדל. |

מעתיקים את `core/authorization/SCOPE.example.yml` ל-`claudeguard.scope.yml` וממלאים כדי להפעיל את
Tier 1–2. **בודקים רק מערכות שבבעלותכם או שיש לכם הרשאה בכתב לבדוק.**

## מה הוא בודק

סודות בצד הלקוח/ב-repo · RLS ו-`service_role` ב-Supabase · חוקי Firebase · אימות והרשאות ו-IDOR ·
ולידציה של קלט · injection מסוג SQL/XSS/SSRF · security headers/CORS/cookies · הגבלת קצב ·
**סיכוני LLM** (חשיפת מפתח, prompt injection, ניצול כלים של agent, DoS עלות) · manifest ואחסון
באנדרואיד/iOS · בידוד ו-IPC ב-Electron · Docker/K8s/Terraform · GitHub Actions ו-supply-chain.

## איך זה בנוי

`core/` הוא מקור האמת היחיד (markdown פשוט). `scripts/build.mjs` מעתיק אותו לשני העטיפות, כך
שעריכה אחת מעדכנת גם את התוסף וגם את ה-skill. מנוע הסריקה הוא **היברידי**: משתמש ב-
`gitleaks` / `semgrep` / `npm audit` כשהם מותקנים, ונופל בחזרה לקריאת קוד ע"י Claude כשלא — ולעולם
לא מתקין כלום בכפייה.

## כתב ויתור

מסופק כמות שהוא, ללא אחריות. דוח נקי **אינו** הוכחה לבטיחות. אתם אחראים על מה שאתם סורקים ועל
ההיקף של כל בדיקת live/DAST. אין קשר ל-Anthropic. רישיון MIT.

</div>
