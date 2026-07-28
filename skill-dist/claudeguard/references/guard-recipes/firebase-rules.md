# Guard: Firebase security rules

Firestore/RTDB/Storage rules are the security boundary — the client talks to the DB directly.

## Firestore — owner-scoped, validated

```
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {

    // Users can read/write only their own profile
    match /users/{uid} {
      allow read: if request.auth != null && request.auth.uid == uid;
      allow write: if request.auth != null && request.auth.uid == uid
                   && request.resource.data.keys().hasOnly(['name','bio','updatedAt']);
    }

    // Posts: public read, author-only write, ownership enforced
    match /posts/{id} {
      allow read: if true;
      allow create: if request.auth != null
                    && request.resource.data.authorId == request.auth.uid;
      allow update, delete: if request.auth != null
                            && resource.data.authorId == request.auth.uid;
    }

    // Deny everything not explicitly allowed
    match /{document=**} { allow read, write: if false; }
  }
}
```

Kill these anti-patterns:
- `allow read, write: if true;` — world-open.
- `allow read, write: if request.auth != null;` — *any* logged-in user can touch *any* doc.
- Test-mode `if request.time < timestamp.date(2025, ...)` left in prod.

## Storage — scope by path + validate

```
service firebase.storage {
  match /b/{bucket}/o {
    match /user/{uid}/{file} {
      allow read, write: if request.auth != null && request.auth.uid == uid
                         && request.resource.size < 5 * 1024 * 1024
                         && request.resource.contentType.matches('image/.*');
    }
  }
}
```

## Also
- Enable **App Check** to blunt abuse from outside your apps.
- The Firebase `apiKey` in the client is fine — it's an identifier. Lock the **rules**, not the key.
- Never commit the Admin SDK service-account JSON; it bypasses all rules (rotate if leaked).
- Test rules with the emulator: `firebase emulators:exec --only firestore "npm test"`.
