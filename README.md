# PassMan 🔐

PassMan is a minimalist, high-security password manager designed to protect your credentials with military-grade encryption. Built for those who understand the importance of digital hygiene, it features AES-256 encryption, a one-way hashed master password, a robust password strength checker, and a beautiful password generator to help you craft strong credentials like a professional.

---

## 🔧 Features

- **AES-256 Encryption**
  - All stored passwords are encrypted using Advanced Encryption Standard (AES) with a 256-bit key. No compromise, no nonsense.

- **Master Password (One Password to Rule Them All)**
  - A single master password governs access to your entire password vault.
  - Stored using **SHA-256**, a one-way cryptographic hash function. It cannot be decrypted – and if you forget it, well… that’s on you.

- **Password Generator**
  - Generates complex, secure passwords with a choice of length and character sets.
  - Aesthetically pleasing and pragmatically secure.

- **Password Strength Checker**
  - Analyses password strength in real-time.
  - Provides constructive feedback:
    - *"Too short, like your last apology."*
    - *"Try adding numbers, symbols, and at least one capital letter."*
  - Recommends how to transform a weak password into something Fort Knox would blush at.

---

## 🛡️ Security Overview

| Component           | Method                    |
|--------------------|---------------------------|
| Storage Encryption | AES-256                   |
| Master Password     | SHA-256 One-way Hash      |
| Other Passwords     | Encrypted at Rest         |
| Password Generator  | Fully Customizable Output |
| Strength Checker    | Real-Time Analysis        |

---

## 🚀 Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/passman.git
   cd passman
```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run PassMan:

   ```bash
   python passman.py
   ```

4. Set your master password – this is the only password you’ll ever need to remember. Make it count.

---

## 🧪 Example Usage

* Generate a new password:

  ```bash
  > Generate password [Length: 16, Include: Uppercase, Numbers, Symbols]
  > Result: T@u9W$zNc#3vP&Lm
  ```

* Check password strength:

  ```bash
  > Enter password: password123
  > Strength: Weak
  > Suggestions: Add uppercase letters, symbols, and increase length.
  ```

---

## 📁 File Structure

```
passman/
├── passman.py
├── password_generator.py
├── strength_checker.py
├── vault.json
├── README.md
└── requirements.txt
```

---

## 📝 Notes

* **No cloud sync.** What happens on your device, stays on your device.
* **No telemetry.** We’re not interested in your data, just protecting it.
* Forget your master password? Then it's curtains, I'm afraid. Consider writing it down and eating the paper afterward.

---

## 🧠 Future Improvements

* Biometric unlock (face/fingerprint)
* Browser extension integration
* Encrypted cloud backup (opt-in)

---

## 👑 Credits

Crafted by minds who understand security, not merely talk about it. This project is for people who actually *use* encryption, not just throw around buzzwords in coffee shops.

---

## 📜 License

MIT License. Because freedom should be free, but your passwords shouldn't.

```

---

Should you desire a slightly more verbose or technical variant, or one tailored for a corporate GitLab deployment, I can whip that up faster than you can say "zero-knowledge architecture", sir.
```

