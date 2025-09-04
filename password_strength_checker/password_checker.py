import re

# Common weak passwords to avoid
common_passwords = ["password", "123456", "12345678", "qwerty", "abc123"]

def check_password_strength(password):
    # Initial score
    score = 0
    feedback = []

    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("❌ Password should be at least 8 characters long.")

    # Check for uppercase
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("❌ Add at least one uppercase letter.")

    # Check for lowercase
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("❌ Add at least one lowercase letter.")

    # Check for digits
    if re.search(r"[0-9]", password):
        score += 1
    else:
        feedback.append("❌ Add at least one digit.")

    # Check for special characters
    if re.search(r"[@$!%*?&#]", password):
        score += 1
    else:
        feedback.append("❌ Add at least one special character (@, $, !, %, *, ?, & or #).")

    # Check against common passwords
    if password.lower() in common_passwords:
        feedback.append("❌ This is a common password. Please choose another.")

    # Final strength evaluation
    if score <= 2:
        strength = "Weak 🔴"
    elif score == 3 or score == 4:
        strength = "Medium 🟡"
    else:
        strength = "Strong 🟢"

    return strength, feedback


# Main program
if __name__ == "__main__":
    user_password = input("Enter your password: ")
    strength, suggestions = check_password_strength(user_password)

    print(f"\nPassword Strength: {strength}")
    if suggestions:
        print("\nSuggestions to improve:")
        for s in suggestions:
            print(s)
