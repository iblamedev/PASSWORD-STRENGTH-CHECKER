import itertools
import string
import hashlib
import time
from typing import Optional

class PasswordStrengthChecker:
    def __init__(self):
        self.attempts = 0
        self.start_time = 0
        
    def hash_password(self, password: str) -> str:
        """Hash a password using MD5"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def estimate_crack_time(self, password: str) -> dict:
        """Estimate how long it would take to crack a password"""
        charset_size = 0
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digit:
            charset_size += 10
        if has_special:
            charset_size += 32
            
        # Calculate possible combinations
        combinations = charset_size ** len(password)
        
        # Assume 1 million attempts per second (modern hardware)
        attempts_per_second = 1000000
        seconds_to_crack = combinations / (2 * attempts_per_second)  # Average case
        
        return {
            'charset_size': charset_size,
            'combinations': combinations,
            'seconds': seconds_to_crack,
            'minutes': seconds_to_crack / 60,
            'hours': seconds_to_crack / 3600,
            'days': seconds_to_crack / 86400,
            'years': seconds_to_crack / 31536000
        }
    
    def analyze_password_strength(self, password: str) -> dict:
        """Analyze password strength and provide detailed feedback"""
        analysis = {
            'password': password,
            'length': len(password),
            'has_lowercase': any(c.islower() for c in password),
            'has_uppercase': any(c.isupper() for c in password),
            'has_digits': any(c.isdigit() for c in password),
            'has_special': any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password),
            'score': 0,
            'strength': 'Very Weak',
            'feedback': []
        }
        
        # Calculate strength score
        if analysis['length'] >= 8:
            analysis['score'] += 2
        elif analysis['length'] >= 6:
            analysis['score'] += 1
            
        if analysis['has_lowercase']:
            analysis['score'] += 1
        if analysis['has_uppercase']:
            analysis['score'] += 1
        if analysis['has_digits']:
            analysis['score'] += 1
        if analysis['has_special']:
            analysis['score'] += 2
            
        # Determine strength level
        if analysis['score'] >= 7:
            analysis['strength'] = 'Very Strong'
        elif analysis['score'] >= 5:
            analysis['strength'] = 'Strong'
        elif analysis['score'] >= 3:
            analysis['strength'] = 'Medium'
        elif analysis['score'] >= 1:
            analysis['strength'] = 'Weak'
        else:
            analysis['strength'] = 'Very Weak'
            
        # Generate feedback
        if analysis['length'] < 8:
            analysis['feedback'].append("Use at least 8 characters")
        if not analysis['has_lowercase']:
            analysis['feedback'].append("Add lowercase letters")
        if not analysis['has_uppercase']:
            analysis['feedback'].append("Add uppercase letters")
        if not analysis['has_digits']:
            analysis['feedback'].append("Add numbers")
        if not analysis['has_special']:
            analysis['feedback'].append("Add special characters (!@#$%^&*)")
            
        return analysis
    
    def brute_force_test(self, password: str, max_length: int = None) -> Optional[str]:
        """Test if password can be cracked with brute force (limited scope for demo)"""
        if max_length is None:
            max_length = min(len(password), 4)  # Limit to prevent long execution
            
        target_hash = self.hash_password(password)
        
        # Determine character set based on password
        charset = ""
        if any(c.islower() for c in password):
            charset += string.ascii_lowercase
        if any(c.isupper() for c in password):
            charset += string.ascii_uppercase
        if any(c.isdigit() for c in password):
            charset += string.digits
        if any(c in "!@#$%^&*" for c in password):
            charset += "!@#$%^&*"
            
        print(f"Testing brute force attack (max length: {max_length})...")
        print(f"Character set size: {len(charset)}")
        
        self.start_time = time.time()
        self.attempts = 0
        
        for length in range(1, max_length + 1):
            print(f"Trying passwords of length {length}...")
            
            for password_tuple in itertools.product(charset, repeat=length):
                test_password = ''.join(password_tuple)
                self.attempts += 1
                test_hash = self.hash_password(test_password)
                
                if test_hash == target_hash:
                    elapsed_time = time.time() - self.start_time
                    print(f"✅ Password cracked: '{test_password}'")
                    print(f"Attempts: {self.attempts}")
                    print(f"Time taken: {elapsed_time:.2f} seconds")
                    return test_password
                
                if self.attempts % 10000 == 0:
                    elapsed = time.time() - self.start_time
                    rate = self.attempts / elapsed if elapsed > 0 else 0
                    print(f"Tried {self.attempts} passwords... ({rate:.0f} attempts/sec)")
                    
                # Safety limit to prevent infinite execution
                if self.attempts > 100000:
                    print("⚠️ Stopping brute force test (safety limit reached)")
                    return None
        
        elapsed_time = time.time() - self.start_time
        print(f"❌ Password not cracked within {max_length} characters")
        print(f"Total attempts: {self.attempts}")
        print(f"Time taken: {elapsed_time:.2f} seconds")
        return None

def format_time(seconds: float) -> str:
    """Format time duration in human readable format"""
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.1f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.1f} days"
    else:
        years = seconds / 31536000
        if years > 1000000:
            return f"{years:.0e} years"
        else:
            return f"{years:.0f} years"

def main():
    """Main function to run the password strength checker"""
    checker = PasswordStrengthChecker()
    
    print("🔐 Password Strength Checker with Brute Force Test")
    print("=" * 55)
    print("Educational tool to analyze password security")
    print("=" * 55)
    
    while True:
        print("\nEnter a password to analyze (or 'quit' to exit):")
        password = input("Password: ").strip()
        
        if password.lower() == 'quit':
            break
            
        if not password:
            print("Please enter a password.")
            continue
            
        print(f"\n--- Analyzing Password: {'*' * len(password)} ---")
        
        # Analyze password strength
        analysis = checker.analyze_password_strength(password)
        
        print(f"Length: {analysis['length']} characters")
        print(f"Strength: {analysis['strength']} (Score: {analysis['score']}/8)")
        
        print("\nCharacter Types:")
        print(f"  Lowercase: {'✓' if analysis['has_lowercase'] else '✗'}")
        print(f"  Uppercase: {'✓' if analysis['has_uppercase'] else '✗'}")
        print(f"  Numbers:   {'✓' if analysis['has_digits'] else '✗'}")
        print(f"  Special:   {'✓' if analysis['has_special'] else '✗'}")
        
        if analysis['feedback']:
            print("\nRecommendations:")
            for feedback in analysis['feedback']:
                print(f"  • {feedback}")
        
        # Time estimation
        time_estimate = checker.estimate_crack_time(password)
        print(f"\nCrack Time Estimate:")
        print(f"  Character set size: {time_estimate['charset_size']}")
        print(f"  Total combinations: {time_estimate['combinations']:,}")
        print(f"  Average time to crack: {format_time(time_estimate['seconds'])}")
        
        # Brute force test for short passwords
        if len(password) <= 4:
            print(f"\n--- Brute Force Test ---")
            print("⚠️ Testing actual brute force attack (password ≤ 4 chars)")
            result = checker.brute_force_test(password)
            if result:
                print("🚨 Oops! Your password was successfully cracked!")
            else:
                print("✅ Password survived the limited brute force test")
        else:
            print(f"\n--- Brute Force Test Skipped ---")
            print("Password too long for practical brute force demonstration")
            print("(Would take too long to complete)")
    
    print("\n🎓 Password Security Tips:")
    print("• Use at least 12 characters")
    print("• Mix uppercase, lowercase, numbers, and symbols")
    print("• Avoid dictionary words and personal information")
    print("• Use unique passwords for each account")
    

if __name__ == "__main__":
    main()