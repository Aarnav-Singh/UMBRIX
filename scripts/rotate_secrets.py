#!/usr/bin/env python3
import os
import secrets
import string
import re

def generate_secure_secret(length=64):
    """Generate a cryptographically secure random string."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def update_env_file(env_path):
    if not os.path.exists(env_path):
        print(f"Error: {env_path} not found.")
        return False
        
    with open(env_path, 'r') as f:
        content = f.read()
        
    # Generate new secrets
    new_jwt_secret = generate_secure_secret(64)
    new_internal_key = generate_secure_secret(64)
    new_postgres_pwd = generate_secure_secret(32)
    
    # Update JWT_SECRET_KEY
    content = re.sub(
        r'^(JWT_SECRET_KEY=).*$', 
        f'\\g<1>{new_jwt_secret}', 
        content, 
        flags=re.MULTILINE
    )
    
    # Update INTERNAL_SERVICE_API_KEY
    content = re.sub(
        r'^(INTERNAL_SERVICE_API_KEY=).*$', 
        f'\\g<1>{new_internal_key}', 
        content, 
        flags=re.MULTILINE
    )
    
    # Update POSTGRES_DSN password
    content = re.sub(
        r'^(POSTGRES_DSN=postgresql\+asyncpg://sentinel:)[^@]+(@.*)$', 
        f'\\g<1>{new_postgres_pwd}\\g<2>', 
        content, 
        flags=re.MULTILINE
    )
    
    # Optional: Update CLICKHOUSE_PASSWORD if it's not empty
    content = re.sub(
        r'^(CLICKHOUSE_PASSWORD=).+$', 
        f'\\g<1>{generate_secure_secret(32)}', 
        content, 
        flags=re.MULTILINE
    )
    
    # Save the updated content
    with open(env_path, 'w') as f:
        f.write(content)
        
    print(f"Successfully rotated secrets in {env_path}")
    print("WARNING: Restart all services for the new secrets to take effect.")
    print("If you have active user sessions, they will be invalidated due to the new JWT secret.")
    return True

if __name__ == "__main__":
    env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
    print(f"Rotating secrets for {env_file}...")
    update_env_file(env_file)
