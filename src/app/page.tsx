"use client";

import React, { FormEvent, useState, useEffect } from 'react';
import crypto from 'crypto';

export interface PasswordFormElements extends HTMLFormControlsCollection {
  master: HTMLInputElement;
  url: HTMLInputElement;
  seed: HTMLInputElement;
  prefix: HTMLInputElement;
  size: HTMLSelectElement;
}

export interface PasswordForm extends HTMLFormElement {
  readonly elements: PasswordFormElements;
}

const generateSecurePassword = (master: string, url: string, seed: string, prefix: string, size: number): string => {
  const salt = Buffer.from(url + seed);
  const iterations = 200000;
  const keyLen = size - prefix.length; // Adjust key length based on prefix

  const derivedKey = crypto.pbkdf2Sync(master, salt, iterations, keyLen, 'sha512');
  const hash = crypto.createHash('sha512').update(derivedKey).digest('base64');

  // Include special characters in the character set
  const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const alphanumeric = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const allChars = alphanumeric + specialChars;

  let password = prefix;
  
  // Ensure at least one special character
  if (!specialChars.split('').some(char => prefix.includes(char))) {
    password += specialChars[Math.floor(Math.random() * specialChars.length)];
  }

  // Fill the rest of the password
  while (password.length < size) {
    const charIndex = parseInt(hash.substr(0, 2), 16) % allChars.length;
    password += allChars[charIndex];
    hash = crypto.createHash('sha512').update(hash).digest('base64');
  }

  return ensureComplexity(password, size);
};

const ensureComplexity = (password: string, size: number): string => {
  const requiredChars = [
    { regex: /[A-Z]/, char: 'A' },
    { regex: /[a-z]/, char: 'a' },
    { regex: /[0-9]/, char: '1' },
    { regex: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/, char: '!' }
  ];

  let modifiedPassword = password;

  requiredChars.forEach(({ regex, char }, index) => {
    if (!regex.test(modifiedPassword)) {
      // Replace a character in the latter half of the password, preserving the prefix
      const replaceIndex = Math.floor(modifiedPassword.length / 2) + index;
      modifiedPassword = modifiedPassword.slice(0, replaceIndex) + char + modifiedPassword.slice(replaceIndex + 1);
    }
  });

  return modifiedPassword.slice(0, size); // Ensure the final length is correct
};


const PasswordGenerator = () => {
  const [password, setPassword] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string>('');

  useEffect(() => {
    console.log('Loading state changed:', loading);
  }, [loading]);

  const handleSubmit = async (event: FormEvent<PasswordForm>) => {
    event.preventDefault();
    setError('');
    setLoading(true);

    const form = event.currentTarget;
    const { master, url, seed, prefix, size } = form.elements;

    if (!master.value || !url.value || !seed.value || !size.value) {
      setError('Please fill in all required fields.');
      setLoading(false);
      return;
    }

    try {
      const generatedPassword = await new Promise<string>((resolve, reject) => {
        setTimeout(() => {
          try {
            resolve(generateSecurePassword(master.value, url.value, seed.value, prefix.value || '', parseInt(size.value, 10)));
          } catch (error) {
            reject(error);
          }
        }, 0);
      });
      setPassword(generatedPassword);
    } catch (error) {
      setError('An error occurred while generating the password.');
      console.error(error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="container">
      <h1>Ultra-Secure Password Generator</h1>
      <form id="password-form" onSubmit={handleSubmit}>
        <label htmlFor="master">
          Master Password:
          <span className="tooltip">
            ⓘ
            <span className="tooltiptext">
              Use a strong, unique master password that you don&apos;t use anywhere else.
            </span>
          </span>
        </label>
        <input type="password" id="master" name="master" required />

        <label htmlFor="url">
          Service/URL:
          <span className="tooltip">
            ⓘ
            <span className="tooltiptext">
              Enter the website or service name for which you&apos;re generating the password.
            </span>
          </span>
        </label>
        <input type="text" id="url" name="url" required />

        <label htmlFor="seed">
          Personal Seed:
          <span className="tooltip">
            ⓘ
            <span className="tooltiptext">
              Use a personal, memorable piece of information (e.g., birthdate) to add extra security.
            </span>
          </span>
        </label>
        <input type="text" id="seed" name="seed" required />

        <label htmlFor="prefix">
          Custom Prefix:
          <span className="tooltip">
            ⓘ
            <span className="tooltiptext">
              Optional: Add a custom prefix to meet specific password requirements.
            </span>
          </span>
        </label>
        <input type="text" id="prefix" name="prefix" />

        <label htmlFor="size">Password Length:</label>
        <select id="size" name="size" defaultValue="32" required>
          <option value="24">24 characters</option>
          <option value="32">32 characters</option>
          <option value="48">48 characters</option>
        </select>

        <button type="submit">Generate Password</button>
      </form>
      {loading && (
        <div className="spinner-container">
          <div className="spinner"></div>
          <p>Generating password...</p>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      {password && !loading && (
        <div className="password-container">
          <h2>Generated Password:</h2>
          <div className="password">
            <span id="generated-password">{password}</span>
            <button className="copy-btn" onClick={() => navigator.clipboard.writeText(password)}>
              Copy
            </button>
          </div>
          <div className="strength-meter">
            <div className="strength-meter-fill" style={{ width: '100%', backgroundColor: 'var(--success-color)' }}></div>
          </div>
        </div>
      )}
    </div>
  );
};

export default PasswordGenerator;
