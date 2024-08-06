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
  const keyLen = size * 2; // Generate more bytes than needed to allow for special character insertion

  const derivedKey = crypto.pbkdf2Sync(master, salt, iterations, keyLen, 'sha512');
  let hash = derivedKey.toString('base64');

  const specialChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const alphanumeric = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

  let password = prefix;
  let specialCharCount = prefix.split('').filter(char => specialChars.includes(char)).length;
  const desiredSpecialChars = Math.max(1, Math.floor(size / 8)); // Aim for about 1 special char per 8 characters

  // Generate the password
  while (password.length < size) {
    const charIndex = parseInt(hash.substr(0, 2), 16);
    hash = crypto.createHash('sha512').update(hash).digest('base64');

    if (specialCharCount < desiredSpecialChars && charIndex % 8 === 0) {
      // Insert a special character
      const specialCharIndex = charIndex % specialChars.length;
      password += specialChars[specialCharIndex];
      specialCharCount++;
    } else {
      // Insert an alphanumeric character
      const alphaNumIndex = charIndex % alphanumeric.length;
      password += alphanumeric[alphaNumIndex];
    }
  }

  return ensureComplexity(password, size);
};

const ensureComplexity = (password: string, size: number): string => {
  const requiredChars = [
    { regex: /[A-Z]/, chars: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' },
    { regex: /[a-z]/, chars: 'abcdefghijklmnopqrstuvwxyz' },
    { regex: /[0-9]/, chars: '0123456789' },
    { regex: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/, chars: '!@#$%^&*()_+-=[]{}|;:,.<>?' }
  ];

  let modifiedPassword = password;

  requiredChars.forEach(({ regex, chars }) => {
    if (!regex.test(modifiedPassword)) {
      // Find a position to replace, preserving the prefix
      let replaceIndex;
      do {
        replaceIndex = crypto.randomInt(prefix.length, modifiedPassword.length);
      } while (regex.test(modifiedPassword[replaceIndex]));

      // Replace with a random character from the required set
      const newChar = chars[crypto.randomInt(chars.length)];
      modifiedPassword = modifiedPassword.slice(0, replaceIndex) + newChar + modifiedPassword.slice(replaceIndex + 1);
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
