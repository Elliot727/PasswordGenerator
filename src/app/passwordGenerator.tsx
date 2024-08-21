const generateSecurePassword = (master: string, url: string, seed: string, prefix: string, size: number): string => {
    const salt = Buffer.from(url + seed + prefix);
    const iterations = 200000;
    const keyLen = size;
  
    const derivedKey = crypto.pbkdf2Sync(master, salt, iterations, keyLen, 'sha512');
    const hash = crypto.createHash('sha512').update(derivedKey).digest('base64');
  
    let password = prefix + hash.replace(/[+/=]/g, ''); // Remove non-alphanumeric characters
    password = password.slice(0, keyLen);
  
    return ensureComplexity(password);
  };