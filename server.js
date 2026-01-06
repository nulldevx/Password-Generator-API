
const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  next();
});


function generatePassword(options) {
  const {
    length = 12,
    includeUppercase = true,
    includeLowercase = true,
    includeNumbers = true,
    includeSymbols = true,
    excludeAmbiguous = false
  } = options;

  let charset = '';
  let password = '';

  const lowercase = 'abcdefghijklmnopqrstuvwxyz';
  const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const numbers = '0123456789';
  const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
  const ambiguous = 'il1Lo0O';

  if (includeLowercase) charset += lowercase;
  if (includeUppercase) charset += uppercase;
  if (includeNumbers) charset += numbers;
  if (includeSymbols) charset += symbols;

  if (excludeAmbiguous) {
    charset = charset.split('').filter(char => !ambiguous.includes(char)).join('');
  }

  if (charset.length === 0) {
    throw new Error('Pelo menos um tipo de caractere deve ser selecionado');
  }

  
  if (includeLowercase) password += lowercase[crypto.randomInt(lowercase.length)];
  if (includeUppercase) password += uppercase[crypto.randomInt(uppercase.length)];
  if (includeNumbers) password += numbers[crypto.randomInt(numbers.length)];
  if (includeSymbols) password += symbols[crypto.randomInt(symbols.length)];

  
  for (let i = password.length; i < length; i++) {
    password += charset[crypto.randomInt(charset.length)];
  }

  
  return password.split('').sort(() => crypto.randomInt(3) - 1).join('');
}


function checkPasswordStrength(password) {
  let strength = 0;
  let feedback = [];

  if (password.length >= 8) strength += 1;
  if (password.length >= 12) strength += 1;
  if (password.length >= 16) strength += 1;
  
  if (/[a-z]/.test(password)) strength += 1;
  if (/[A-Z]/.test(password)) strength += 1;
  if (/[0-9]/.test(password)) strength += 1;
  if (/[^a-zA-Z0-9]/.test(password)) strength += 1;

  if (password.length < 8) feedback.push('Senha muito curta');
  if (!/[a-z]/.test(password)) feedback.push('Adicione letras minúsculas');
  if (!/[A-Z]/.test(password)) feedback.push('Adicione letras maiúsculas');
  if (!/[0-9]/.test(password)) feedback.push('Adicione números');
  if (!/[^a-zA-Z0-9]/.test(password)) feedback.push('Adicione símbolos');

  let level;
  if (strength <= 3) level = 'Fraca';
  else if (strength <= 5) level = 'Média';
  else if (strength <= 6) level = 'Forte';
  else level = 'Muito Forte';

  return {
    score: strength,
    level,
    feedback: feedback.length > 0 ? feedback : ['Senha segura!']
  };
}


app.get('/', (req, res) => {
  res.json({
    message: 'API Gerador de Senhas',
    version: '1.0.0',
    endpoints: {
      'POST /api/generate': 'Gerar senha personalizada',
      'POST /api/check-strength': 'Verificar força da senha',
      'GET /api/generate/quick': 'Gerar senha rápida (padrão)'
    }
  });
});


app.get('/api/generate/quick', (req, res) => {
  try {
    const password = generatePassword({});
    const strength = checkPasswordStrength(password);
    
    res.json({
      success: true,
      password,
      length: password.length,
      strength
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});


app.post('/api/generate', (req, res) => {
  try {
    const options = req.body;
    
    
    if (options.length && (options.length < 4 || options.length > 128)) {
      return res.status(400).json({
        success: false,
        error: 'O tamanho da senha deve estar entre 4 e 128 caracteres'
      });
    }

    const password = generatePassword(options);
    const strength = checkPasswordStrength(password);

    res.json({
      success: true,
      password,
      length: password.length,
      options: {
        length: options.length || 12,
        includeUppercase: options.includeUppercase !== false,
        includeLowercase: options.includeLowercase !== false,
        includeNumbers: options.includeNumbers !== false,
        includeSymbols: options.includeSymbols !== false,
        excludeAmbiguous: options.excludeAmbiguous || false
      },
      strength
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});


app.post('/api/check-strength', (req, res) => {
  try {
    const { password } = req.body;

    if (!password) {
      return res.status(400).json({
        success: false,
        error: 'Senha não fornecida'
      });
    }

    const strength = checkPasswordStrength(password);

    res.json({
      success: true,
      password: password,
      length: password.length,
      strength
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});


app.post('/api/generate/bulk', (req, res) => {
  try {
    const { count = 5, ...options } = req.body;

    if (count < 1 || count > 20) {
      return res.status(400).json({
        success: false,
        error: 'Você pode gerar entre 1 e 20 senhas por vez'
      });
    }

    const passwords = [];
    for (let i = 0; i < count; i++) {
      const password = generatePassword(options);
      passwords.push({
        password,
        strength: checkPasswordStrength(password)
      });
    }

    res.json({
      success: true,
      count: passwords.length,
      passwords
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`🚀 API rodando na porta ${PORT}`);
  console.log(`📍 Acesse: http://localhost:${PORT}`);
});