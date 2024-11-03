require('dotenv').config(); // Carregar variáveis de ambiente

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const db = require('./database/models/');
const { eAdmin } = require('./middlewares/auth');

const app = express();
const port = 3000;

// Middleware de proteção CSRF
const csrfProtection = csrf({ cookie: true });

// Middleware de verificação de token JWT
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ message: 'Token não fornecido' });
  }

  jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Token inválido' });
    }
    req.userId = decoded.id;
    next();
  });
};

// Configuração de middlewares
app.use(express.json());
app.use(cookieParser()); // Necessário para a proteção CSRF
app.use(cors());
app.use(helmet()); // Adiciona cabeçalhos de segurança HTTP
app.use(csrfProtection); // Adiciona proteção CSRF

// Limitador de requisições para prevenir força bruta
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 5, // Limita a 5 requisições por IP
  message: 'Muitas tentativas de login. Tente novamente mais tarde.'
});

// Servidor rodando
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});

// Rota de login com limitador de requisições
app.post('/login', loginLimiter, [
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('A senha deve ter no mínimo 8 caracteres')
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const user = await db.Register.findOne({
      attributes: ['id', 'email', 'password'],
      where: { email: req.body.email }
    });

    if (!user) {
      return res.status(400).json({
        erro: true,
        mensagem: 'Usuário não localizado. Realize o cadastro.'
      });
    }

    const passwordMatch = await bcrypt.compare(req.body.password, user.password);
    if (!passwordMatch) {
      return res.status(400).json({
        erro: true,
        mensagem: 'Email ou senha inválidos!'
      });
    }

    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: '1h'
    });

    res.cookie('XSRF-TOKEN', req.csrfToken()); // Enviar token CSRF em um cookie

    return res.json({
      erro: false,
      mensagem: 'Login realizado com sucesso!',
      token
    });
  } catch (error) {
    return res.status(500).json({ mensagem: 'Erro interno do servidor' });
  }
});

// Rota de registro com validação e sanitização de entrada
app.post('/register', [
  body('email').isEmail().withMessage('Email inválido').normalizeEmail(),
  body('password').isLength({ min: 8 }).withMessage('A senha deve ter no mínimo 8 caracteres').trim().escape(),
  body('name').isAlphanumeric('pt-BR').withMessage('O nome deve conter apenas letras e números').trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    var data = req.body;
    data.password = await bcrypt.hash(data.password, 12); // Hashing seguro

    const existingUser = await db.Register.findOne({ where: { email: data.email } });
    if (existingUser) {
      return res.status(400).json({ mensagem: 'Email já está em uso!' });
    }

    await db.Register.create(data);
    return res.json({ erro: false, mensagem: 'Cadastrado com sucesso!' });
  } catch (error) {
    return res.status(500).json({ mensagem: 'Erro ao registrar o usuário' });
  }
});

// Rota protegida para listar cartões com validação e proteção
app.get('/cards', verifyToken, async (req, res) => {
  try {
    const cards = await db.Card.findAll();
    return res.json({ id_user: req.userId, cards });
  } catch (err) {
    return res.status(500).json({ mensagem: 'Erro ao buscar cartões' });
  }
});

// Rota para criar cartão com autenticação e validação de entrada
app.post('/create-card', verifyToken, eAdmin, [
  body('cardNumber').isNumeric().withMessage('O número do cartão deve ser numérico').trim().escape(),
  body('expiryDate').isDate().withMessage('A data de expiração deve ser válida').trim().escape(),
  body('cvv').isLength({ min: 3, max: 4 }).isNumeric().withMessage('CVV deve ser numérico com 3 ou 4 dígitos').trim().escape()
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    const data = req.body;
    const cardUser = await db.Card.create(data);
    return res.json({ error: false, message: 'Cartão cadastrado', data: cardUser });
  } catch (err) {
    return res.status(500).json({ mensagem: 'Erro ao criar cartão' });
  }
});

// Outras rotas devem seguir o mesmo padrão de validação e segurança...
