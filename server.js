// server.js - Backend Node.js para AUTOGIRO com MySQL
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'autogiro_secret_key_2024';

// Middleware
app.use(cors());
app.use(express.json());

// Configuração do banco MySQL
const dbConfig = {
  host: '82.29.60.164',
  user: 'fribest',
  password: 'fribest',
  database: 'calculadora_autogiro',  // Nome correto do banco
  charset: 'utf8mb4',
  timezone: 'Z',
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

let db;

// Conectar ao MySQL
async function connectToDatabase() {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log('✅ Conectado ao MySQL com sucesso!');
    
    // Criar tabelas se não existirem
    await createTables();
    
    // Criar usuários padrão
    await createDefaultUsers();
    
  } catch (error) {
    console.error('❌ Erro ao conectar com MySQL:', error);
    process.exit(1);
  }
}

// Criar tabelas
async function createTables() {
  try {
    // Tabela de usuários
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role ENUM('admin', 'vendedor', 'usuario') DEFAULT 'usuario',
        status ENUM('ativo', 'inativo') DEFAULT 'ativo',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        
        INDEX idx_email (email),
        INDEX idx_status (status)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    // Tabela de veículos
    await db.execute(`
      CREATE TABLE IF NOT EXISTS vehicles (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        marca VARCHAR(100) NOT NULL,
        modelo VARCHAR(100) NOT NULL,
        ano VARCHAR(10),
        fipe DECIMAL(15,2) DEFAULT 0.00,
        valor_compra DECIMAL(15,2) NOT NULL,
        impostos DECIMAL(15,2) DEFAULT 0.00,
        valor_venda DECIMAL(15,2) NOT NULL,
        observacoes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        
        INDEX idx_user_id (user_id),
        INDEX idx_marca (marca),
        INDEX idx_modelo (modelo),
        INDEX idx_created_at (created_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    console.log('✅ Tabelas criadas/verificadas com sucesso!');
  } catch (error) {
    console.error('❌ Erro ao criar tabelas:', error);
  }
}

// Criar usuários padrão
async function createDefaultUsers() {
  try {
    const defaultUsers = [
      { name: 'Administrador', email: 'admin@autogiro.com', password: '123456', role: 'admin' },
      { name: 'Vendedor Principal', email: 'vendedor@autogiro.com', password: '123456', role: 'vendedor' }
    ];

    for (const user of defaultUsers) {
      // Verificar se usuário já existe
      const [existing] = await db.execute(
        'SELECT id FROM users WHERE email = ?',
        [user.email]
      );

      if (existing.length === 0) {
        const hashedPassword = await bcrypt.hash(user.password, 10);
        await db.execute(
          'INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)',
          [user.name, user.email, hashedPassword, user.role]
        );
        console.log(`✅ Usuário padrão criado: ${user.email} (${user.role})`);
      }
    }
  } catch (error) {
    console.error('❌ Erro ao criar usuários padrão:', error);
  }
}

// Middleware de autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token de acesso requerido' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Token inválido' });
    }
    req.user = user;
    next();
  });
};

// ROTAS DE AUTENTICAÇÃO

// Login
app.post('/api/login', async (req, res) => {
  console.log('📥 Tentativa de login:', req.body.email);
  
  const { email, password } = req.body;

  if (!email || !password) {
    console.log('❌ Email ou senha faltando');
    return res.status(400).json({ 
      success: false, 
      message: 'Email e senha são obrigatórios' 
    });
  }

  try {
    console.log('🔍 Buscando usuário no banco:', email);
    const [rows] = await db.execute(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );

    const user = rows[0];
    console.log('👤 Usuário encontrado:', user ? 'Sim' : 'Não');

    if (!user) {
      console.log('❌ Usuário não encontrado');
      return res.status(401).json({ 
        success: false, 
        message: 'Email ou senha incorretos' 
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    console.log('🔐 Senha válida:', isValidPassword ? 'Sim' : 'Não');

    if (!isValidPassword) {
      console.log('❌ Senha incorreta');
      return res.status(401).json({ 
        success: false, 
        message: 'Email ou senha incorretos' 
      });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log('✅ Login realizado com sucesso para:', email);
    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email
      },
      token
    });
  } catch (error) {
    console.error('💥 Erro no login:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro interno do servidor' 
    });
  }
});

// Registro de novo usuário
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ 
      success: false, 
      message: 'Nome, email e senha são obrigatórios' 
    });
  }

  if (password.length < 6) {
    return res.status(400).json({ 
      success: false, 
      message: 'Senha deve ter pelo menos 6 caracteres' 
    });
  }

  try {
    // Verificar se email já existe
    const [existing] = await db.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existing.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email já está em uso' 
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const [result] = await db.execute(
      'INSERT INTO users (name, email, password) VALUES (?, ?, ?)',
      [name, email, hashedPassword]
    );

    const token = jwt.sign(
      { id: result.insertId, email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(201).json({
      success: true,
      user: {
        id: result.insertId,
        name,
        email
      },
      token
    });
  } catch (error) {
    console.error('Erro no registro:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro interno do servidor' 
    });
  }
});

// ROTAS DE VEÍCULOS

// Listar veículos do usuário
app.get('/api/vehicles', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      'SELECT * FROM vehicles WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );

    res.json({
      success: true,
      vehicles: rows
    });
  } catch (error) {
    console.error('Erro ao buscar veículos:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao buscar veículos' 
    });
  }
});

// Salvar novo veículo
app.post('/api/vehicles', authenticateToken, async (req, res) => {
  const { marca, modelo, ano, fipe, valorCompra, impostos, valorVenda } = req.body;

  if (!marca || !modelo || !valorCompra || !valorVenda) {
    return res.status(400).json({ 
      success: false, 
      message: 'Marca, modelo, valor de compra e valor de venda são obrigatórios' 
    });
  }

  try {
    const [result] = await db.execute(
      `INSERT INTO vehicles 
       (user_id, marca, modelo, ano, fipe, valor_compra, impostos, valor_venda) 
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [req.user.id, marca, modelo, ano || '', fipe || 0, valorCompra, impostos || 0, valorVenda]
    );

    const [vehicle] = await db.execute(
      'SELECT * FROM vehicles WHERE id = ?',
      [result.insertId]
    );

    res.status(201).json({
      success: true,
      vehicle: vehicle[0]
    });
  } catch (error) {
    console.error('Erro ao salvar veículo:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao salvar veículo' 
    });
  }
});

// Buscar veículo específico
app.get('/api/vehicles/:id', authenticateToken, async (req, res) => {
  const vehicleId = req.params.id;

  try {
    const [rows] = await db.execute(
      'SELECT * FROM vehicles WHERE id = ? AND user_id = ?',
      [vehicleId, req.user.id]
    );

    if (rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Veículo não encontrado' 
      });
    }

    res.json({
      success: true,
      vehicle: rows[0]
    });
  } catch (error) {
    console.error('Erro ao buscar veículo:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao buscar veículo' 
    });
  }
});

// Atualizar veículo
app.put('/api/vehicles/:id', authenticateToken, async (req, res) => {
  const vehicleId = req.params.id;
  const { marca, modelo, ano, fipe, valorCompra, impostos, valorVenda } = req.body;

  if (!marca || !modelo || !valorCompra || !valorVenda) {
    return res.status(400).json({ 
      success: false, 
      message: 'Marca, modelo, valor de compra e valor de venda são obrigatórios' 
    });
  }

  try {
    const [result] = await db.execute(
      `UPDATE vehicles 
       SET marca = ?, modelo = ?, ano = ?, fipe = ?, 
           valor_compra = ?, impostos = ?, valor_venda = ?
       WHERE id = ? AND user_id = ?`,
      [marca, modelo, ano || '', fipe || 0, valorCompra, impostos || 0, valorVenda, vehicleId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Veículo não encontrado' 
      });
    }

    res.json({
      success: true,
      message: 'Veículo atualizado com sucesso'
    });
  } catch (error) {
    console.error('Erro ao atualizar veículo:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao atualizar veículo' 
    });
  }
});

// Excluir veículo
app.delete('/api/vehicles/:id', authenticateToken, async (req, res) => {
  const vehicleId = req.params.id;

  try {
    const [result] = await db.execute(
      'DELETE FROM vehicles WHERE id = ? AND user_id = ?',
      [vehicleId, req.user.id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Veículo não encontrado' 
      });
    }

    res.json({
      success: true,
      message: 'Veículo excluído com sucesso'
    });
  } catch (error) {
    console.error('Erro ao excluir veículo:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao excluir veículo' 
    });
  }
});

// ROTAS DE ESTATÍSTICAS

// Dashboard - estatísticas do usuário
app.get('/api/dashboard', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.execute(
      `SELECT 
         COUNT(*) as total_vehicles,
         AVG(valor_venda - valor_compra - impostos) as avg_margin,
         SUM(valor_venda - valor_compra - impostos) as total_margin
       FROM vehicles 
       WHERE user_id = ?`,
      [req.user.id]
    );

    res.json({
      success: true,
      stats: rows[0]
    });
  } catch (error) {
    console.error('Erro ao buscar estatísticas:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Erro ao buscar estatísticas' 
    });
  }
});

// Rota de teste da conexão
app.get('/api/test', async (req, res) => {
  try {
    const [rows] = await db.execute('SELECT 1 as test');
    res.json({
      success: true,
      message: 'Conexão com MySQL funcionando!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Erro na conexão com MySQL',
      error: error.message
    });
  }
});

// Rota principal
app.get('/', (req, res) => {
  res.json({
    message: '🚗 AUTOGIRO API funcionando!',
    version: '1.0.0',
    database: 'MySQL',
    endpoints: {
      auth: ['/api/login', '/api/register'],
      vehicles: ['/api/vehicles'],
      dashboard: ['/api/dashboard'],
      test: ['/api/test']
    }
  });
});

// Middleware de erro global
app.use((err, req, res, next) => {
  console.error('Erro global:', err.stack);
  res.status(500).json({ 
    success: false, 
    message: 'Erro interno do servidor' 
  });
});

// Middleware para rotas não encontradas
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Rota não encontrada'
  });
});

// Inicializar servidor
async function startServer() {
  await connectToDatabase();
  
  app.listen(PORT, () => {
    console.log(`🚗 Servidor AUTOGIRO rodando na porta ${PORT}`);
    console.log(`📊 API: http://localhost:${PORT}/api`);
    console.log(`🔗 Teste: http://localhost:${PORT}/api/test`);
    console.log(`🗄️ MySQL: ${dbConfig.host}/${dbConfig.database}`);
  });
}

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Encerrando servidor...');
  try {
    if (db) {
      await db.end();
      console.log('✅ Conexão MySQL fechada com sucesso.');
    }
  } catch (error) {
    console.error('❌ Erro ao fechar conexão MySQL:', error.message);
  }
  process.exit(0);
});

// Tratar erros não capturados
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('❌ Uncaught Exception:', error);
  process.exit(1);
});

// Iniciar o servidor
startServer().catch(error => {
  console.error('❌ Erro ao iniciar servidor:', error);
  process.exit(1);
});
