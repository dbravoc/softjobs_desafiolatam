const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');

const app = express();
const port = 3000;

// Conexión a la base de datos PostgreSQL
const pool = new Pool({
    user: 'capitan',
    host: 'localhost',
    database: 'softjobs',
    port: 5432,
});

app.use(cors());
app.use(express.json());

// Middleware para loggear las peticiones
app.use((req, res, next) => {
    console.log(`Received ${req.method} request for ${req.url}`);
    next();
});

// Ruta para registrar usuarios
app.post('/usuarios', async (req, res) => {
    const { email, password, rol, lenguage } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const result = await pool.query(
            'INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *',
            [email, hashedPassword, rol, lenguage]
        );
        res.status(201).json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ruta para iniciar sesión
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
        if (rows.length > 0) {
            const user = rows[0];
            if (await bcrypt.compare(password, user.password)) {
                const token = jwt.sign({ email: user.email }, 'tu_clave_secreta', { expiresIn: '1h' });
                res.json({ token });
            } else {
                res.status(401).send('Credenciales no válidas');
            }
        } else {
            res.status(404).send('Usuario no encontrado');
        }
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Ruta para obtener información de usuario autenticado
app.get('/usuarios', async (req, res) => {
    const token = req.headers.authorization.split(" ")[1];
    try {
        const decoded = jwt.verify(token, 'tu_clave_secreta');
        const { rows } = await pool.query('SELECT * FROM usuarios WHERE email = $1', [decoded.email]);
        if (rows.length > 0) {
            res.json(rows[0]);
        } else {
            res.status(404).send('Usuario no encontrado');
        }
    } catch (error) {
        res.status(401).send('Token no válido o expirado');
    }
});

// Manejador de errores
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Algo salió mal!');
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
