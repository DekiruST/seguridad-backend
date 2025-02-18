const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const { db } = require('./firebase');

const app = express();

// Middlewares
app.use(cors());
app.use(express.json());

const SECRET_KEY = 'MI_CLAVE_SUPER_SECRETA';


app.post('/register', async (req, res) => {
  try {
    const { email, username, password, role } = req.body;

    // Validación básica
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Faltan campos requeridos (email, username, password)' });
    }

    // Verifica si ya existe un usuario con ese email
    const usersRef = db.collection('users');
    const querySnapshot = await usersRef.where('email', '==', email).get();

    if (!querySnapshot.empty) {
      return res.status(400).json({ message: 'El email ya está registrado.' });
    }

    // Hashear la contraseña
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Crea el usuario en Firestore
    await usersRef.add({
      email,
      username,
      password: hashedPassword,
      role: role || 'common_user',
      date_register: new Date(),
      last_login: null,
    });

    return res.status(201).json({ message: 'Usuario registrado exitosamente.' });
  } catch (error) {
    console.error('Error en /register:', error);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, username, password } = req.body;

    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Faltan campos requeridos (email, username, password)' });
    }

    // Buscar usuario en Firestore
    const usersRef = db.collection('users');
    const querySnapshot = await usersRef
      .where('email', '==', email)
      .where('username', '==', username)
      .limit(1)
      .get();

    if (querySnapshot.empty) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    let userDoc;
    querySnapshot.forEach(doc => {
      userDoc = { id: doc.id, ...doc.data() };
    });

    // Comparar contraseña
    const match = await bcrypt.compare(password, userDoc.password);
    if (!match) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    // Actualiza last_login
    await usersRef.doc(userDoc.id).update({
      last_login: new Date(),
    });

    // Genera el token JWT (expira en 1 minuto)
    const token = jwt.sign(
      { userId: userDoc.id, role: userDoc.role },
      SECRET_KEY,
      { expiresIn: '1m' }
    );

    // Retorna el token
    res.status(200).json({
      message: 'Login exitoso.',
      token,
    });
  } catch (error) {
    console.error('Error en /login:', error);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor iniciado en http://localhost:${PORT}`);
});
