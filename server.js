// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { db } = require('./firebase');

const app = express();
app.use(cors());
app.use(express.json());

// Clave secreta para JWT (en producción usar variable de entorno)
const SECRET_KEY = 'MI_CLAVE_SUPER_SECRETA';


// 1) verifyToken: extrae el token del header Authorization y verifica
function verifyToken(req, res, next) {
  try {
    const authHeader = req.headers['authorization']; 
    if (!authHeader) {
      return res.status(401).json({ message: 'No se proporcionó token' });
    }

    // authHeader debe ser "Bearer <token>"
    const token = authHeader.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token inválido' });
    }

    // Decodifica el token
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;

    next();
  } catch (error) {
    console.error('Error en verifyToken:', error);
    return res.status(401).json({ message: 'Token inválido o expirado' });
  }
}

// 2) checkPermission: consulta Firestore para saber si el rol del usuario tiene el permiso
async function checkPermission(permissionName, req, res) {
  try {
    const userRole = req.user.role;
    if (!userRole) {
      return false;
    }
    // Lee la colección roles con el doc userRole
    const roleDoc = await db.collection('roles').doc(userRole).get();
    if (!roleDoc.exists) {
      return false;
    }
    const roleData = roleDoc.data();

    return roleData.permissions.includes(permissionName);
  } catch (error) {
    console.error('Error en checkPermission:', error);
    return false;
  }
}

function requirePermission(permissionName) {
  return async (req, res, next) => {

    const hasPerm = await checkPermission(permissionName, req, res);
    if (!hasPerm) {
      return res.status(403).json({ message: 'No tienes permisos para esta acción' });
    }
    next();
  };
}


// REGISTRO
app.post('/register', async (req, res) => {
  try {
    const { email, username, password, role } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Faltan campos requeridos (email, username, password)' });
    }

    // Verificar si ya existe un usuario con ese email
    const usersRef = db.collection('users');
    const querySnapshot = await usersRef.where('email', '==', email).get();
    if (!querySnapshot.empty) {
      return res.status(400).json({ message: 'El email ya está registrado.' });
    }

    // Hashear password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    await usersRef.add({
      email,
      username,
      password: hashedPassword,
      role: role || 'common_user',
      date_register: new Date(),
      last_login: null
    });

    return res.status(201).json({ message: 'Usuario registrado exitosamente.' });
  } catch (error) {
    console.error('Error en /register:', error);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  try {
    const { email, username, password } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: 'Faltan campos requeridos (email, username, password)' });
    }

    // Buscar usuario
    const usersRef = db.collection('users');
    const query = await usersRef
      .where('email', '==', email)
      .where('username', '==', username)
      .limit(1)
      .get();

    if (query.empty) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }
    let userDoc;
    query.forEach(doc => {
      userDoc = { id: doc.id, ...doc.data() };
    });

    // Comparar contraseña
    const match = await bcrypt.compare(password, userDoc.password);
    if (!match) {
      return res.status(401).json({ message: 'Credenciales inválidas.' });
    }

    // Actualiza last_login
    await usersRef.doc(userDoc.id).update({ last_login: new Date() });

    // Genera token 
    const token = jwt.sign(
      { userId: userDoc.id, role: userDoc.role },
      SECRET_KEY,
      { expiresIn: '1m' }
    );

    return res.status(200).json({ message: 'Login exitoso.', token });
  } catch (error) {
    console.error('Error en /login:', error);
    return res.status(500).json({ message: 'Error interno del servidor.' });
  }
});


// 1) GET USERS 
app.get('/getUsers', verifyToken, requirePermission('getUser'), async (req, res) => {
  try {
    const snapshot = await db.collection('users').get();
    const users = [];
    snapshot.forEach(doc => {
      users.push({ id: doc.id, ...doc.data() });
    });
    res.status(200).json({ users });
  } catch (error) {
    console.error('/getUsers error:', error);
    res.status(500).json({ message: 'Error al obtener usuarios' });
  }
});

// 2) DELETE USER 
app.delete('/deleteUsers/:id', verifyToken, requirePermission('deleteUser'), async (req, res) => {
  try {
    const userId = req.params.id;
    await db.collection('users').doc(userId).delete();
    res.status(200).json({ message: 'Usuario eliminado con éxito' });
  } catch (error) {
    console.error('/deleteUsers error:', error);
    res.status(500).json({ message: 'Error al eliminar usuario' });
  }
});

// 3) UPDATE USER 
app.put('/updateUsers/:id', verifyToken, requirePermission('updateUser'), async (req, res) => {
  try {
    const userId = req.params.id;
    const { email, username, role } = req.body;

    const dataToUpdate = {};
    if (email) dataToUpdate.email = email;
    if (username) dataToUpdate.username = username;
    if (role) dataToUpdate.role = role;

    await db.collection('users').doc(userId).update(dataToUpdate);
    res.status(200).json({ message: 'Usuario actualizado' });
  } catch (error) {
    console.error('/updateUsers error:', error);
    res.status(500).json({ message: 'Error al actualizar usuario' });
  }
});

// 4) UPDATE ROL 
app.put('/updateRol/:roleName', verifyToken, requirePermission('updateRol'), async (req, res) => {
  try {
    const { roleName } = req.params;
    const { permissions } = req.body; // array de permisos nuevos
    await db.collection('roles').doc(roleName).update({ permissions });
    res.status(200).json({ message: 'Rol actualizado con éxito' });
  } catch (error) {
    console.error('/updateRol error:', error);
    res.status(500).json({ message: 'Error al actualizar rol' });
  }
});

// 5) ADD ROL 
app.post('/addRol', verifyToken, requirePermission('addRol'), async (req, res) => {
  try {
    const { role_name, permissions } = req.body;
    // Crea un doc con ID = role_name
    await db.collection('roles').doc(role_name).set({
      role_name,
      permissions: permissions || []
    });
    res.status(201).json({ message: 'Rol creado exitosamente' });
  } catch (error) {
    console.error('/addRol error:', error);
    res.status(500).json({ message: 'Error al crear rol' });
  }
});

// 6) DELETE ROL 
app.delete('/deleteRol/:roleName', verifyToken, requirePermission('deleteRol'), async (req, res) => {
  try {
    const { roleName } = req.params;
    await db.collection('roles').doc(roleName).delete();
    res.status(200).json({ message: 'Rol eliminado con éxito' });
  } catch (error) {
    console.error('/deleteRol error:', error);
    res.status(500).json({ message: 'Error al eliminar rol' });
  }
});

// 7) ADD PERMISSION 
app.post('/addPermission/:roleName', verifyToken, requirePermission('addPermission'), async (req, res) => {
  try {
    const { roleName } = req.params;
    const { permission } = req.body; 

    // leer rol actual
    const roleDoc = await db.collection('roles').doc(roleName).get();
    if (!roleDoc.exists) {
      return res.status(404).json({ message: 'Rol no encontrado' });
    }
    const roleData = roleDoc.data();
    const updatedPermissions = new Set([ ...(roleData.permissions || []), permission ]);

    // guardar
    await db.collection('roles').doc(roleName).update({ permissions: Array.from(updatedPermissions) });
    res.status(200).json({ message: 'Permiso agregado al rol' });
  } catch (error) {
    console.error('/addPermission error:', error);
    res.status(500).json({ message: 'Error al agregar permiso' });
  }
});

// 8) DELETE PERMISSION 
app.post('/deletePermission/:roleName', verifyToken, requirePermission('deletePermission'), async (req, res) => {
  try {
    const { roleName } = req.params;
    const { permission } = req.body;

    const roleDoc = await db.collection('roles').doc(roleName).get();
    if (!roleDoc.exists) {
      return res.status(404).json({ message: 'Rol no encontrado' });
    }
    const roleData = roleDoc.data();

    const filteredPerms = (roleData.permissions || []).filter(p => p !== permission);
    await db.collection('roles').doc(roleName).update({ permissions: filteredPerms });

    res.status(200).json({ message: 'Permiso eliminado del rol' });
  } catch (error) {
    console.error('/deletePermission error:', error);
    res.status(500).json({ message: 'Error al eliminar permiso' });
  }
});

// Endpoint para obtener todos los roles y sus permisos
app.get('/getRoles', verifyToken, async (req, res) => {
  try {
    const snapshot = await db.collection('roles').get();
    const roles = [];
    snapshot.forEach(doc => {
      roles.push({ id: doc.id, ...doc.data() });
    });
    res.status(200).json({ roles });
  } catch (error) {
    console.error('Error en /getRoles:', error);
    res.status(500).json({ message: 'Error al obtener roles' });
  }
});


const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en http://localhost:${PORT}`);
});
