const express = require('express');
const cors = require('cors');
const pool = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('../public'));

// ========== AUTH ==========
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Non autorisé' });
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Token invalide' });
        req.user = user;
        next();
    });
};

// ========== UPLOAD ==========
const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, uploadDir),
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });
app.use('/uploads', express.static(uploadDir));

// ========== PUBLIC ROUTES ==========
app.get('/api/health', async (req, res) => {
    try { const r = await pool.query('SELECT NOW()'); res.json({ status: 'OK', time: r.rows[0].now }); }
    catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register', async (req, res) => {
    const { firstname, lastname, email, password, role } = req.body;
    if (!email || !password || !role) return res.status(400).json({ error: 'Champs requis' });
    try {
        const exist = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
        if (exist.rows.length) return res.status(400).json({ error: 'Email déjà utilisé' });
        const hash = await bcrypt.hash(password, 10);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash, role, first_name, last_name) VALUES ($1,$2,$3,$4,$5) RETURNING id,email,role',
            [email, hash, role, firstname || null, lastname || null]
        );
        const user = result.rows[0];
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({ token, user });
    } catch (e) { console.error(e); res.status(500).json({ error: 'Erreur serveur' }); }
});

app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const r = await pool.query('SELECT * FROM users WHERE email=$1', [email]);
        const user = r.rows[0];
        if (!user) return res.status(401).json({ error: 'Identifiants invalides' });
        const ok = await bcrypt.compare(password, user.password_hash);
        if (!ok) return res.status(401).json({ error: 'Identifiants invalides' });
        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id: user.id, email: user.email, role: user.role, first_name: user.first_name, last_name: user.last_name } });
    } catch (e) { res.status(500).json({ error: 'Erreur serveur' }); }
});

// ========== CLASSES (PROF) ==========
app.post('/api/classes', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403).json({ error: 'Réservé' });
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Nom requis' });
    try {
        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        const r = await pool.query(
            'INSERT INTO classes (name, code, professor_id) VALUES ($1,$2,$3) RETURNING id,name,code',
            [name, code, req.user.id]
        );
        res.status(201).json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/classes', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403).json({ error: 'Accès refusé' });
    try {
        const r = await pool.query('SELECT * FROM classes WHERE professor_id=$1 ORDER BY created_at DESC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/classes/:id/students', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const id = parseInt(req.params.id);
    try {
        const r = await pool.query(
            `SELECT u.id, u.email, u.first_name, u.last_name
             FROM class_members cm
             JOIN users u ON cm.user_id = u.id
             WHERE cm.class_id = $1 AND u.role = 'student'`,
            [id]
        );
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/classes/:id/projects', authenticateToken, async (req, res) => {
    const id = parseInt(req.params.id);
    try {
        const r = await pool.query(
            `SELECT p.*, (SELECT COUNT(*) FROM groups g WHERE g.project_id = p.id) as group_count
             FROM projects p
             WHERE p.class_id = $1
             ORDER BY created_at DESC`,
            [id]
        );
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/classes/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const id = parseInt(req.params.id);
    try {
        await pool.query('DELETE FROM classes WHERE id=$1 AND professor_id=$2', [id, req.user.id]);
        res.json({ message: 'Classe supprimée' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== PROJETS (PROF) ==========
app.post('/api/projects', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const { class_id, title, description, group_size, max_groups, deadline, required_skills } = req.body;
    if (!class_id || !title || !group_size) return res.status(400).json({ error: 'Champs requis' });
    if (!required_skills || !required_skills.length) return res.status(400).json({ error: 'Au moins une compétence requise' });

    try {
        await pool.query('BEGIN');
        const p = await pool.query(
            'INSERT INTO projects (class_id, title, description, group_size, max_groups, deadline) VALUES ($1,$2,$3,$4,$5,$6) RETURNING id',
            [class_id, title, description, group_size, max_groups || null, deadline ? new Date(deadline) : null]
        );
        const pid = p.rows[0].id;
        for (const skill of required_skills) {
            await pool.query(
                'INSERT INTO project_skills (project_id, skill_name, required_level) VALUES ($1, $2, $3)',
                [pid, skill.name, skill.level]
            );
        }
        await pool.query('COMMIT');
        res.status(201).json({ id: pid, message: 'Projet créé' });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: e.message });
    }
});

app.put('/api/projects/:id/deadline', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const id = parseInt(req.params.id);
    const { deadline } = req.body;
    try {
        await pool.query(
            'UPDATE projects SET deadline = $1 WHERE id = $2 AND class_id IN (SELECT id FROM classes WHERE professor_id = $3)',
            [deadline ? new Date(deadline) : null, id, req.user.id]
        );
        res.json({ message: 'Date mise à jour' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/projects/:id', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const id = parseInt(req.params.id);
    try {
        await pool.query(
            'DELETE FROM projects WHERE id=$1 AND class_id IN (SELECT id FROM classes WHERE professor_id=$2)',
            [id, req.user.id]
        );
        res.json({ message: 'Projet supprimé' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:id/generate-groups', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        const proj = (await pool.query('SELECT class_id, group_size, title FROM projects WHERE id=$1', [pid])).rows[0];
        if (!proj) return res.status(404).json({ error: 'Projet inexistant' });
        const existing = await pool.query('SELECT id FROM groups WHERE project_id=$1 LIMIT 1', [pid]);
        if (existing.rows.length) return res.status(400).json({ error: 'Groupes déjà générés' });

        // Récupérer tous les étudiants de la classe
        const students = (await pool.query(
            `SELECT u.id, u.first_name, u.last_name
             FROM class_members cm
             JOIN users u ON cm.user_id = u.id
             WHERE cm.class_id = $1 AND u.role = 'student'`,
            [proj.class_id]
        )).rows;
        if (students.length === 0) return res.status(400).json({ error: 'Aucun étudiant' });

        // Compétences requises pour ce projet
        const requiredSkills = (await pool.query(
            'SELECT skill_name, required_level FROM project_skills WHERE project_id = $1',
            [pid]
        )).rows;
        if (requiredSkills.length === 0) return res.status(400).json({ error: 'Aucune compétence requise' });

        // Pour chaque étudiant, récupérer ses niveaux déclarés pour ce projet
        const studentVectors = [];
        for (const s of students) {
            const skills = (await pool.query(
                `SELECT skill_name, level
                 FROM project_user_skills
                 WHERE user_id = $1 AND project_id = $2`,
                [s.id, pid]
            )).rows;
            const skillMap = {};
            skills.forEach(sk => skillMap[sk.skill_name] = sk.level);
            let total = 0;
            for (const req of requiredSkills) {
                total += skillMap[req.skill_name] || 0;
            }
            studentVectors.push({ id: s.id, name: `${s.first_name} ${s.last_name}`, total });
        }

        // Trier par total décroissant
        studentVectors.sort((a,b) => b.total - a.total);
        const numGroups = Math.ceil(studentVectors.length / proj.group_size);
        const groups = Array(numGroups).fill().map(() => []);
        for (let i = 0; i < studentVectors.length; i++) groups[i % numGroups].push(studentVectors[i]);

        await pool.query('BEGIN');
        for (let idx = 0; idx < groups.length; idx++) {
            const g = groups[idx];
            if (!g.length) continue;
            const grp = await pool.query('INSERT INTO groups (project_id) VALUES ($1) RETURNING id', [pid]);
            const gid = grp.rows[0].id;
            for (const stu of g) {
                await pool.query('INSERT INTO group_members (group_id, user_id) VALUES ($1,$2)', [gid, stu.id]);
                await pool.query(
                    'INSERT INTO notifications (user_id, message) VALUES ($1, $2)',
                    [stu.id, `Vous êtes dans le groupe ${idx+1} du projet "${proj.title}".`]
                );
            }
        }
        await pool.query('COMMIT');
        res.json({ message: 'Groupes générés', numGroups: groups.length });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: e.message });
    }
});

app.get('/api/projects/:id/details', authenticateToken, async (req, res) => {
    const pid = parseInt(req.params.id);
    try {
        const p = (await pool.query(
            'SELECT id, class_id, title, description, group_size, deadline FROM projects WHERE id=$1',
            [pid]
        )).rows[0];
        if (!p) return res.status(404).json({ error: 'Projet inexistant' });
        const groups = (await pool.query(
            `SELECT g.id, json_agg(json_build_object('id', u.id, 'name', u.first_name||' '||u.last_name)) as members
             FROM groups g
             LEFT JOIN group_members gm ON g.id = gm.group_id
             LEFT JOIN users u ON gm.user_id = u.id
             WHERE g.project_id = $1
             GROUP BY g.id
             ORDER BY g.id`,
            [pid]
        )).rows;
        p.groups = groups.map(g => ({ id: g.id, members: (g.members || []).filter(m => m.id) }));
        res.json(p);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/projects/:id/required-skills', authenticateToken, async (req, res) => {
    const pid = parseInt(req.params.id);
    try {
        const r = await pool.query('SELECT skill_name, required_level FROM project_skills WHERE project_id = $1', [pid]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ========== COMPÉTENCES ÉTUDIANT PAR PROJET ==========
app.get('/api/projects/:id/my-skills', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        const r = await pool.query(
            'SELECT skill_name, level FROM project_user_skills WHERE user_id = $1 AND project_id = $2',
            [req.user.id, pid]
        );
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/projects/:id/my-skills', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const pid = parseInt(req.params.id);
    const { skills } = req.body; // [{ name, level }]
    if (!skills || !Array.isArray(skills)) return res.status(400).json({ error: 'Format invalide' });
    try {
        await pool.query('BEGIN');
        await pool.query('DELETE FROM project_user_skills WHERE user_id = $1 AND project_id = $2', [req.user.id, pid]);
        for (const sk of skills) {
            await pool.query(
                'INSERT INTO project_user_skills (user_id, project_id, skill_name, level) VALUES ($1, $2, $3, $4)',
                [req.user.id, pid, sk.name, sk.level]
            );
        }
        await pool.query('COMMIT');
        res.json({ message: 'Compétences enregistrées' });
    } catch (e) {
        await pool.query('ROLLBACK');
        res.status(500).json({ error: e.message });
    }
});

// ========== SOUMISSIONS ==========
app.post('/api/projects/:id/submit', authenticateToken, upload.single('file'), async (req, res) => {
    if (req.user.role !== 'student') return res.status(403).json({ error: 'Réservé aux étudiants' });
    const pid = parseInt(req.params.id);
    if (!req.file) return res.status(400).json({ error: 'Aucun fichier' });
    try {
        const deadlineRes = await pool.query('SELECT deadline FROM projects WHERE id=$1', [pid]);
        const deadline = deadlineRes.rows[0]?.deadline;
        if (deadline && new Date() > new Date(deadline)) return res.status(403).json({ error: 'Délai dépassé' });

        const groupRes = await pool.query(
            `SELECT g.id FROM groups g
             JOIN group_members gm ON g.id = gm.group_id
             WHERE g.project_id = $1 AND gm.user_id = $2`,
            [pid, req.user.id]
        );
        if (groupRes.rows.length === 0) return res.status(400).json({ error: 'Vous n\'êtes dans aucun groupe' });
        const groupId = groupRes.rows[0].id;
        const fileUrl = `/uploads/${req.file.filename}`;
        await pool.query(
            `INSERT INTO submissions (group_id, project_id, file_url, submitted_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (group_id, project_id)
             DO UPDATE SET file_url = EXCLUDED.file_url, submitted_at = NOW()`,
            [groupId, pid, fileUrl]
        );
        res.json({ message: 'Fichier soumis' });
    } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});

app.get('/api/projects/:id/my-submission', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        const groupRes = await pool.query(
            `SELECT g.id FROM groups g
             JOIN group_members gm ON g.id = gm.group_id
             WHERE g.project_id = $1 AND gm.user_id = $2`,
            [pid, req.user.id]
        );
        if (groupRes.rows.length === 0) return res.json({ submission: null });
        const groupId = groupRes.rows[0].id;
        const subRes = await pool.query(
            `SELECT file_url, submitted_at, grade FROM submissions
             WHERE group_id = $1 AND project_id = $2`,
            [groupId, pid]
        );
        if (subRes.rows.length === 0) res.json({ submission: null });
        else res.json({ submission: subRes.rows[0] });
    } catch (err) { console.error(err); res.status(500).json({ error: err.message }); }
});

app.delete('/api/projects/:id/my-submission', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        const groupRes = await pool.query(
            `SELECT g.id FROM groups g
             JOIN group_members gm ON g.id = gm.group_id
             WHERE g.project_id = $1 AND gm.user_id = $2`,
            [pid, req.user.id]
        );
        if (groupRes.rows.length === 0) return res.status(404).json({ error: 'Groupe non trouvé' });
        const groupId = groupRes.rows[0].id;
        await pool.query('DELETE FROM submissions WHERE group_id=$1 AND project_id=$2', [groupId, pid]);
        res.json({ message: 'Soumission supprimée' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/projects/:id/submissions', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        // D'abord récupérer tous les groupes du projet
        const groups = await pool.query(
            `SELECT g.id as group_id,
                    string_agg(u.first_name || ' ' || u.last_name, ', ') as members
             FROM groups g
             JOIN group_members gm ON g.id = gm.group_id
             JOIN users u ON gm.user_id = u.id
             WHERE g.project_id = $1
             GROUP BY g.id
             ORDER BY g.id`,
            [pid]
        );
        if (groups.rows.length === 0) {
            return res.json([]);
        }
        // Pour chaque groupe, ajouter les infos de soumission
        const result = [];
        for (const grp of groups.rows) {
            const sub = await pool.query(
                `SELECT file_url, submitted_at, grade
                 FROM submissions
                 WHERE group_id = $1 AND project_id = $2`,
                [grp.group_id, pid]
            );
            result.push({
                group_id: grp.group_id,
                members: grp.members,
                file_url: sub.rows[0]?.file_url || null,
                submitted_at: sub.rows[0]?.submitted_at || null,
                grade: sub.rows[0]?.grade || null
            });
        }
        res.json(result);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/projects/:id/grade', authenticateToken, async (req, res) => {
    if (req.user.role !== 'professor') return res.status(403);
    const pid = parseInt(req.params.id);
    const { group_id, grade } = req.body;
    if (!group_id || grade === undefined || grade < 0 || grade > 20) return res.status(400).json({ error: 'Note invalide' });
    try {
        await pool.query(
            'UPDATE submissions SET grade = $1 WHERE project_id = $2 AND group_id = $3',
            [grade, pid, group_id]
        );
        res.json({ message: 'Note enregistrée' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// ========== ROUTES ÉTUDIANTS ==========
app.post('/api/classes/join', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const { code } = req.body;
    try {
        const c = (await pool.query('SELECT id, name FROM classes WHERE code=$1', [code])).rows[0];
        if (!c) return res.status(404).json({ error: 'Classe introuvable' });
        const exist = await pool.query('SELECT * FROM class_members WHERE user_id=$1 AND class_id=$2', [req.user.id, c.id]);
        if (exist.rows.length) return res.status(400).json({ error: 'Déjà membre' });
        await pool.query('INSERT INTO class_members (user_id, class_id) VALUES ($1,$2)', [req.user.id, c.id]);
        res.json({ message: 'Inscription réussie', class: c });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/classes/:id/leave', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const id = parseInt(req.params.id);
    try {
        await pool.query('DELETE FROM class_members WHERE user_id=$1 AND class_id=$2', [req.user.id, id]);
        res.json({ message: 'Classe quittée' });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/student/classes', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    try {
        const r = await pool.query(
            `SELECT c.*, u.first_name as professor_name
             FROM classes c
             JOIN class_members cm ON cm.class_id = c.id
             JOIN users u ON u.id = c.professor_id
             WHERE cm.user_id = $1
             ORDER BY c.created_at DESC`,
            [req.user.id]
        );
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/student/classes/:id/projects', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const id = parseInt(req.params.id);
    try {
        const r = await pool.query(
            `SELECT p.*,
                    (SELECT COUNT(*) FROM groups g WHERE g.project_id = p.id) as group_count
             FROM projects p
             WHERE p.class_id = $1
             ORDER BY created_at DESC`,
            [id]
        );
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/projects/:id/my-group', authenticateToken, async (req, res) => {
    if (req.user.role !== 'student') return res.status(403);
    const pid = parseInt(req.params.id);
    try {
        const proj = (await pool.query('SELECT title, description FROM projects WHERE id=$1', [pid])).rows[0];
        if (!proj) return res.status(404).json({ error: 'Projet inexistant' });
        const group = (await pool.query(
            `SELECT g.id FROM groups g
             JOIN group_members gm ON g.id = gm.group_id
             WHERE g.project_id = $1 AND gm.user_id = $2`,
            [pid, req.user.id]
        )).rows[0];
        if (!group) return res.json({ project: proj, group: null });
        const members = (await pool.query(
            `SELECT u.id, u.first_name || ' ' || u.last_name as name
             FROM group_members gm
             JOIN users u ON gm.user_id = u.id
             WHERE gm.group_id = $1`,
            [group.id]
        )).rows;
        res.json({ project: proj, group: { id: group.id, members } });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/notifications', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT * FROM notifications WHERE user_id=$1 ORDER BY created_at DESC', [req.user.id]);
        res.json(r.rows);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/me', authenticateToken, async (req, res) => {
    try {
        const r = await pool.query('SELECT id, email, role, first_name, last_name FROM users WHERE id=$1', [req.user.id]);
        if (r.rows.length === 0) return res.status(404).json({ error: 'Utilisateur non trouvé' });
        res.json(r.rows[0]);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.listen(port, () => console.log(`EduMatch backend sur http://localhost:${port}`));