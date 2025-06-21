require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const path = require('path');
const multer = require('multer');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const upload = multer({ dest: path.join(__dirname, 'public/uploads/') });

// MongoDB connection
const uri = process.env.MONGODB_URI || "mongodb+srv://ltstorestl:Tr93fL7bPqXz19Mn@ltstorestl-db-main.0vfcdr5.mongodb.net/?retryWrites=true&w=majority&appName=ltstorestl-db-main";

mongoose.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || 'supersecret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ mongoUrl: uri }),
  cookie: { maxAge: 1000 * 60 * 60 }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// User model
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false },
  profileName: { type: String },
  profilePicture: { type: String }, // URL or filename
  online: { type: Boolean, default: false }
}));

// Message model
const Message = mongoose.model('Message', new mongoose.Schema({
  from: { type: String, required: true },
  to: { type: String, required: true },
  content: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  read: { type: Boolean, default: false },
  type: { type: String, enum: ['chat', 'inbox'], default: 'inbox' },
  likes: [{ type: String }], // usernames who liked
  reactions: { type: Map, of: [String], default: {} } // emoji: [usernames]
}));

// Post model
const Post = mongoose.model('Post', new mongoose.Schema({
  author: { type: String, required: true },
  content: { type: String },
  media: { type: String },
  emoji: { type: String },
  timestamp: { type: Date, default: Date.now },
  likes: [{ type: String }], // usernames who liked
  reactions: { type: Map, of: [String], default: {} } // emoji: [usernames]
}));

// Report model
const Report = mongoose.model('Report', new mongoose.Schema({
  reporter: { type: String, required: true },
  reportedUser: { type: String, required: true },
  postId: { type: mongoose.Schema.Types.ObjectId, ref: 'Post' },
  reason: { type: String, required: true },
  timestamp: { type: Date, default: Date.now }
}));

// Middleware to check if user is admin
function requireAdmin(req, res, next) {
  if (req.session.user && req.session.user.isAdmin) return next();
  res.redirect('/login');
}

// Routes
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.render('login', { error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.render('login', { error: 'Invalid credentials' });
  req.session.user = { username: user.username, isAdmin: user.isAdmin };
  // Set user online status
  user.online = true;
  await user.save();
  res.redirect('/dashboard');
});

app.get('/dashboard', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = await User.findOne({ username: req.session.user.username });
  // If admin, show all users for management and online status
  let users = [];
  if (user.isAdmin) {
    users = await User.find({}, 'username profileName profilePicture online');
  }
  res.render('dashboard', { user, users });
});

app.get('/admin-setup', (req, res) => {
  res.render('admin-setup', { error: null });
});

app.post('/admin-setup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.render('admin-setup', { error: 'All fields required' });
  const hash = await bcrypt.hash(password, 12);
  try {
    await User.create({ username, password: hash, isAdmin: true });
    res.redirect('/login');
  } catch (e) {
    res.render('admin-setup', { error: 'Username already exists' });
  }
});

app.get('/logout', async (req, res) => {
  if (req.session.user) {
    await User.updateOne({ username: req.session.user.username }, { online: false });
  }
  req.session.destroy(() => res.redirect('/login'));
});

// Admin: Add user page
app.get('/admin/users', requireAdmin, async (req, res) => {
  const users = await User.find({}, 'username profileName profilePicture online isAdmin');
  const user = await User.findOne({ username: req.session.user.username });
  res.render('admin-users', { users, user, error: null });
});

// Admin: Add user form
app.post('/admin/users', requireAdmin, upload.single('profilePicture'), async (req, res) => {
  const { username, password, profileName } = req.body;
  if (!username || !password || !profileName) {
    const users = await User.find({}, 'username profileName profilePicture online');
    return res.render('admin-users', { users, error: 'All fields required' });
  }
  const hash = await bcrypt.hash(password, 12);
  let profilePicture = '';
  if (req.file) {
    profilePicture = '/uploads/' + req.file.filename;
  }
  try {
    await User.create({ username, password: hash, profileName, profilePicture });
    res.redirect('/admin/users');
  } catch (e) {
    const users = await User.find({}, 'username profileName profilePicture online');
    res.render('admin-users', { users, error: 'Username already exists' });
  }
});

// Admin: Remove user and all their data
app.post('/admin/users/delete', requireAdmin, async (req, res) => {
  const { username } = req.body;
  if (!username) return res.redirect('/admin/users');
  // Prevent removing admin users
  const userToDelete = await User.findOne({ username });
  if (!userToDelete || userToDelete.isAdmin) return res.redirect('/admin/users');
  // Remove user
  await User.deleteOne({ username });
  // Remove posts
  await Post.deleteMany({ author: username });
  // Remove messages (sent or received)
  await Message.deleteMany({ $or: [{ from: username }, { to: username }] });
  // Remove reports involving this user
  await Report.deleteMany({ $or: [{ reporter: username }, { reportedUser: username }] });
  res.redirect('/admin/users');
});

app.get('/feed', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = await User.findOne({ username: req.session.user.username });
  const onlineUsers = await User.find({ online: true, username: { $ne: user.username } }, 'username profileName profilePicture online');
  const posts = await Post.find({}).sort({ timestamp: -1 }).limit(20).lean();
  // Attach user info to posts
  for (let post of posts) {
    const postUser = await User.findOne({ username: post.author });
    post.profileName = postUser?.profileName || post.author;
    post.profilePicture = postUser?.profilePicture;
  }
  res.render('feed', { user, onlineUsers, posts });
});

app.post('/feed/post', upload.single('media'), async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  const { content, emoji } = req.body;
  let media = '';
  if (req.file) {
    media = '/uploads/' + req.file.filename;
  }
  await Post.create({ author: req.session.user.username, content, media, emoji });
  res.redirect('/feed');
});

// Inbox send: set type to inbox
app.post('/inbox/send', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  const { to, content } = req.body;
  if (!to || !content) return res.status(400).send('Missing fields');
  await Message.create({ from: req.session.user.username, to, content, type: 'inbox' }); // Set type to inbox
  res.redirect('/inbox');
});

app.get('/inbox', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = await User.findOne({ username: req.session.user.username });
  // Mark all messages as read when visiting inbox
  await Message.updateMany({ to: user.username, read: { $ne: true }, type: 'inbox' }, { read: true });
  const messages = await Message.find({ to: user.username, type: 'inbox' }).sort({ timestamp: -1 }).lean(); // Only inbox messages
  // Get all users for sending messages
  const users = await User.find({ username: { $ne: user.username } }, 'username profileName');
  res.render('inbox', { user, users, messages });
});

app.get('/settings', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const user = await User.findOne({ username: req.session.user.username });
  res.render('settings', { user });
});

app.post('/settings', upload.single('profilePicture'), async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  const { profileName } = req.body;
  let update = { profileName };
  if (req.file) {
    update.profilePicture = '/uploads/' + req.file.filename;
  }
  await User.updateOne({ username: req.session.user.username }, update);
  res.redirect('/settings');
});

app.post('/feed/report', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  const { postId, reportedUser, reason } = req.body;
  if (!postId || !reportedUser || !reason) return res.status(400).send('Missing fields');
  await Report.create({ reporter: req.session.user.username, reportedUser, postId, reason });
  res.redirect('/feed');
});

app.get('/admin/reports', requireAdmin, async (req, res) => {
  const reports = await Report.find({}).sort({ timestamp: -1 }).populate('postId').lean();
  res.render('admin-reports', { reports });
});

// Delete a single inbox message (user or admin)
app.post('/inbox/message/delete', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  const { messageId } = req.body;
  const user = await User.findOne({ username: req.session.user.username });
  const message = await Message.findById(messageId);
  if (!message) return res.redirect('/inbox');
  // Allow delete if user is sender, recipient, or admin
  if (message.from === user.username || message.to === user.username || user.isAdmin) {
    await Message.deleteOne({ _id: messageId });
  }
  res.redirect('/inbox');
});

// Admin: Delete all inbox messages for all users
app.post('/inbox/messages/delete-all', requireAdmin, async (req, res) => {
  await Message.deleteMany({});
  res.redirect('/inbox');
});

// Endpoint to fetch chat history between logged-in user and another user
app.get('/chat/history/:user', async (req, res) => {
  if (!req.session.user) return res.status(401).send('Unauthorized');
  const user1 = req.session.user.username;
  const user2 = req.params.user;
  // Find all chat messages between user1 and user2
  const messages = await Message.find({
    type: 'chat',
    $or: [
      { from: user1, to: user2 },
      { from: user2, to: user1 }
    ]
  }).sort({ timestamp: 1 }).lean();
  res.json(messages);
});

// Socket.IO chat logic
io.on('connection', (socket) => {
  socket.on('join', async (username) => {
    socket.username = username;
    socket.join(username);
    // Set user online in DB
    await User.updateOne({ username }, { online: true });
    // Broadcast to all clients that online users may have changed
    io.emit('online-users-updated');
  });

  // Handle sending chat messages
  socket.on('chat message', async (msg) => {
    if (!msg.from || !msg.to || !msg.content) return;
    const message = await Message.create({ from: msg.from, to: msg.to, content: msg.content, type: 'chat' }); // Set type to chat
    io.to(msg.to).emit('chat message', message);
    socket.emit('chat message', message);
  });

  socket.on('disconnect', async () => {
    if (socket.username) {
      await User.updateOne({ username: socket.username }, { online: false });
      // Broadcast to all clients that online users may have changed
      io.emit('online-users-updated');
    }
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
