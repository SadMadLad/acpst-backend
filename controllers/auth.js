import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';

export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // Check if email already exists
    const existingUser = await User.findOne({ email: email });
    if (existingUser) return res.status(400).json({ error: 'Email already exists' });

    // Generate salt for password
    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    // Create new user
    const newUser = new User({
      name,
      email,
      password: passwordHash,
    })

    // Sign Token
    const user = await newUser.save();
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);

    res.status(201).json({ user, token });
  }
  catch (err) {
    res.status(500).json({ error: err.message });
  }
}

export const login  = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email: email });
    if (!user) return res.status(400).json({ msg: 'Email does not exist' });

    // Check if password is correct
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });
    delete user.password;

    // Sign Token and send it back
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.status(200).json({ token, user });
  }
  catch (err) {
    res.status(500).json({ error: err.message });
  }
}
