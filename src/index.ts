import express, { type Request, type Response, type NextFunction } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'moneris-super-secret-key';

app.use(express.json());
app.use(cors());

// Hardcoded hashed PIN for our mock user (corresponds to the plain PIN: "1234")
const HASHED_PIN = bcrypt.hashSync('1234', 10);

interface Transaction {
  id: string;
  merchant: string;
  amount: number;
  status: 'approved' | 'declined';
  date: string;
}

const MOCK_TRANSACTIONS: Transaction[] = [
  { id: 'tx_1', merchant: 'Starbucks', amount: 5.45, status: 'approved', date: '2026-07-15T10:00:00Z' },
  { id: 'tx_2', merchant: 'Amazon Canada', amount: 114.20, status: 'approved', date: '2026-07-15T11:30:00Z' },
  { id: 'tx_3', merchant: 'Loblaws', amount: 84.50, status: 'declined', date: '2026-07-15T14:15:00Z' }
];

// Custom TypeScript interface to extend Express Request with user payloads
interface AuthenticatedRequest extends Request {
  user?: any;
}

// ROUTE GUARD MIDDLEWARE
const verifyToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Expected format: "Bearer <token>"

  if (!token) {
    return res.status(401).json({ error: 'Access denied. Missing token header.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next(); // Pass control down to the actual route handler
  } catch (err) {
    res.status(403).json({ error: 'Invalid or expired token.' });
  }
};

// PUBLIC AUTHENTICATION ENDPOINT
app.post('/api/auth/login', async (req: Request, res: Response) => {
  const { pin } = req.body;

  if (!pin) {
    return res.status(400).json({ error: 'PIN is required' });
  }

  // Compare incoming plain text PIN to our hashed variant
  const isMatch = await bcrypt.compare(pin, HASHED_PIN);
  if (isMatch) {
    // Generate token valid for 1 hour
    const token = jwt.sign({ userId: 'user_moneris_1' }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token });
  }

  return res.status(401).json({ error: 'Invalid security PIN' });
});

// PROTECTED ROUTE (Notice the verifyToken argument injected before the handler)
app.get('/api/transactions', verifyToken, (req: AuthenticatedRequest, res: Response) => {
  res.json(MOCK_TRANSACTIONS);
});

app.listen(PORT, () => {
  console.log(`[Server]: API updated and listening on port ${PORT}`);
});