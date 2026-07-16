import request from 'supertest';
import express, { type Request, type Response, type NextFunction } from 'express';
import jwt from 'jsonwebtoken';


// Setup an isolated Express instances for test boundaries
const app = express();
app.use(express.json());

const JWT_SECRET = 'test-secret';

interface AuthenticatedRequest extends Request {
  user?: any;
}

const verifyToken = (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

app.get('/api/transactions', verifyToken, (req: AuthenticatedRequest, res: Response) => {
  res.json([{ id: 'tx_test', amount: 10.00 }]);
});

describe('Moneris API Guard Assertions', () => {
  
  it('should return 401 Unauthorized if the Authorization header is completely missing', async () => {
    const response = await request(app).get('/api/transactions');
    expect(response.statusCode).toBe(401);
    expect(response.body).toHaveProperty('error');
  });

  it('should return 403 Forbidden if an invalid or corrupted token is passed down', async () => {
    const response = await request(app)
      .get('/api/transactions')
      .set('Authorization', 'Bearer bad-token-payload');
    expect(response.statusCode).toBe(403);
  });

  it('should return 200 OK and valid dataset schemas when given a signed JWT token', async () => {
    const validToken = jwt.sign({ userId: 'test_user' }, JWT_SECRET);
    const response = await request(app)
      .get('/api/transactions')
      .set('Authorization', `Bearer ${validToken}`);
    expect(response.statusCode).toBe(200);
    expect(Array.isArray(response.body)).toBe(true);
    expect(response.body[0].id).toBe('tx_test');
  });
});