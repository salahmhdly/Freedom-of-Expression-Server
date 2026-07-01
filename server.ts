import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import { CloudinaryStorage } from 'multer-storage-cloudinary';
import { PrismaClient } from '@prisma/client';
import { OAuth2Client } from 'google-auth-library';

dotenv.config();

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. إعدادات الأمان والـ Middleware
// ==========================================
app.use(helmet());
app.use(cors());
app.use(express.json());

// ==========================================
// 2. إعدادات Cloudinary و Multer (لرفع الوسائط)
// ==========================================
if (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET) {
  cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
  });
}
// إذا لم يتم توفير المتغيرات الفردية، ستقوم مكتبة cloudinary تلقائياً
// بقراءة المتغير CLOUDINARY_URL إذا كان موجوداً في البيئة (environment)

const storage = new CloudinaryStorage({
  cloudinary: cloudinary,
  params: {
    folder: 'social_app',
    allowed_formats: ['jpg', 'png', 'jpeg', 'mp4'],
  } as any,
});
const upload = multer({ storage });

// ==========================================
// Middleware للمصادقة (JWT)
// ==========================================
const authenticate = (req: any, res: Response, next: NextFunction) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret');
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ==========================================
// 3. المصادقة (Authentication)
// ==========================================

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// تسجيل الدخول بواسطة جوجل (Google Auth)
app.post('/api/auth/google', async (req: Request, res: Response) => {
  try {
    const { token } = req.body;
    
    // التحقق من صحة التوكن المرسل من الواجهة الأمامية
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    if (!payload) return res.status(401).json({ error: 'Invalid Google token' });

    const { sub: googleId, email, name: username, picture: avatar } = payload;
    if (!email) return res.status(400).json({ error: 'Email not provided by Google' });

    // البحث عن المستخدم أو إنشائه
    let user = await prisma.user.findUnique({ where: { email } });
    
    if (!user) {
      user = await prisma.user.create({
        data: {
          email,
          username: username || 'User',
          googleId,
          avatar,
        },
      });
    } else if (!user.googleId) {
      // ربط حساب جوجل بحساب موجود مسبقاً بنفس الإيميل
      user = await prisma.user.update({
        where: { email },
        data: { googleId, avatar },
      });
    }
    
    const jwtToken = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ user, token: jwtToken });
  } catch (error: any) {
    console.error('❌ Google login error details:', error.stack || error.message || error);
    res.status(500).json({ error: 'Google login failed', details: error.message });
  }
});

// تسجيل حساب جديد
app.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const user = await prisma.user.create({
      data: { username, email, password: hashedPassword },
    });
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.status(201).json({ user, token });
  } catch (error) {
    res.status(400).json({ error: 'User registration failed' });
  }
});

// تسجيل الدخول
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    const user = await prisma.user.findUnique({ where: { email } });
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET || 'secret', { expiresIn: '7d' });
    res.json({ user, token });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

// ==========================================
// 4. خوارزمية عرض المنشورات (Feed Algorithm)
// ==========================================
app.get('/api/feed', authenticate, async (req: any, res: Response) => {
  try {
    const userId = req.user.userId;
    const limit = parseInt(req.query.limit as string) || 10;
    const cursor = req.query.cursor as string; // نستخدم cursor بدلاً من page لتجنب تكرار المنشورات

    // جلب قائمة المستخدمين الذين يتابعهم المستخدم الحالي
    const following = await prisma.follow.findMany({
      where: { followerId: userId },
      select: { followingId: true },
    });
    const followingIds = following.map((f) => f.followingId);

    // تجهيز خيارات الاستعلام
    const queryOptions: any = {
      where: {
        OR: [
          { authorId: { in: followingIds } }, // منشورات المتابَعين
          {
            // منشورات مقترحة (ليست للمستخدم نفسه وليست لمن يتابعهم)
            authorId: { notIn: [...followingIds, userId] },
            // يمكننا تحديد شرط بأن يكون المنشور لديه عدد إعجابات معين ليكون "شائعاً"
            likes: { some: {} } // كمثال، منشورات حصلت على تفاعل
          }
        ],
      },
      include: {
        author: { select: { id: true, username: true, avatar: true } },
        hashtags: true,
        _count: { select: { likes: true, comments: true, reposts: true } },
      },
      orderBy: [
        { createdAt: 'desc' }, // ترتيب زمني
      ],
      take: limit + 1, // جلب عنصر إضافي لمعرفة ما إذا كانت هناك صفحة تالية
    };

    // إذا كان هناك cursor (وهو ID آخر منشور شاهده المستخدم)، نبدأ من بعده
    if (cursor) {
      queryOptions.cursor = { id: cursor };
      queryOptions.skip = 1; // تخطي المنشور الذي يمثل الـ cursor نفسه
    }

    const feed = await prisma.post.findMany(queryOptions);

    let nextCursor = null;
    if (feed.length > limit) {
      const nextItem = feed.pop(); // إزالة العنصر الإضافي
      nextCursor = nextItem?.id; // تعيين المؤشر للصفحة القادمة
    }

    res.json({ data: feed, nextCursor });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch feed' });
  }
});

// ==========================================
// 5. رفع الوسائط وإنشاء منشور (Media Upload)
// ==========================================
app.post('/api/posts', authenticate, upload.single('media'), async (req: any, res: Response) => {
  try {
    const { content } = req.body;
    const mediaUrl = req.file?.path; // رابط الملف المرفوع من Cloudinary
    
    // استخراج الهاشتاكات من النص
    const hashtags = content ? (content.match(/#\w+/g) || []).map((tag: string) => tag.toLowerCase()) : [];
    
    const post = await prisma.post.create({
      data: {
        content,
        mediaUrl,
        authorId: req.user.userId,
        hashtags: {
          connectOrCreate: hashtags.map((tag: string) => ({
            where: { name: tag },
            create: { name: tag },
          })),
        }
      },
      include: { hashtags: true }
    });
    
    res.status(201).json(post);
  } catch (error) {
    res.status(500).json({ error: 'Failed to create post' });
  }
});

// ==========================================
// 6. التفاعلات (Likes, Comments, Reposts)
// ==========================================

// إضافة إعجاب
app.post('/api/posts/:postId/like', authenticate, async (req: any, res: Response) => {
  try {
    const { postId } = req.params;
    const userId = req.user.userId;
    
    const like = await prisma.like.create({
      data: { postId, userId },
    });
    res.status(201).json(like);
  } catch (error) {
    res.status(400).json({ error: 'Already liked or failed' });
  }
});

// إضافة تعليق أو رد على تعليق
app.post('/api/posts/:postId/comment', authenticate, async (req: any, res: Response) => {
  try {
    const { postId } = req.params;
    const { content, parentId } = req.body;
    const userId = req.user.userId;
    
    const comment = await prisma.comment.create({
      data: { 
        content, 
        postId, 
        authorId: userId,
        parentId: parentId || null
      },
    });
    res.status(201).json(comment);
  } catch (error) {
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

// إعادة نشر (Repost)
app.post('/api/posts/:postId/repost', authenticate, async (req: any, res: Response) => {
  try {
    const { postId } = req.params;
    const userId = req.user.userId;
    
    const repost = await prisma.repost.create({
      data: { postId, userId },
    });
    res.status(201).json(repost);
  } catch (error) {
    res.status(400).json({ error: 'Already reposted or failed' });
  }
});

// متابعة مستخدم (Follow)
app.post('/api/users/:userId/follow', authenticate, async (req: any, res: Response) => {
  try {
    const followingId = req.params.userId;
    const followerId = req.user.userId;
    
    if (followerId === followingId) {
      return res.status(400).json({ error: 'Cannot follow yourself' });
    }
    
    const follow = await prisma.follow.create({
      data: { followerId, followingId },
    });
    res.status(201).json(follow);
  } catch (error) {
    res.status(400).json({ error: 'Already following or failed' });
  }
});

// مسار اختبار للتأكد من عمل الخادم
app.get('/', (req: Request, res: Response) => {
  res.send('Social Media API is running!');
});

// ==========================================
// 7. تشغيل الخادم
// ==========================================
async function startServer() {
  try {
    // محاولة الاتصال بقاعدة البيانات للتحقق من عملها
    await prisma.$connect();
    console.log('✅ Successfully connected to MongoDB via Prisma!');
    
    // محاولة التحقق من اتصال Cloudinary
    try {
      if (process.env.CLOUDINARY_URL || (process.env.CLOUDINARY_CLOUD_NAME && process.env.CLOUDINARY_API_KEY && process.env.CLOUDINARY_API_SECRET)) {
        await cloudinary.api.ping();
        console.log('✅ Successfully connected to Cloudinary!');
      } else {
        console.warn('⚠️ Cloudinary configuration variables are missing. Media uploads might not work.');
      }
    } catch (cloudinaryError: any) {
      console.error('❌ Failed to connect to Cloudinary:', cloudinaryError.message || cloudinaryError);
    }

    app.listen(PORT, () => {
      console.log(`🚀 Server is running on port ${PORT}`);
    });
  } catch (error) {
    console.error('❌ Failed to connect to the database:', error);
    process.exit(1);
  }
}

startServer();
