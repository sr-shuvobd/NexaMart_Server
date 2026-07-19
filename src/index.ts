import express, { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import mongoose, { Schema, Document, Model } from "mongoose";
import * as dotenv from "dotenv";

dotenv.config();

// ════════════════════════════════════════════════════════
//  MongoDB Connection
// ════════════════════════════════════════════════════════

const MONGODB_URI = process.env.MONGODB_URI!;

async function connectDB() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log("✅ MongoDB connected successfully");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    process.exit(1);
  }
}

// ════════════════════════════════════════════════════════
//  Mongoose Models
// ════════════════════════════════════════════════════════

// ── Product ──
interface IProduct extends Document {
  name: string;
  price: number;
  originalPrice?: number;
  description: string;
  category: string;
  image: string;
  badge?: string;
  rating: number;
  reviews: number;
  stock: number;
  status: string;
  sellerId: string;
  createdAt: Date;
  updatedAt: Date;
}

const ProductSchema = new Schema<IProduct>(
  {
    name: { type: String, required: true },
    price: { type: Number, required: true },
    originalPrice: { type: Number },
    description: { type: String, default: "" },
    category: { type: String, required: true },
    image: { type: String, required: true },
    badge: { type: String },
    rating: { type: Number, default: 0 },
    reviews: { type: Number, default: 0 },
    stock: { type: Number, default: 0 },
    status: { type: String, default: "Active" },
    sellerId: { type: String, required: true },
  },
  { timestamps: true }
);

const Product: Model<IProduct> =
  mongoose.models.Product || mongoose.model<IProduct>("Product", ProductSchema);

// ── User (Better-Auth sync) ──
interface IUser extends Document {
  name: string;
  email: string;
  role: string;
  status: string;
  addresses?: {
    id: string;
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
    isDefault: boolean;
  }[];
  createdAt: Date;
  updatedAt: Date;
}

const AddressSchema = new Schema({
  id: { type: String, required: true },
  street: { type: String, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  zipCode: { type: String, required: true },
  country: { type: String, required: true },
  isDefault: { type: Boolean, default: false }
});

const UserSchema = new Schema<IUser>(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    role: { type: String, default: "user" },
    status: { type: String, default: "Active" },
    addresses: [AddressSchema],
  },
  { timestamps: true, strict: false } // Strict false because better-auth adds its own fields
);

const User: Model<IUser> =
  mongoose.models.user || mongoose.model<IUser>("user", UserSchema, "user");

// ── Settings ──
interface ISettings extends Document {
  storeName: string;
  storeEmail: string;
  currency: string;
}

const SettingsSchema = new Schema<ISettings>({
  storeName: { type: String, default: "NexaMart BD" },
  storeEmail: { type: String, default: "support@nexamart.com" },
  currency: { type: String, default: "USD" },
});

const Settings: Model<ISettings> = mongoose.models.Settings || mongoose.model<ISettings>("Settings", SettingsSchema);

// ── Order ──
interface IOrderItem {
  productId: string;
  name: string;
  price: number;
  quantity: number;
  image: string;
}

interface IOrder extends Document {
  orderNumber: string;
  customerId: string;
  customerName: string;
  customerEmail: string;
  items: IOrderItem[];
  totalAmount: number;
  status: string;
  shippingAddress: {
    street: string;
    city: string;
    state: string;
    zipCode: string;
    country: string;
  };
  paymentMethod: string;
  createdAt: Date;
  updatedAt: Date;
}

const OrderItemSchema = new Schema<IOrderItem>({
  productId: { type: String, required: true },
  name: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, required: true, min: 1 },
  image: { type: String },
});

const OrderSchema = new Schema<IOrder>(
  {
    orderNumber: { type: String, required: true, unique: true },
    customerId: { type: String, required: true },
    customerName: { type: String, default: "" },
    customerEmail: { type: String, default: "" },
    items: [OrderItemSchema],
    totalAmount: { type: Number, required: true },
    status: { type: String, default: "Pending" },
    shippingAddress: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      country: String,
    },
    paymentMethod: { type: String, default: "COD" },
  },
  { timestamps: true }
);

const Order: Model<IOrder> =
  mongoose.models.Order || mongoose.model<IOrder>("Order", OrderSchema);

// ── Message (Contact) ──
interface IMessage extends Document {
  name: string;
  email: string;
  subject: string;
  message: string;
  read: boolean;
  createdAt: Date;
}

const MessageSchema = new Schema<IMessage>({
  name: { type: String, required: true },
  email: { type: String, required: true },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false },
}, { timestamps: true });

const Message: Model<IMessage> = mongoose.models.Message || mongoose.model<IMessage>("Message", MessageSchema);

// ════════════════════════════════════════════════════════
//  Express App Setup
// ════════════════════════════════════════════════════════

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: ["http://localhost:3000", "http://localhost:3001", process.env.CLIENT_URL || ""],
    credentials: true,
  })
);
app.use(helmet());
app.use(morgan("dev"));
app.use(express.json());

// ════════════════════════════════════════════════════════
//  Authentication Middleware
// ════════════════════════════════════════════════════════

const requireAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  const secret = process.env.JWT_SECRET || process.env.BETTER_AUTH_SECRET || "fallback_secret";

  try {
    const decoded = jwt.verify(token, secret);
    (req as any).user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, error: "Unauthorized: Invalid token" });
  }
};

const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
  requireAuth(req, res, () => {
    if ((req as any).user.role === "admin") {
      next();
    } else {
      res.status(403).json({ success: false, error: "Forbidden: Admin access required" });
    }
  });
};

const requireSeller = (req: Request, res: Response, next: NextFunction) => {
  requireAuth(req, res, () => {
    if ((req as any).user.role === "seller" || (req as any).user.role === "admin") {
      next();
    } else {
      res.status(403).json({ success: false, error: "Forbidden: Seller access required" });
    }
  });
};

// ════════════════════════════════════════════════════════
//  Health Check
// ════════════════════════════════════════════════════════

app.get("/", (_req: Request, res: Response) => {
  res.json({
    message: "🚀 NexaMart API is running",
    status: "ok",
    timestamp: new Date().toISOString(),
  });
});

// ════════════════════════════════════════════════════════
//  Product Routes
// ════════════════════════════════════════════════════════

// GET  /api/products         → All products (public)
// GET  /api/products/:id     → Single product
// GET  /api/products/seller/:sellerId → Seller's products
// POST /api/products         → Create product
// PUT  /api/products/:id     → Update product
// DELETE /api/products/:id   → Delete product

app.get("/api/products", async (_req: Request, res: Response) => {
  try {
    const { category, search, sort, limit } = _req.query;
    const filter: any = {};

    if (category && category !== "all") {
      filter.category = category;
    }
    if (search) {
      filter.name = { $regex: search, $options: "i" };
    }

    let query = Product.find(filter);

    if (sort === "price_low") query = query.sort({ price: 1 });
    else if (sort === "price_high") query = query.sort({ price: -1 });
    else if (sort === "newest") query = query.sort({ createdAt: -1 });
    else query = query.sort({ reviews: -1 }); // popular

    if (limit) query = query.limit(Number(limit));

    const products = await query;
    res.json({ success: true, products });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/products/seller/:sellerId", async (req: Request, res: Response) => {
  try {
    const products = await Product.find({ sellerId: req.params.sellerId }).sort({
      createdAt: -1,
    });
    res.json({ success: true, products });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/products/:id", async (req: Request, res: Response) => {
  try {
    const product = await Product.findById(req.params.id);
    if (!product) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }
    res.json({ success: true, product });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/products", requireSeller, async (req: Request, res: Response) => {
  try {
    const { name, price, originalPrice, description, category, image, badge, stock, sellerId } =
      req.body;

    if (!name || price === undefined || price === null || !category || !image || !sellerId) {
      return res.status(400).json({ success: false, error: "Missing required fields" });
    }

    const product = new Product({
      name,
      price,
      originalPrice,
      description,
      category,
      image,
      badge,
      stock: stock || 0,
      sellerId,
    });

    const saved = await product.save();
    res.status(201).json({ success: true, product: saved });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/products/:id", requireSeller, async (req: Request, res: Response) => {
  try {
    const updated = await Product.findByIdAndUpdate(req.params.id, req.body, {
      new: true,
    });
    if (!updated) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }
    res.json({ success: true, product: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete("/api/products/:id", requireSeller, async (req: Request, res: Response) => {
  try {
    const deleted = await Product.findByIdAndDelete(req.params.id);
    if (!deleted) {
      return res.status(404).json({ success: false, error: "Product not found" });
    }
    res.json({ success: true, message: "Product deleted" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  User Routes (Admin)
// ════════════════════════════════════════════════════════

app.get("/api/users", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    res.json({ success: true, users });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/users/:id", requireAuth, async (req: Request, res: Response) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: "User not found" });
    res.json({ success: true, user });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/users/:id/role", requireAdmin, async (req: Request, res: Response) => {
  try {
    const userToUpdate = await User.findById(req.params.id);
    if (userToUpdate && userToUpdate.email === "srs@gmail.com") {
      return res.status(403).json({ success: false, error: "Cannot change role of permanent admin" });
    }

    const { role } = req.body;
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { role },
      { new: true }
    );
    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/users/:id/status", requireAdmin, async (req: Request, res: Response) => {
  try {
    const userToUpdate = await User.findById(req.params.id);
    if (userToUpdate && userToUpdate.email === "srs@gmail.com") {
      return res.status(403).json({ success: false, error: "Cannot change status of permanent admin" });
    }

    const { status } = req.body;
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/users/:id/addresses", requireAuth, async (req: Request, res: Response) => {
  try {
    const { addresses } = req.body;
    const updated = await User.findByIdAndUpdate(
      req.params.id,
      { addresses },
      { new: true }
    );
    res.json({ success: true, user: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Order Routes
// ════════════════════════════════════════════════════════

// GET  /api/orders              → All orders (admin)
// GET  /api/orders/user/:userId → User's orders
// GET  /api/orders/seller/:sellerId → Orders containing seller's products
// POST /api/orders              → Place an order
// PUT  /api/orders/:id/status   → Update order status

app.get("/api/orders", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const orders = await Order.find({}).sort({ createdAt: -1 });
    res.json({ success: true, orders });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/orders/user/:userId", requireAuth, async (req: Request, res: Response) => {
  try {
    const orders = await Order.find({ customerId: req.params.userId }).sort({
      createdAt: -1,
    });
    res.json({ success: true, orders });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/orders/seller/:sellerId", requireSeller, async (req: Request, res: Response) => {
  try {
    // Find all products by this seller, then find orders containing those product IDs
    const sellerProducts = await Product.find({ sellerId: req.params.sellerId }).select("_id");
    const productIds = sellerProducts.map((p) => p._id.toString());

    const orders = await Order.find({
      "items.productId": { $in: productIds },
    }).sort({ createdAt: -1 });

    res.json({ success: true, orders });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.post("/api/orders", requireAuth, async (req: Request, res: Response) => {
  try {
    const { customerId, customerName, customerEmail, items, totalAmount, shippingAddress, paymentMethod } =
      req.body;

    if (!customerId || !items || items.length === 0) {
      return res
        .status(400)
        .json({ success: false, error: "Customer ID and items are required" });
    }

    const orderNumber = `NM-${Date.now()}-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

    const order = new Order({
      orderNumber,
      customerId,
      customerName,
      customerEmail,
      items,
      totalAmount,
      shippingAddress,
      paymentMethod,
    });

    const saved = await order.save();
    res.status(201).json({ success: true, order: saved });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/orders/:id/status", requireSeller, async (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    const updated = await Order.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    if (!updated) {
      return res.status(404).json({ success: false, error: "Order not found" });
    }
    res.json({ success: true, order: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Dashboard Stats (Admin)
// ════════════════════════════════════════════════════════

app.get("/api/stats/admin", requireAdmin, async (_req: Request, res: Response) => {
  try {
    const totalProducts = await Product.countDocuments();
    const totalOrders = await Order.countDocuments();
    const completedOrders = await Order.countDocuments({ status: "Completed" });
    const pendingOrders = await Order.countDocuments({ status: "Pending" });

    const revenueResult = await Order.aggregate([
      { $match: { status: { $in: ["Completed", "Processing"] } } },
      { $group: { _id: null, total: { $sum: "$totalAmount" } } },
    ]);
    const totalRevenue = revenueResult.length > 0 ? revenueResult[0].total : 0;

    const recentOrders = await Order.find({}).sort({ createdAt: -1 }).limit(5);

    res.json({
      success: true,
      stats: {
        totalProducts,
        totalOrders,
        completedOrders,
        pendingOrders,
        totalRevenue,
      },
      recentOrders,
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Dashboard Stats (Seller)
// ════════════════════════════════════════════════════════

app.get("/api/stats/seller/:sellerId", requireSeller, async (req: Request, res: Response) => {
  try {
    const sellerId = req.params.sellerId;
    const totalProducts = await Product.countDocuments({ sellerId });
    const activeProducts = await Product.countDocuments({ sellerId, status: "Active" });

    // Get orders that contain this seller's products
    const sellerProducts = await Product.find({ sellerId }).select("_id");
    const productIds = sellerProducts.map((p) => p._id.toString());

    const orders = await Order.find({ "items.productId": { $in: productIds } });
    const totalOrders = orders.length;

    let totalRevenue = 0;
    orders.forEach((order) => {
      order.items.forEach((item) => {
        if (productIds.includes(item.productId)) {
          totalRevenue += item.price * item.quantity;
        }
      });
    });

    res.json({
      success: true,
      stats: {
        totalProducts,
        activeProducts,
        totalOrders,
        totalRevenue,
      },
    });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Message Routes
// ════════════════════════════════════════════════════════

app.post("/api/messages", async (req: Request, res: Response) => {
  try {
    const newMessage = new Message(req.body);
    await newMessage.save();
    res.status(201).json({ success: true, message: "Message sent successfully" });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/api/messages", requireAdmin, async (req: Request, res: Response) => {
  try {
    const messages = await Message.find({}).sort({ createdAt: -1 });
    res.json({ success: true, messages });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/messages/:id/read", requireAdmin, async (req: Request, res: Response) => {
  try {
    const updated = await Message.findByIdAndUpdate(req.params.id, { read: true }, { new: true });
    res.json({ success: true, message: updated });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.delete("/api/messages/:id", requireAdmin, async (req: Request, res: Response) => {
  try {
    await Message.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Settings Routes
// ════════════════════════════════════════════════════════

app.get("/api/settings", async (_req: Request, res: Response) => {
  try {
    let settings = await Settings.findOne();
    if (!settings) {
      settings = await Settings.create({});
    }
    res.json({ success: true, settings });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

app.put("/api/settings", requireAdmin, async (req: Request, res: Response) => {
  try {
    const { storeName, storeEmail, currency } = req.body;
    let settings = await Settings.findOne();
    if (settings) {
      settings.storeName = storeName || settings.storeName;
      settings.storeEmail = storeEmail || settings.storeEmail;
      settings.currency = currency || settings.currency;
      await settings.save();
    } else {
      settings = await Settings.create({ storeName, storeEmail, currency });
    }
    res.json({ success: true, settings });
  } catch (error: any) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ════════════════════════════════════════════════════════
//  Start Server
// ════════════════════════════════════════════════════════

connectDB().then(() => {
  if (process.env.NODE_ENV !== "production" && !process.env.VERCEL) {
    app.listen(PORT, () => {
      console.log(`🚀 NexaMart Server running on http://localhost:${PORT}`);
    });
  }
});

export default app;
