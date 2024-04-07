import express, { NextFunction, Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcrypt";
import jwt, { JwtPayload } from "jsonwebtoken";
import * as dotenv from "dotenv";
import { google } from "googleapis";

const app = express();
const PORT = 7000;
const prisma = new PrismaClient();

const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  "http://localhost:7000/auth/google/callback"
);

const scopes = [
  "https://www.googleapis.com/auth/userinfo.email",
  "https://www.googleapis.com/auth/userinfo.profile",
];

const authorizationUrl = oauth2Client.generateAuthUrl({
  access_type: "offline",
  scope: scopes,
  include_granted_scopes: true,
});

app.use(express.json());

interface UserData {
  id: string;
  name: string;
  address: string;
}

interface ValidationRequest extends Request {
  userData: UserData;
}

const accessValidation = (req: Request, res: Response, next: NextFunction) => {
  const validationReq = req as ValidationRequest;
  const { authorization } = validationReq.headers;

  console.log("here: ", authorization);

  if (!authorization) {
    return res.status(401).json({
      message: "Token diperlukan",
    });
  }

  const token = authorization.split(" ")[1];
  const secret = process.env.JWT_SECRET!;

  try {
    const jwtDecode = jwt.verify(token, secret);

    if (typeof jwtDecode !== "string") {
      validationReq.userData = jwtDecode as UserData;
    }
  } catch (error) {
    return res.status(401).json({
      message: "Unauthorized",
    });
  }
  next();
};

// GOOGLE Login
app.get("/auth/google", (req, res) => {
  res.redirect(authorizationUrl);
});

// GOOGLE callback login
app.get("/auth/google/callback", async (req, res) => {
  const { code } = req.query;

  const { tokens } = await oauth2Client.getToken(code as string);

  oauth2Client.setCredentials(tokens);

  const oauth2 = google.oauth2({
    auth: oauth2Client,
    version: 'v2',
  });

  const { data } = await oauth2.userinfo.get();

  if (!data.email || !data.name) {
    return res.json({
      data: data,
    });
  }

  let user = await prisma.users.findUnique({
    where: {
      email: data.email,
    },
  });

  if (!user) {
    user = await prisma.users.create({
      data: {
        name: data.name,
        email: data.email,
        address: "-",
      },
    });
  }

  const payload = {
    id: user?.id,
    name: user?.name,
    address: user?.address,
  };

  const secret = process.env.JWT_SECRET!;

  const expiresIn = 60 * 60 * 1;

  const token = jwt.sign(payload, secret, { expiresIn: expiresIn });

  // return res.redirect(`http://localhost:3000/auth-success?token=${token}`)

  return res.json({
    data: {
      id: user.id,
      name: user.name,
      address: user.address,
    },
    token: token,
  });
});

// REGISTER
app.use("/register", async (req, res) => {
  const { name, email, password, address } = req.body;

  const hashedPasword = await bcrypt.hash(password, 10);
  // const data = {
  //   name: name,
  //   email: email,
  //   password: hashedPasword,
  //   address: address,
  // };

  const result = await prisma.users.create({
    data: {
      name,
      email,
      password: hashedPasword,
      address,
    },
  });
  res.json({
    message: `User Created`,
    data: result,
  });
});

// LOGIN
app.use("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.users.findUnique({
    where: {
      email: email,
    },
  });

  if (!user) {
    return res.status(404).json({
      message: `User not found`,
    });
  }

  if (!user?.password) {
    return res.status(404).json({
      message: `Password not set`,
    });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);

  if (isPasswordValid) {
    const payload = {
      id: user.id,
      email: user.email,
      address: user.address,
    };

    // Secret Token untuk bagian server
    const secret = process.env.JWT_SECRET!;

    // Expire token
    const expiresIn = 60 * 60 * 1;

    const token = jwt.sign(payload, secret, { expiresIn: expiresIn });
    return res.json({
      data: {
        id: user.id,
        email: user.email,
        address: user.address,
      },
      token: token,
    });
  } else {
    return res.status(403).json({
      message: `Wrong password`,
    });
  }
});

// CREATE
app.post("/users", async (req, res, next) => {
  const { name, email, address } = req.body;
  const result = await prisma.users.create({
    data: {
      name: name,
      email: email,
      address: address,
    },
  });
  res.json({
    data: result,
    message: `User Created`,
  });
});

// READ
app.get("/users", accessValidation, async (req, res) => {
  const result = await prisma.users.findMany({
    select: {
      id: true,
      name: true,
      email: true,
      address: true,
    },
  });
  res.json({
    data: result,
    message: `User list`,
  });
});

// UPDATE
app.patch("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { name, email, address } = req.body;

  const result = await prisma.users.update({
    data: {
      name: name,
      email: email,
      address: address,
    },
    where: {
      id: id,
    },
  });
  res.json({
    data: result,
    message: `User ${id} updated`,
  });
});

// DELETE
app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;

  const result = await prisma.users.delete({
    where: {
      id: id,
    },
  });
  res.json({
    // data: result,
    message: `User ${id} deleted`,
  });
});

app.listen(PORT, () => {
  console.log(`Server running in PORT: ${PORT}`);
});
