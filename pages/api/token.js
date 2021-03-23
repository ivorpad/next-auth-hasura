// This is an example of how to read a JSON Web Token from an API route
import { getToken } from "next-auth/jwt";

const secret = process.env.SECRET;

export default async (req, res) => {
  console.log(req.cookies)
  const token = await getToken({ req, secret, encryption: true, raw: true });
  console.log({ token });
  if (token) {
    
    // Signed in
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify({ token }));
  } else {
    // Not Signed in
    res.status(401);
  }
  res.end();
};

