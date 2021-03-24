const { getToken } = require("next-auth/jwt");
const { NextAuthHandler } = require("next-auth");
import jwt from "jsonwebtoken";
import Cookies from 'cookies';

function getSession(req, res) {
  const cookies = new Cookies(req, res);
  const sessionCookie = cookies.get("next-auth.session-token");

  if(!sessionCookie) {
    return { session: null };
  }

  const decodedJwt = jwt.decode(sessionCookie);

  const sessionExpiresDate = new Date();
  sessionExpiresDate.setTime(sessionExpiresDate.getTime() + process.env.MAX_AGE * 1000);
  const sessionExpires = sessionExpiresDate.toISOString();

  const defaultSessionPayload = {
    user: {
      name: decodedJwt.name || null,
      email: decodedJwt.email || null,
      image: decodedJwt.image || null,
    },
    expires: sessionExpires,
  };

  return { session: defaultSessionPayload };
}

export default getSession

