const { getToken } = require("next-auth/jwt");
const { NextAuthHandler } = require("next-auth");
import jwt from "jsonwebtoken";
import Cookies from 'cookies';

const generateNewJtwPayload = (token) => {

}

const generateNewSession = async (session, jwtPayload) => {
  const encodedToken = jwt.sign(token, process.env.SECRET, {
    algorithm: "HS256",
  });
  if (token) {
    session.user = { name: token.name, image: token.image };
    session.access_token = encodedToken;
  }
  return Promise.resolve(session);
}

async function getSession(req, res) {
  const cookies = new Cookies(req, res);
  const sessionCookie = cookies.get("next-auth.session-token");

  if(!sessionCookie) {
    return { session: null };
  }

  const decodedJwt = jwt.decode(sessionCookie);

  const payload = await generateNewJtwPayload(decodedJwt);

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

  const sessionPayload = await callbacks.session(
    defaultSessionPayload,
    jwtPayload
  );



  return { session: defaultSessionPayload };
}

export default getSession

