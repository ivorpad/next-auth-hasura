import NextAuth from "next-auth";
import Providers from "next-auth/providers";
import add from "date-fns/add";
import jwt from "jsonwebtoken";
import getUnixTime from 'date-fns/getUnixTime'
import Cookies from 'cookies'

function makeId(length) {
  var result = "";
  var characters =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  var charactersLength = characters.length;
  for (var i = 0; i < length; i++) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
  }
  return result;
}

const generateHasuraJwtClaims = (user) => {
  const jwtClaims = {
    id: user.id ? user.id.toString() : undefined,
    sub: user.id ? user.id.toString() : undefined,
    name: user.name,
    image: user.image,
    iat: Math.floor(Date.now() / 1000),
    exp: getUnixTime(add(new Date(), { seconds: 5 })),
    "https://hasura.io/jwt/claims": {
      "x-hasura-allowed-roles": ["user", "manager", "hr"],
      "x-hasura-default-role": "user",
      "x-hasura-role": "user",
      "x-hasura-user-id": user.id ? user.id.toString() : undefined,
    },
  };

  return jwtClaims;
};

const fakeRefreshToken = (token) => {

  const decodedToken = jwt.decode(token);
  const jwtClaims = generateHasuraJwtClaims(decodedToken);
  const refreshToken = makeId(30);

  return {
    ...jwtClaims,
    refreshToken,
  };
};

export default async (req, res) => {

  const cookies = new Cookies(req, res);

  return NextAuth(req, res, {
    // https://next-auth.js.org/configuration/providers
    providers: [
      Providers.GitHub({
        clientId: process.env.GITHUB_ID,
        clientSecret: process.env.GITHUB_SECRET,
      }),
    ],
    // Database optional. MySQL, Maria DB, Postgres and MongoDB are supported.
    // https://next-auth.js.org/configuration/databases
    //
    // Notes:
    // * You must to install an appropriate node_module for your database
    // * The Email provider requires a database (OAuth providers do not)
    database: process.env.DATABASE_URL,

    // The secret should be set to a reasonably long random string.
    // It is used to sign cookies and to sign and encrypt JSON Web Tokens, unless
    // a separate secret is defined explicitly for encrypting the JWT.
    secret: process.env.SECRET,

    session: {
      // Use JSON Web Tokens for session instead of database sessions.
      // This option can be used with or without a database for users/accounts.
      // Note: `jwt` is automatically set to `true` if no database is specified.
      jwt: true,

      // Seconds - How long until an idle session expires and is no longer valid.
      maxAge: process.env.MAX_AGE, // 30 days

      // Seconds - Throttle how frequently to write to database to extend a session.
      // Use it to limit write operations. Set to 0 to always update the database.
      // Note: This option is ignored if using JSON Web Tokens
      // updateAge: 24 * 60 * 60, // 24 hours
    },

    // JSON Web tokens are only used for sessions if the `jwt: true` session
    // option is set - or by default if no database is specified.
    // https://next-auth.js.org/configuration/options#jwt
    jwt: {
      // A secret to use for key generation (you should set this explicitly)
      // secret: 'INp8IvdIyeMcoGAgFGoA61DdBglwwSqnXJZkgz8PSnw',
      // Set to true to use encryption (default: false)
      // encryption: true,
      // You can define your own encode/decode functions for signing and encryption
      // if you want to override the default behaviour.
      encode: async ({ secret, token, maxAge }) => {
        const jwtClaims = generateHasuraJwtClaims(token);
        const encodedToken = jwt.sign(jwtClaims, secret, {
          algorithm: "HS256",
        });

        return Promise.resolve(encodedToken);
      },
      decode: async ({ secret, token, maxAge }) => {
        try {
          const decodedToken = jwt.verify(token, secret, {
            algorithms: ["HS256"],
          });
          return decodedToken;
        } catch (error) {
          const newToken = fakeRefreshToken(token);
          if (newToken) {
            const expires = add(new Date(), {
              days: 15,
            });

            cookies.set("next-auth.refresh-token", newToken.refreshToken, {
              httpOnly: true,
              path: "/",
              expires,
              overwrite: true,
            });

            // delete the returning refresh token because we don't want to expose it in the token
            delete newToken.refreshToken;
            // return the new token
            return newToken;
          }
          return {
            error: "TokenExpiredError",
          };
        }
      },
    },

    // You can define custom pages to override the built-in ones. These will be regular Next.js pages
    // so ensure that they are placed outside of the '/api' folder, e.g. signIn: '/auth/mycustom-signin'
    // The routes shown here are the default URLs that will be used when a custom
    // pages is not specified for that route.
    // https://next-auth.js.org/configuration/pages
    pages: {
      // signIn: '/auth/signin',  // Displays signin buttons
      // signOut: '/auth/signout', // Displays form with sign out button
      // error: '/auth/error', // Error code passed in query string as ?error=
      // verifyRequest: '/auth/verify-request', // Used for check email page
      // newUser: null // If set, new users will be directed here on first sign in
    },

    // Callbacks are asynchronous functions you can use to control what happens
    // when an action is performed.
    // https://next-auth.js.org/configuration/callbacks
    callbacks: {
      // async signIn(user, account, profile) { return true },
      // async redirect(url, baseUrl) { return baseUrl },
      async session(session, token) {
        const encodedToken = jwt.sign(token, process.env.SECRET, {
          algorithm: "HS256",
        });
        if (token) {
          session.user = { name: token.name, image: token.image };
          session.access_token = encodedToken;
        }
        return Promise.resolve(session);
      },
      async jwt(token, user, account, profile, isNewUser) {

        // initial sign in
        if (user) {
          const expires = add(new Date(), { days: 15 });
          cookies.set("next-auth.refresh-token", makeId(30), {
            httpOnly: true,
            path: "/",
            expires,
            overwrite: true,
          });

          return {
            name: user.name,
            id: user.id,
            image: user.image,
          };
        }

        return token;
      },
    },

    // Events are useful for logging
    // https://next-auth.js.org/configuration/events
    events: {},

    // Enable debug messages in the console if you are having problems
    debug: false,
  });
}


