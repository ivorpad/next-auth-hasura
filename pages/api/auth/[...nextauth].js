import NextAuth from "next-auth";
import Providers from "next-auth/providers";
import add from "date-fns/add";
import jwt from "jsonwebtoken";
import getUnixTime from "date-fns/getUnixTime";
import Cookies from "cookies";
import { gql, GraphQLClient } from "graphql-request";
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

  const client = new GraphQLClient(process.env.HASURA_GRAPHQL_ENDPOINT);

  const requestHeaders = {
    "x-hasura-use-backend-only-permissions": true,
    "x-hasura-admin-secret": process.env.HASURA_ADMIN_SECRET,
  };

  return NextAuth(req, res, {
    // https://next-auth.js.org/configuration/providers
    providers: [
      Providers.GitHub({
        clientId: process.env.GITHUB_ID,
        clientSecret: process.env.GITHUB_SECRET,
      }),
    ],
    database: process.env.DATABASE_URL,
    secret: process.env.SECRET,
    session: {
      jwt: true,
      maxAge: process.env.MAX_AGE, // 30 days
    },
    jwt: {
      encode: async ({ secret, token, maxAge }) => {
        let encodedToken, jwtClaims;

        // Save the next token in a new variable
        const nextRefreshToken = token.refreshToken;

        // Delete from the access token to avoid storing it again
        delete token.refreshToken;

        // Generate our JWT claims
        jwtClaims = generateHasuraJwtClaims(token);

        // Encode the JTW 
        encodedToken = jwt.sign(jwtClaims, secret, {
          algorithm: "HS256",
        });


        // We store prev and next refreshTokens for better readability
        const refreshToken = {
          prev: cookies.get("next-auth.refresh-token"),
          next: nextRefreshToken,
        };

        if (!refreshToken.next) {
          const InsertAccessToken = gql`
            mutation InsertAccessToken(
              $refresh_token: String = ""
              $access_token: String = ""
            ) {
              update_sessions(
                where: { refresh_token: { _eq: $refresh_token } }
                _set: {
                  access_token: $access_token
                }
              ) {
                returning {
                  access_token
                }
              }
            }
          `;

          const data = await client.request(
            InsertAccessToken,
            {
              refresh_token: refreshToken.prev,
              access_token: encodedToken,
            },
            requestHeaders
          );
        } else {
          const UpdateSession = gql`
            mutation UpdateSession(
              $old_refresh_token: String = ""
              $refresh_token: String = ""
              $access_token: String = ""
            ) {
              update_sessions(
                where: { refresh_token: { _eq: $old_refresh_token } }
                _set: {
                  access_token: $access_token
                  refresh_token: $refresh_token
                }
              ) {
                returning {
                  refresh_token
                  access_token
                }
              }
            }
          `;

          const data = await client.request(
            UpdateSession,
            {
              old_refresh_token: refreshToken.prev,
              refresh_token: refreshToken.next,
              access_token: encodedToken,
            },
            requestHeaders
          );
        }


          return Promise.resolve(encodedToken);
      },
      decode: async ({ secret, token, maxAge }) => {
        try {
          // Verify the current token, if it fails it means it expired and then we need to refresh
          const decodedToken = jwt.verify(token, secret, {
            algorithms: ["HS256"],
          });
          return decodedToken;
        } catch (error) {
          // Token expired let's do an access token rotation
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
            // delete newToken.refreshToken;
            // return the new token
            return newToken;
          }
          return {
            error: "TokenExpiredError",
          };
        }
      },
    },

    pages: {},

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
          const refresh_token = makeId(30);

          let email;
          if (account.provider === "github") {
            const emailRes = await fetch("https://api.github.com/user/emails", {
              headers: {
                Authorization: `token ${account.accessToken}`,
              },
            });
            const emails = await emailRes.json();
            const githubEmail = emails.find((e) => e.primary).email;
            email = githubEmail;
          } else {
            email = user.email;
          }

         const variables = {
           object: {
             name: user.name,
             email: email,
             sessions: {
               data: {
                 refresh_token: refresh_token,
                 expires,
               },
             },
           },
         };

          const InsertUser = gql`
            mutation InsertUser($object: users_insert_input!) {
              insert_users_one(
                object: $object
                on_conflict: {
                  constraint: users_email_key
                  update_columns: [updated_at, name]
                }
              ) {
                id
                sessions {
                  refresh_token
                }
              }
            }
          `;

          const data = await client.request(
            InsertUser,
            variables,
            requestHeaders
          );

          if (data) {
            cookies.set(
              "next-auth.refresh-token",
              data.insert_users_one.sessions[0].refresh_token,
              {
                httpOnly: true,
                path: "/",
                expires,
                overwrite: true,
              }
            );

            return {
              name: user.name,
              id: data.insert_users_one.id,
              image: user.image,
            };
          }
        }

        token.refresh_token = makeId(30);
        return token;
      },
    },

    // Events are useful for logging
    // https://next-auth.js.org/configuration/events
    events: {
      signOut(message) {
        cookies.set("next-auth.refresh-token", "", {
          maxAge: 0
        });
      }
    },

    // Enable debug messages in the console if you are having problems
    debug: false,
  });
};
