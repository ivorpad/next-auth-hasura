import Layout from "./layout";
import { useQuery } from "urql";


function Home() {

  const UserQuery = `
    query {
      users {
        name
      }
    }
  `;

  const [user, reexecuteQuery] = useQuery({
    query: UserQuery,
  });

  if(user.fetching) return <p>is fetching...</p>

  const [singleUser] = user.data?.users ?? [{ name: "Not Signed In" }];

  return (
    <Layout>
      <h1>NextAuth.js Example | {singleUser.name}</h1>
      <p>
        This is an example site to demonstrate how to use{" "}
        <a href={`https://next-auth.js.org`}>NextAuth.js</a> for authentication.
      </p>
    </Layout>
  );
}

export default Home;
