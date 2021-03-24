import { useSession } from "next-auth/client";
import Layout from "../components/layout";
import jwt from "jsonwebtoken";
import getSession from '../utils/getSession'
export default function Page({ session }) {

  const [sess] = useSession()

  console.log({sess, session})

  return (
    <Layout>
      <h1>
        Server Side Rendering |{" "}
        {session?.user ? session.user.name : "Not Signed In"}
      </h1>
      <p>
        This page uses the universal <strong>getSession()</strong> method in{" "}
        <strong>getServerSideProps()</strong>.
      </p>
      <p>
        Using <strong>getSession()</strong> in{" "}
        <strong>getServerSideProps()</strong> is the recommended approach if you
        need to support Server Side Rendering with authentication.
      </p>
      <p>
        The advantage of Server Side Rendering is this page does not require
        client side JavaScript.
      </p>
      <p>
        The disadvantage of Server Side Rendering is that this page is slower to
        render.
      </p>
    </Layout>
  );
}

// Export the `session` prop to use sessions with Server Side Rendering
export async function getServerSideProps({ req, res }) {

  const { session } = getSession(req, res);
  
  return {
    props: { session },
  };
}
