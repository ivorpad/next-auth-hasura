import { useState, useEffect } from "react";
import Home from '../components/home'
import { createClient, Provider } from "urql";
import { useSession, getSession } from "next-auth/client";

const UrqlProvider = ({ children, session }) => {

  const client = createClient({
    url: process.env.NEXT_PUBLIC_HASURA_GRAPHQL_ENDPOINT,
    fetchOptions: () => {
      return {
        headers: {
          authorization: session?.access_token
            ? `Bearer ${session.access_token}`
            : "",
        },
      };
    },
  });

  return <Provider value={client}>{children}</Provider>;
};

export default function Page({ session }) {
  return (
    <UrqlProvider session={session}>
      <Home />
    </UrqlProvider>
  );
}


// Export the `session` prop to use sessions with Server Side Rendering
export async function getServerSideProps(context) {

  const session = await getSession(context)

  return {
    props: { session },
  };
}
