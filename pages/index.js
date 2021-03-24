import Home from '../components/home'
import { createClient, Provider } from "urql";
import { useSession } from "next-auth/client";

const UrqlProvider = ({children}) => {
  const [session, loading] = useSession();

  if(process.browser) {
    console.log(session);
  }

  const client = createClient({
    url: process.env.NEXT_PUBLIC_HASURA_GRAPHQL_ENDPOINT,
    fetchOptions: () => {
      return {
        headers: {
          authorization: session?.access_token ? `Bearer ${session.access_token}` : "",
        },
      };
    },
  });

  return <Provider value={client}>{children}</Provider>;
}

export default function Page () {
  return (
    <UrqlProvider>
      <Home />
    </UrqlProvider>
  );
}