import { analyzeFile } from "@/lib/scanner";

describe("GraphQL introspection/IDE enabled (found via real-world Damn Vulnerable GraphQL App testing)", () => {
  it("flags a Flask/graphene view registered with graphiql=True", () => {
    const content = `
from flask_graphql import GraphQLView

app.add_url_rule('/graphiql', view_func=GraphQLView.as_view(
  'graphiql',
  schema=schema,
  graphiql = True,
  context={'session': db.session}
))
`;
    const result = analyzeFile("core/views.py", content);
    const finding = result.indicators.find(i => i.id === "graphql-introspection-enabled");
    expect(finding).toBeDefined();
    expect(finding?.severity).toBe("medium");
  });

  it("flags Apollo Server configured with introspection explicitly enabled", () => {
    const content = `
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: true,
  playground: true,
});
`;
    const result = analyzeFile("src/server.ts", content);
    expect(result.indicators.some(i => i.id === "graphql-introspection-enabled")).toBe(true);
  });

  it("does not flag a GraphQL server with introspection disabled", () => {
    const content = `
const server = new ApolloServer({
  typeDefs,
  resolvers,
  introspection: false,
});
`;
    const result = analyzeFile("src/server.ts", content);
    expect(result.indicators.some(i => i.id === "graphql-introspection-enabled")).toBe(false);
  });
});
