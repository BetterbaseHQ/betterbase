import { collection, t } from "../src/index.js";

export interface User {
  name: string;
  email: string;
  age: number;
}

export function generateUsers(count: number): User[] {
  return Array.from({ length: count }, (_, i) => ({
    name: `user${i}`,
    email: `user${i}@example.com`,
    age: 20 + (i % 50),
  }));
}

/** Collection definition used by both bench files and the bench worker. */
export function buildBenchCollection() {
  return collection("users")
    .v(1, {
      name: t.string(),
      email: t.string(),
      age: t.number(),
    })
    .index(["name"])
    .index(["age"])
    .build();
}

export type BenchUsersCollection = ReturnType<typeof buildBenchCollection>;
