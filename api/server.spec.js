const server = require("./server");
const supertest = require("supertest");
const db = require("../database/dbConfig");

const credentials = {
  username: "admin",
  password: "admin",
};
const createUser = async (credentials) => {
  return await supertest(server).post("/api/auth/register").send(credentials);
};

describe("/POST /api/auth", () => {
  beforeEach(async () => {
    await db("users").truncate();
  });

  it("It should return status code of 201", () => {
    return supertest(server)
      .post("/api/auth/register")
      .send(credentials)
      .then((res) => {
        expect(res.status).toBe(201);
      });
  });

  it("It should return a token", () => {
    return supertest(server)
      .post("/api/auth/register")
      .send(credentials)
      .then((res) => {
        expect(res.body.token).toBeTruthy();
      });
  });
});

describe("/POST /api/login", () => {
  beforeEach(async () => {
    await db("users").truncate();
  });

  it("Should return a success message", async () => {
    const successMessage = "successfully logged in";
    await createUser(credentials);

    const res = await supertest(server)
      .post("/api/auth/login")
      .send(credentials);

    return expect(res.body.message).toBe(successMessage);
  });

  it("Should return a token", async () => {
    await createUser(credentials);

    const res = await supertest(server)
      .post("/api/auth/login")
      .send(credentials);

    return expect(res.body.token).toBeTruthy();
  });
});

describe("GET /api/jokes", () => {
  beforeEach(async () => {
    await db("users").truncate();
  });

  it("should return status 401", async () => {
    const user = await createUser(credentials);

    const res = await supertest(server)
      .get("/api/jokes")

    return expect(res.status).toBe(401);
  });

  it("should send a response message missing authorization", async () => {
    const res = await supertest(server).get("/api/jokes");
    return expect(res.body.you).toBe("Missing authorization token");
  });
});
