const db = require("../database/dbConfig");

module.exports = {
  add,
  findBy,
};

async function add(user) {
  await db("users").insert(user);
  return findBy(user);
}

function findBy(filter) {
  return db("users").select("*").where(filter);
}
