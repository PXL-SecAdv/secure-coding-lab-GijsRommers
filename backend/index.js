const pg = require('pg');

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const cors = require('cors')
const argon2 = require('argon2');

const port=3000;

const pool = new pg.Pool({
    user: 'secadv',
    host: 'db',
    database: 'pxldb',
    password: 'ilovesecurity',
    port: 5432,
    connectionTimeoutMillis: 5000
})

console.log("Connecting...:")

app.use(cors());
app.use(bodyParser.json());
app.use(
    bodyParser.urlencoded({
        extended: true,
    })
)

app.get('/authenticate/:username/:password', async (request, response) => {
    const username = request.params.username;
    const password = request.params.password;
    const query = 'SELECT * FROM users WHERE user_name=$1';
    pool.query(query, [username], async (error, results) => {
        if (error) {
            throw error
        } else {
            const storedPassword = results.rows[0]["password"]
            try {
                if (await argon2.verify(storedPassword, password)) {
                    response.status(200).json({status: 'success'})
                } else {
                    response.status(401).json({status: 'Username or password is incorrect'})
                }
            } catch (err) {
                response.status(500).json({status: 'Internal server error'})
            }
        }
    })
})



async function hashAllPasswords() {
    const query = "SELECT * FROM users WHERE password NOT LIKE '$argon2id$%'"
    const users = await pool.query(query)
    for (let user of users.rows) {
        const password = user.password
        const username = user['user_name']
        const hashedPassword = await argon2.hash(password)
        const updateQuery = 'UPDATE users SET password=$1 WHERE user_name=$2'
        await pool.query(updateQuery, [hashedPassword, username])
    }
}

setTimeout(hashAllPasswords, 5000);

app.listen(port, () => {
  console.log(`App running on port ${port}.`)
})

