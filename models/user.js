const ExpressError = require('../expressError');
const db = require('../db');
const bcrypt = require('bcrypt')
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config')
const jwt = require('jsonwebtoken');
 
/** User class for message.ly */



/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register(username, password, first_name, last_name, phone) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, NOW(), NOW()) RETURNING
      username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]);
    return result.rows[0];
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(`
      SELECT username, password
      FROM users WHERE username=$1`, [username]); 
    const user = result.rows[0];
    if(user) {
      if(await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username }, SECRET_KEY);
        return user;
      } else {
        return false;
      }
    } else {
      return false;
    }
   }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const result = await db.query(`
      UPDATE users SET last_login_at=NOW() 
      WHERE username=$1 RETURNING username`, [username]);
    if(result.rows === undefined) {
      throw new ExpressError("User not found!", 404)
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const result = await db.query(`SELECT 
      username, first_name, last_name, phone
      FROM users`);
    return result.rows;

    
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const result = await db.query(`
      SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users WHERE username=$1`, [username]); 
    let user = result.rows[0];
    if(!user) {
      throw new ExpressError("No user by that name", 404)
    }
    return {
      username: user.username,
      first_name: user.first_name,
      last_name: user.last_name,
      phone: user.phone,
      join_at: user.join_at,
      last_login_at: user.last_login_at
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(`
      SELECT m.id, m.to_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at
        FROM messages AS m
          JOIN users AS u
            ON m.to_username = u.username
        WHERE from_username=$1`, [username]);
    let messages = results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));

    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const results = await db.query(`
      SELECT m.id, m.from_username, u.first_name, u.last_name, u.phone, m.body, m.sent_at, m.read_at
        FROM messages AS m
          JOIN users AS u
            ON m.from_username = u.username
        WHERE to_username=$1`, [username]);
    let messages = results.rows.map(m => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }));
    
    return messages;
  }
}


module.exports = User;