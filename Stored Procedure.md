**Stored Procedure**

A stored procedure is a group of SQL statements that are grouped together and stored in a database. Stored procedures can be used to perform a variety of tasks, such as:

Inserting, updating, or deleting data from a database
Calculating complex values
Validating data
Enforcing security

Stored procedures offer a number of advantages over executing SQL statements directly. For example, stored procedures can:

Improve performance by reducing the number of round trips between the application and the database
Increase security by centralizing access control
Make code more reusable and easier to maintain

Here is an example of a stored procedure that inserts a new row into a table:

SQL

`CREATE PROCEDURE sp_insert_row@username VARCHAR(255),@password VARCHAR(255)ASBEGININSERT INTO users (username, password)VALUES (@username, @password);END;`

---
This stored procedure has two parameters: `username` and `password`. These parameters are used to specify the values for the `username` and `password` columns in the `users` table.

To execute this stored procedure, you would use the following command:
SQL
`EXEC sp_insert_row 'admin', 'password';`

This command would insert a new row into the users table with the username `admin` and the password `password`.

---

**Prepared Statement**
  
A prepared statement is a type of SQL statement that is pre-compiled by the database. This means that the database can parse the statement once, and then reuse the compiled statement for subsequent executions. This can improve performance, especially for queries that are executed frequently.

Prepared statements are also useful for security. This is because they prevent attackers from injecting malicious code into the query. For example, if a query is written as follows:
SQL
`SELECT * FROM users WHERE username = 'admin' AND password = 'password';`

An attacker could inject malicious code into the query by changing the value of the `password` parameter to something like this:

SQL
`SELECT * FROM users WHERE username = 'admin' AND password = 'password'; OR 1=1; --';`

This would cause the query to return all of the rows in the `users` table, even if the `password` did not match.

However, if the query is written as a prepared statement, the attacker would not be able to inject malicious code. For example, the following query is a prepared statement:

SQL
`SELECT * FROM users WHERE username = :username AND password = :password;`

In this query, the `username` and `password` parameters are placeholders that are replaced with actual values when the query is executed. This prevents the attacker from injecting malicious code into the query.

To create a prepared statement, you would use the `PREPARE` statement. For example, the following statement would create a prepared statement called `sp_select_user`:

SQL
`PREPARE sp_select_user FROM 'SELECT * FROM users WHERE username = :username AND password = :password';`

Once the prepared statement is created, you can execute it by using the `EXECUTE` statement. For example, the following statement would execute the `sp_select_user` prepared statement with the username `admin` and the password `password`:

SQL
`EXECUTE sp_select_user 'admin', 'password';`

This would return all of the rows in the users table where the username is `admin` and the password is `password`.
