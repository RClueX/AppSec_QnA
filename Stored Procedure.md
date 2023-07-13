<h4>Stored Procedure</h4>

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
