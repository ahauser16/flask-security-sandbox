this tutorial is from here:
https://www.geeksforgeeks.org/flask-role-based-access-control/

## reminders on how to work on this project:

### running the application:

1. There is a virtual environment already set up for this project so you need to activate it:

`source venv/bin/activate`

2. In Flask, the `FLASK_APP` environment variable is used to specify how to load your application. It can be set to a python file, a module, or a package. In this case, it's being set to the `app.py` file, which is presumably where your Flask application is defined.

When you run `flask run`, Flask uses the value of `FLASK_APP` to find your application and run it. If `FLASK_APP` is not set, Flask won't know where your application is and won't be able to run it. So before you run the application you must run the command:

`export FLASK_APP=app.py`

3. Now you can run the application:

`flask run`

### psql and the database:

1. Since this is a Unix-based system you must activate the PostgreSQL service with the command:
   NB--> be prepared to enter your `psql` password

`sudo service postgresql start`

2. To log in to your PSQL account you must use the `psql` command with the `-U` option followed by your username:

`psql -U your_username`

3. Helpful "general" `psql` commands:

- `\l` : list all your databases.
- `\c database_name` : Connect to a specific database.
- `\dt` : List all tables in the current database.
- `\d` : table_name: Show the structure of a specific table.
- `\du` : List all users.
- `\h` : Get a help on syntax of SQL commands.
- `\?` : Lists all psql slash commands.
- `\q` : Quit psql.

4. Helpful `psql` commands to run once you are connected to a database:

- `\dt`: List all tables in the current database.
- `\d table_name` : Show the structure of a specific table. Replace table_name with the name of the table you want to inspect.
- `\dn` : List all schemas in the current database.
- `\df` : List all functions in the current database.
- `dv` : List all views in the current database.
- `\x` : Toggle expanded display. This can make the output of some commands easier to read.
- `\a` : Toggle between unaligned and aligned output mode.
- `\timing` : Toggle timing of commands. When on, psql will show how long each command takes to execute.
- `\i filename` : Execute commands from a file. Replace filename with the name of the file you want to execute commands from.
- `\o filename` : Send all query results to a file. Replace filename with the name of the file you want to send results to.
- `\q` : Quit psql.