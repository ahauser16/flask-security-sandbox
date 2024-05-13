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

## notes to refactor from school use case to my use case:
1. change roles from Admin, Teacher, Staff and Student to Admin, Principal, Traditional Notary and Electronic Notary
2. files to be refactored:
   - `app.py`
     - copy `app.py` and save it as `app_copy.py` in case you want to start the refactor over again.
      - you will have to add logic to the `def signin()` route where if the user picks "traditioanal notary" or "electronic notary" then a second signin screen shows up that asks for their commission details: full name, commission id, commissioned county and commission start and expiration dates.
     - you don't have to change the `roles_users` table, `User Class` or `Role Class`.
     - you don't have to change the `def signin()` route.
     - 
   - `index.html`
      - save original file as "index_notes.html" in case you need to refer to it later.
      - replace old roles with new roles and new routes.
   - `signup.html`
       - replace old roles with new roles.  The `value` matches up to the ids as defined in the `create_roles.py` file (I think).
   - `mydetails.html`
     - change to `myaccount.html` and this page will essentially be an index of all the account subcategories that will vary depending on the user's role.  For now implement the following subcategories:
       - admins, principals, trad notaries and e-notaries: 
         - `contactinfo.html`: first name, last name, email, phone number
         - `contactaddress.html`: street address line 1, street address line 2, City, State, Zip code
         - `billing.html`: embed a Stripe API component here which should include first name on cc, last name on cc, cc number, expiration, cvv, billing address line 1, billing address line 2, billing address City, billing address State, billing address Zip code.
         - `scheduling.html`: embed a booking component here that uses a calendar and has bookling logic.  Maybe include a preferred contact method (email vs phone) and a public notes section.
         - `mynotaries.html`: redirect to the /Explore route that has the table and CRUD operations or maybe embed the table with CRUD operations into this page.
         - `mydocuments.html`: embed a table with file upload capability.  this will require setting up firebase document account to the user.
         - `e-signature.html`: embed the docusign test feature here, 
         - `backgroundinfo.html`: this will also use Firebase to store the avatar image.  Other info can be stored here such as teleconference options, languages spoken, specializations, certifications, current employer & title, etc.  This may be a good placehold for if a user wants to incorporate their LinkedIn information.
   - `signin.html`
     - unchanged
   - `staff.html`, `students.html`, `teachers.html`, `teacherslounge.html`
     - depracated; no longer need but keep as a reference 
   - `create_roles.py`
     - you will have to refactor this by changing the role names and you may want to change the ids from integers to text but this may have a negligible impact on the final code post refactor.