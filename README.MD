this tutorial is from here:
https://www.geeksforgeeks.org/flask-role-based-access-control/

## reminders on how to work on this project:

### ToDos:

1.  currently working on--> add a notary logbook feature with an editable table for Traditional Notary and Electronic Notary users.
    1.  COMPLETE-->This will require updating the `User` model for registered users who are either Traditional Notaries or Electronic Notaries to include their commission details: `commission_holder_name`, `commission_number_uid`, `commissioned_county`, `commission_type_traditional_or_electronic`, `term_issue_date` and `term_expiration_date`.
    2.  COMPLETE-->UPDATE PSQL `User` MODEL: once a user registers as a notary and successfully authenticates using NYSDOS notary credentials those credentials need to be added to the user's profile in the database.
    3.  Add editable_logbook.py and editable_logbook.html to the front end.
    4.  create notary_logbook models for database and join it with the `User` model.
    5.  Add CRUD operations for logbook
    6.  Add logic that checks if a user has already registered with the notary credentials.
2.  Add "Forgot Username" and "Forgot Password" feature using flask-security & flask-mailman

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
- `\c nysdos_notaries_test` : Connect to a specific database.
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
     - replace old roles with new roles. The `value` matches up to the ids as defined in the `create_roles.py` file (I think).
   - `mydetails.html`
     - change to `myaccount.html` and this page will essentially be an index of all the account subcategories that will vary depending on the user's role. For now implement the following subcategories:
       - admins, principals, trad notaries and e-notaries:
         - `contactinfo.html`: first name, last name, email, phone number
         - `contactaddress.html`: street address line 1, street address line 2, City, State, Zip code
         - `billing.html`: embed a Stripe API component here which should include first name on cc, last name on cc, cc number, expiration, cvv, billing address line 1, billing address line 2, billing address City, billing address State, billing address Zip code.
         - `scheduling.html`: embed a booking component here that uses a calendar and has bookling logic. Maybe include a preferred contact method (email vs phone) and a public notes section.
         - `mynotaries.html`: redirect to the /Explore route that has the table and CRUD operations or maybe embed the table with CRUD operations into this page.
         - `mydocuments.html`: embed a table with file upload capability. this will require setting up firebase document account to the user.
         - `e-signature.html`: embed the docusign test feature here,
         - `backgroundinfo.html`: this will also use Firebase to store the avatar image. Other info can be stored here such as teleconference options, languages spoken, specializations, certifications, current employer & title, etc. This may be a good placehold for if a user wants to incorporate their LinkedIn information.
   - `signin.html`
     - unchanged
   - `staff.html`, `students.html`, `teachers.html`, `teacherslounge.html`
     - depracated; no longer need but keep as a reference
   - `create_roles.py`
     - you will have to refactor this by changing the role names and you may want to change the ids from integers to text but this may have a negligible impact on the final code post refactor.

## fake users login credentials

enotary user test #1:
theflash@gmail.com
abc123

enotary user test #2:
batman@gmail.com
abc123

enotary user test #3:
superman@gmail.com
abc123

principal user test#1
johndoe@gmail.com
abc123

principal user test#2-post notaryauth route refactor on 5-15-24:
bugs@bunny.com
abc123

enotary user test#1-post notaryauth route refactor on 5-15-24:
daffythenotary@disney.com
abc123
[created with real notary credentials below]

enotary user test#2-post notaryauth route refactor on 5-15-24:
baloney@oscar.com
abc123
[created with real notary credentials below]

trad_notary user test#1-post notaryauth route refactor on 5-15-24v2(second session):

vladtheimpala@bleh.com
asdgfadfhassdfgadfh
CHAK C CHONG
02CH5009104
Putnam
Traditional
03/08/2023
03/08/2027

trad_notary user test#2-post notaryauth route refactor on 5-15-24v2(second session):
--> fringe case where the commission id only has 10 characters but is 11 charaters long
kangelo@aol.com
abc123
KAREN M D'ANGELO
01 D6390284
Monroe
Traditional
04/15/2023
04/15/2027

trad_notary user test#3-post notaryauth route refactor on 5-15-24v3(second session):
--> fringe case where the commission id only has 10 characters but is 11 charaters long
gpruno@bruno.com
abc123
GRACE PRUNO
01 P4603811
Suffolk
Traditional
01/31/2023
01/31/2027

https://data.ny.gov/resource/rwbv-mz6z.json?commission_number_uid=01 P4603811

trad_notary user test#4-post notaryauth route refactor on 5-15-24v3(second session):
--> not a fringe case
rsharif@aol.com
abc123
RASHAD SHARIF
01SH6313188
Rockland
Traditional
01/20/2023
01/20/2027

if you go to the data.ny.gov website and search for records that contain a sapce " " using the 'contains' query term you get 236 records that are 11 characters long but only contain 10 characters and a space in the middle of the textstring. Querying these records is problematic from the API perspective and even copying and pasting the commission holder's name in the URL doesn't always work.

e.g. these five GET requests return an empty `[ ]`

`https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=GRACE PRUNO`

`https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=JOHN A OWENS JR`

`https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=CAROL A BLAKE`

`https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=KAREN M D'ANGELO`

`https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=MICHELE A GREEN HOSANG`

while `https://data.ny.gov/resource/rwbv-mz6z.json?commission_holder_name=COSTA-TRAHAN CYNTHIA A` returns:

```
[
  {
    "commission_holder_name": "COSTA-TRAHAN CYNTHIA A",
    "commission_number_uid": "02A 5074644",
    "business_address_1_if_available": "COSTA & ASSOCIATES",
    "business_address_2_if_available": "56 N. BROADWAY",
    "business_city_if_available": "NYACK",
    "business_state_if_available": "NY",
    "business_zip_if_available": "10960",
    "commissioned_county": "Rockland",
    "commission_type_traditional_or_electronic": "Traditional",
    "term_issue_date": "2023-05-17T00:00:00.000",
    "term_expiration_date": "2027-05-17T00:00:00.000",
    "georeference": {
      "type": "Point",
      "coordinates": [
        -73.9249517,
        41.0917555
      ]
    }
  }
]
```

## my public credentials

use this fake default to log in as "arthur"
NB--> 5/17/24 registration works fine

therealarturo@gmail.com
abc123

wtf@gmail.com
abc123

whitesnake@gmail.com
abc123
ARTHUR John HAUSER
01HA0018990
Kings
Electronic
12/21/2023
12/21/2027
