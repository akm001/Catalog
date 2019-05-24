# World Football Leagues
It is a small web application written in Python Flask and sqlite database,
It provide viewers with info about whatever league they want and its teams and players.
Not just view , but also add your league and its teams and players if not found.

## Easy Login 

You can easily login by your Google or Facebook accounts to be able to add, edit, delete data that you created.

## Database preparation 
As I am using SQLAlchemy, it is easy to change the DB Engine, but for simplicity I chose sqlite so you don't need to deal with any DB system.
 DB consist of 4 tables :
 * Users table: store user data such as username, email.
 * League table: store leagues basic info such as name, teams number.
 * Teams table: store each team basic info such as name and its league.
 * Players table: store each player info such as name, T-Shirt No., nationality.
  
## How to use ?
##### Just use your favourite web server that support python WSGI , make sure python3 with Flask and SQLAlchemy are installed.

###### As a new initialization , no data, so you have to login and create your own leagues, teams and players to begin with.
Everyone can view the website, but only authorized users can create, edit, delete data.
* The League's owner is the only authorized user to create, edit, delete its teams and every team's players that belong to that league.
* Deleting a league will also delete all of its teams and players, be careful !.
* Deleting a team will also delete its players, be careful !.

## JSON data
You have given access to our data to include and use it in your app using a simple JSON format.
Access required data by adding "JSON" to the end of url to get its json data,
for example to get leagues data: https://localhost:5000/leagues/JSON
to get teams of the first league: https://localhost:5000/leagues/1/JSON
players of a team: https://localhost:5000/leagues/1/team/1/JSON

## Contribution 
You are all invited to edit, send suggestions , modify style, extend functionality to include more sports.

#### Notes and Thanks
Notice that the domain must be _**localhost**_ as it is the allowed by Google and Facebook for authentication.
Also ssl is required for FB authentication.

Created by **Ahmed Kamel** for _**FSND**_.