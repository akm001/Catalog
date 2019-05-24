#!/usr/bin/python3
from flask import Flask, render_template, request, redirect, \
    jsonify, url_for, flash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Users, League, Teams, Players
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import json
import requests
from flask import make_response
import httplib2

CLIENT_ID = json.loads(
    open('client_secret.json', 'r').read())['web']['client_id']


app = Flask(__name__)
app.secret_key = "qyAxbizRZdk_q2mEIrTtGx87"

engine = create_engine('sqlite:///leagues.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/login', methods=['POST', 'GET'])
def showLogin():
    if 'username' in login_session:
        redirect('/leagues')
    state = ''.join(random.choice(string.ascii_uppercase + string.digits +
                                  string.ascii_lowercase)
                    for x in range(32))
    login_session['state'] = state
    # return "The current login state is %s" %login_session['state']
    return render_template('login.html',
                           login_session=login_session, STATE=state)


# Function to connect using Google
@app.route('/gconnect', methods=['POST'])
def gconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalide state token !'), 401)
        response.headers['Content-Type'] = "application/json"
        return response
    code = request.data

    try:
        oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(json.dumps
                                 ('Failed to upgrade the authorization code.'),
                                 401)
        response.headers['Content-Type'] = "application/json"
        return response
    accsess_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % accsess_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = "application/json"
        return response

    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match "
                                            "the given ID."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    if result['issued_to'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID doesn't match"
                                            " the app's ID."), 401)
        response.headers['Content-Type'] = "application/json"
        return response

    stored_credentials = login_session.get('credentials')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps
                                 ("Current user is already connected"), 200)
        response.headers['Content-Type'] = "application/json"
        return response

    login_session['credentials'] = credentials.to_json()
    login_session['gplus_id'] = gplus_id
    login_session['access_token'] = credentials.access_token
    login_session['provider'] = 'google'

    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    print(data)
    login_session['username'] = data['name']
    login_session['email'] = data['email']
    login_session['picture'] = data['picture']

    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 10%; height: 300px;border-radius: 10%;' \
              '-webkit-border-radius: 10%;-moz-border-radius: 10%;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")

    return output


# Function to disconnect if the login was by Google
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    print(type(access_token))
    print(access_token)
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    print(url)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for'
                                            ' given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Function to connect using Facebook
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print("access token received %s " % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=' \
          'fb_exchange_token&client_id=%s&client_secret=%s&' \
          'fb_exchange_token=%s' % (app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
    Due to the formatting for the result from the server token exchange
    we have to split the token first on commas and select the first index
    which gives us the key : value for the server access token
    then we split it on colons to pull out the actual token value
    and replace the remaining quotes with nothing so that it can be used
    directly in the graph api calls
    '''
    print(result)
#    token = result.split('&')[0]
#    print(token)
#    token = result.split(',')[0].split(':')[1].replace('"', '')
#    print(token)
    token = access_token.decode('ascii')
    print("Token string: " + token)

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&' \
          'fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("url sent for API access:%s" % url)
    print("API JSON result: %s" % result)
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v3.3/me/picture?access_token=%s&' \
          'redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 10%; height: 10%;border-radius: 150px;' \
              '-webkit-border-radius: 10%;-moz-border-radius: 10%;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


# Function to disconnect if login was by Facebook
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s'\
          % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Function to disconnect whatever authentication provider was.
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()

            del login_session['credentials']
            print("google disconneted!!")
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
            del login_session['username']
            print(login_session['user_id'])
            del login_session['user_id']
            del login_session['email']
            del login_session['picture']
        del login_session['provider']

        flash("You have been successfully been logged out!")
        return redirect(url_for('showLeagues'))
    flash("You are not logged in to begin with.")
    return redirect(url_for('showLeagues'))


''' The fllowing functions and routes makes this web app,
it uses simple representative names for each path,
 also JSON api to get all data easily.
'''


# Display functions
@app.route('/')
@app.route('/leagues/')
def showLeagues():
    leagues = session.query(League).all()
    if 'username' not in login_session:
        return render_template('publeagues.html', leagues=leagues,
                               login_session=login_session)

    return render_template('leagues.html', leagues=leagues,
                           login_session=login_session)


@app.route('/leagues/JSON')
def leaguesJSON():
    leagues = session.query(League).all()
    return jsonify(leagues=[i.serialize for i in leagues])


@app.route('/<int:league_id>/')
@app.route('/leagues/<int:league_id>/')
def showLeague(league_id):
    league = session.query(League).filter_by(id=league_id).one()
    teams = session.query(Teams).filter_by(teamleague=league_id).all()

    if 'username' not in login_session:
        return render_template('publeague.html', teams=teams, league=league,
                               login_session=login_session)
    return render_template('league.html', teams=teams, league=league,
                           login_session=login_session)


@app.route('/leagues/<int:league_id>/JSON')
def teamsJSON(league_id):
    league = session.query(League).filter_by(id=league_id).one()
    teams = session.query(Teams).filter_by(teamleague=league_id).all()
    return jsonify(teams=[i.serialize for i in teams])


@app.route('/leagues/<int:league_id>/team/<int:team_id>/')
def showTeam(league_id, team_id):
    team = session.query(Teams).filter_by(id=team_id).one()
    league = session.query(League).filter_by(id=league_id).one()
    players = session.query(Players).filter_by(team_id=team_id).all()
    if 'username' not in login_session:
        return render_template('pubteam.html', team=team, players=players,
                               league=league, login_session=login_session)
    return render_template('team.html', team=team, players=players,
                           league=league, login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/JSON')
def playersJSON(league_id, team_id):
    players = session.query(Players).filter_by(team_id=team_id).all()
    return jsonify(players=[i.serialize for i in players])


# Editing Functions
@app.route('/leagues/<int:league_id>/edit/', methods=['GET', 'POST'])
def editLeague(league_id):
    if 'username' not in login_session:
        redirect('/login')
    editedLeague = session.query(League).filter_by(id=league_id).one()
    if editedLeague.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        if request.form['name']:
            editedLeague.name = request.form['name']
        if request.form['team_no']:
            editedLeague.teams_no = request.form['team_no']
        session.add(editedLeague)
        session.commit()
        return redirect(url_for('showLeagues'))
    else:
        return render_template(
            'editLeague.html', editedLeague=editedLeague,
            login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/edit/',
           methods=['GET', 'POST'])
def editTeam(team_id, league_id):
    if 'username' not in login_session:
        redirect('/login')
    editedTeam = session.query(Teams).filter_by(id=team_id).one()
    if editedTeam.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        if request.form['team_name']:
            editedTeam.teamname = request.form['team_name']
        session.add(editedTeam)
        session.commit()
        return redirect(url_for('showTeam', team_id=editedTeam.id,
                                league_id=league_id,
                                login_session=login_session))
    else:
        return render_template(
            'editTeam.html', team=editedTeam, league_id=league_id,
            login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/<int:player_id>/edit',
           methods=['GET', 'POST'])
def editPlayer(team_id, league_id, player_id):
    if 'username' not in login_session:
        redirect('/login')
    editedPlayer = session.query(Players).filter_by(id=player_id).one()

    if editedPlayer.owner != login_session['user_id']:
        return render_template('notAuthorized.html')

    if request.method == 'POST':
        if request.form['player_name']:
            editedPlayer.playername = request.form['player_name']
        if request.form['player_no']:
            editedPlayer.playernumber = request.form['player_no']
        if request.form['player_nation']:
            editedPlayer.playernationality = request.form['player_nation']
        session.add(editedPlayer)
        session.commit()
        return redirect(url_for('showTeam', team_id=team_id,
                                league_id=league_id,
                                login_session=login_session))
    else:
        return render_template(
            'editPlayer.html', team_id=team_id, player_id=player_id,
            editedPlayer=editedPlayer, league_id=league_id,
            login_session=login_session)


# Create Functions
@app.route('/leagues/new', methods=['GET', 'POST'])
def newLeague():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        nl = League(name=request.form['league_name'],
                    teams_no=request.form['teams_no'],
                    owner=login_session['user_id'])
        session.add(nl)
        session.commit()
        return redirect(url_for('showLeagues'))
    else:
        return render_template('newLeague.html', login_session=login_session)


@app.route('/leagues/<int:league_id>/team/new', methods=['GET', 'POST'])
def newTeam(league_id):
    if 'username' not in login_session:
        return redirect('/login')
    league = session.query(League).filter_by(id=league_id).one()
    if league.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        teamname = request.form['team_name']
        nt = Teams(teamname=teamname, teamleague=league_id,
                   owner=login_session['user_id'])
        session.add(nt)
        session.commit()
        teamnt = session.query(Teams).filter_by(teamname=teamname).one()
        return redirect(url_for('showTeam', league_id=league_id,
                                team_id=teamnt.id,
                                login_session=login_session))
    else:
        return render_template('newTeam.html', league_id=league_id,
                               league=league, login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/new',
           methods=['GET', 'POST'])
def newPlayer(team_id, league_id):
    if 'username' not in login_session:
        return redirect('/login')
    team = session.query(Teams).filter_by(id=team_id).one()
    if team.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        player_name = request.form['player_name']
        player_number = request.form['player_no']
        player_nationality = request.form['player_nation']

        np = Players(playername=player_name, team_id=team_id,
                     playernumber=player_number,
                     playernationality=player_nationality,
                     owner=login_session['user_id'])

        session.add(np)
        session.commit()

        return redirect(url_for('showTeam', league_id=league_id,
                                team_id=team_id, login_session=login_session))
    else:
        return render_template('newPlayer.html', league_id=league_id,
                               team_id=team_id, team=team,
                               login_session=login_session)


# Delete functions
@app.route('/leagues/<int:league_id>/del', methods=['GET', 'POST'])
def delLeague(league_id):
    if 'username' not in login_session:
        return redirect('/login')

    leagueToDel = session.query(League).filter_by(id=league_id).one()

    if leagueToDel.owner != login_session['user_id']:
        return render_template('notAuthorized.html')

    if request.method == 'POST':
        v = dict(request.values)
        if 'yes' in v:
            leagueTeams = session.query(Teams).filter_by(
                teamleague=leagueToDel.id).all()
            for team in leagueTeams:
                teamPlayers = session.query(Players).filter_by(
                    team_id=team.id).all()
                for player in teamPlayers:
                    session.delete(player)
                session.delete(team)
            session.delete(leagueToDel)
            session.commit()
            return redirect(url_for('showLeagues'))
        if 'no' in v:
            return redirect(url_for('showLeagues'))

        return redirect(url_for('showLeagues'))

    else:
        return render_template('delLeague.html', league_id=league_id,
                               leagueToDel=leagueToDel,
                               login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/del',
           methods=['GET', 'POST'])
def delTeam(team_id, league_id):
    if 'username' not in login_session:
        return redirect('/login')
    teamToDel = session.query(Teams).filter_by(id=team_id).one()

    if teamToDel.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        v = dict(request.values)
        if 'yes' in v:
            teamPlayers = session.query(Players).filter_by(
                team_id=team_id).all()
            for player in teamPlayers:
                session.delete(player)
            session.delete(teamToDel)
            session.commit()
            return redirect(url_for('showLeague', league_id=league_id,
                                    login_session=login_session))
        if 'no' in v:
            return redirect(url_for('showLeague', league_id=league_id,
                                    login_session=login_session))

        return redirect(url_for('showLeagues'))

    else:
        return render_template('delTeam.html', league_id=league_id,
                               team_id=team_id, teamToDel=teamToDel,
                               login_session=login_session)


@app.route('/leagues/<int:league_id>/team/<int:team_id>/<int:player_id>/del',
           methods=['GET', 'POST'])
def delPlayer(team_id, league_id, player_id):
    if 'username' not in login_session:
        return redirect('/login')
    playerToDel = session.query(Players).filter_by(id=player_id).one()

    if playerToDel.owner != login_session['user_id']:
        return render_template('notAuthorized.html')
    if request.method == 'POST':
        v = dict(request.values)
        if 'yes' in v:
            session.delete(playerToDel)
            session.commit()
            return redirect(url_for('showTeam', team_id=team_id,
                                    league_id=league_id,
                                    login_session=login_session))
        if 'no' in v:
            return redirect(url_for('showTeam', team_id=team_id,
                                    league_id=league_id,
                                    login_session=login_session))

    else:
        return render_template('delPlayer.html', league_id=league_id,
                               team_id=team_id,  player_id=player_id,
                               playerToDel=playerToDel,
                               login_session=login_session)


# Get user ID by email
def getUserID(email):
    try:
        user = session.query(Users).filter_by(email=email).one()
        return user.id
    except Exception:
        return None


# Get user info after getting its ID
def getUserInfo(user_id):
    user = session.query(Users).filter_by(id=user_id).one()
    return user


# Add use to DB after successful authentication by third party.
def createUser(login_session):
    newUser = Users(username=login_session['username'],
                    email=login_session['email'],
                    img_url=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(Users).filter_by(email=login_session['email']).one()
    return user.id


# Run the App as HTTPS on port 8000
if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=8000, ssl_context='adhoc')
