#!/usr/bin/python3
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class Users(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True, nullable=False)
    email = Column(String(64), index=True, nullable=False)
    img_url = Column(String)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {

            'name': self.username,

        }


class League(Base):
    __tablename__ = 'leagues'
    id = Column(Integer, primary_key=True)
    name = Column(String(32), index=True, nullable=False)
    teams_no = Column(Integer, nullable=False)
    owner = Column(Integer, ForeignKey('users.id'))
    Users = relationship(Users)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {

            'League name': self.name,
            'Number of teams': self.teams_no,
        }


class Teams(Base):
    __tablename__ = 'Fteams'
    id = Column(Integer, primary_key=True)
    teamname = Column(String(32), index=True, nullable=False)
    teamleague = Column(Integer, ForeignKey('leagues.id'))
    leagues = relationship(League)
    owner = Column(Integer, ForeignKey('users.id'))
    users = relationship(Users)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {

            'Team name': self.teamname,
        }


class Players(Base):
    __tablename__ = 'Players'
    id = Column(Integer, primary_key=True)
    playername = Column(String(64), nullable=False)
    playernumber = Column(Integer, nullable=False)
    playernationality = Column(String(32), nullable=False)
    team_id = Column(Integer, ForeignKey('Fteams.id'))
    Fteams = relationship(Teams)
    owner = Column(Integer, ForeignKey('users.id'))
    users = relationship(Users)

    @property
    def serialize(self):
        """Return object data in easily serializeable format"""
        return {

            'Player name': self.playername,
            'Player T-Shirt No.': self.playernumber,
            'nationality': self.playernationality,
        }


engine = create_engine('sqlite:///leagues.db')

Base.metadata.create_all(engine)
